"""The local HTTP API.

Bound to 127.0.0.1 by default and shipped with **no authentication**, which is
a deliberate and documented constraint rather than an omission: an unauthenticated
API that can restart services must not be reachable off the host, so the safe
default is loopback and the documented deployment is behind an authenticating
proxy. :func:`create_app` logs a warning when the configured bind address is
not local, and ``scrappy doctor`` reports it as a WARN.

The API has no interactive approver. A task that needs approval parks at
``POST /approvals/{id}`` and waits for a human there - the HTTP layer can never
approve on its own, and nothing about "the client asked nicely" changes that.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import APIRouter, Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from scrappy_os import __version__
from scrappy_os.core.config import ScrappySettings, get_settings
from scrappy_os.core.enums import RiskLevel, RuntimeStatus
from scrappy_os.core.errors import ApprovalExpired, ScrappyError
from scrappy_os.core.models import ApprovalDecision, Objective
from scrappy_os.heart.runtime import Runtime
from scrappy_os.observability.logging import get_logger
from scrappy_os.security.approvals import ApprovalNotFound

logger = get_logger("api")

#: Tasks the API has run, kept in memory for GET /tasks/{id}.
#: Bounded so a long-lived daemon cannot grow without limit; the durable record
#: is the audit log, which this is only a convenience view over.
MAX_TRACKED_TASKS = 200


class TaskRequest(BaseModel):
    """Body of ``POST /tasks``."""

    model_config = {"extra": "forbid"}

    objective: str = Field(min_length=1, max_length=8000)
    max_risk: RiskLevel = Field(
        default=RiskLevel.READ,
        description="Risk ceiling. Anything above READ still requires approval per step.",
    )
    dry_run: bool = False
    actor: str = Field(default="api", max_length=64)


class ApprovalBody(BaseModel):
    """Body of ``POST /approvals/{approval_id}``."""

    model_config = {"extra": "forbid"}

    approved: bool
    decided_by: str = Field(default="api", max_length=64)
    note: str | None = Field(default=None, max_length=1000)
    confirmation_phrase: str | None = Field(default=None, max_length=200)


def create_app(settings: ScrappySettings | None = None, *, with_heartbeat: bool = True) -> FastAPI:
    """Build the FastAPI application with a managed runtime lifespan."""
    resolved = settings or get_settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        runtime = Runtime(resolved)
        await runtime.start(with_heartbeat=with_heartbeat)
        application.state.runtime = runtime
        application.state.tasks = {}
        try:
            yield
        finally:
            await runtime.stop()

    app = FastAPI(
        title="Scrappy OS",
        version=__version__,
        summary="Local control plane for an AI-operated Linux machine.",
        lifespan=lifespan,
    )

    if not resolved.api_is_local_only:
        logger.warning(
            "api_bound_non_local",
            host=resolved.api_host,
            detail="the API has no authentication; put it behind an authenticating proxy",
        )

    app.include_router(_build_router())
    return app


def _runtime(request: Request) -> Runtime:
    runtime: Runtime | None = getattr(request.app.state, "runtime", None)
    if runtime is None or not runtime.started:
        raise HTTPException(status_code=503, detail="runtime is not ready")
    return runtime


def _build_router() -> APIRouter:
    router = APIRouter()

    @router.get("/health", summary="Liveness and component health")
    async def health(request: Request) -> dict[str, Any]:
        runtime = _runtime(request)
        state = await runtime.health()
        healthy = state.status in {RuntimeStatus.HEALTHY, RuntimeStatus.DEGRADED}
        return {
            "healthy": healthy,
            "status": str(state.status),
            "version": state.version,
            "uptime_seconds": round(state.uptime_seconds, 1),
            "components": [item.model_dump(mode="json") for item in state.components],
        }

    @router.get("/status", summary="Full runtime state")
    async def status(request: Request) -> dict[str, Any]:
        runtime = _runtime(request)
        state = await runtime.health()
        return {
            **state.model_dump(mode="json"),
            "development_provider": runtime.router.is_development_provider,
            "tools": [tool.name for tool in runtime.registry.enabled()],
            "pending_approvals": len(await runtime.approvals.pending()),
        }

    @router.post("/tasks", status_code=202, summary="Submit an objective")
    async def create_task(request: Request, body: TaskRequest) -> dict[str, Any]:
        runtime = _runtime(request)
        objective = Objective(
            text=body.objective,
            actor=body.actor,
            max_risk=body.max_risk,
            dry_run=body.dry_run,
        )
        handle = runtime.spawn(objective)
        _track(request.app, objective.id, handle)
        logger.info(
            "task_submitted",
            objective_id=objective.id,
            actor=body.actor,
            max_risk=str(body.max_risk),
        )
        return {
            "objective_id": objective.id,
            "status": "accepted",
            "max_risk": str(body.max_risk),
            "note": (
                "Steps above WRITE will park at an approval request. "
                "Resolve them with POST /approvals/{approval_id}."
            ),
            "events_url": f"/tasks/{objective.id}/events",
        }

    @router.get("/tasks/{task_id}", summary="Task result or progress")
    async def get_task(request: Request, task_id: str) -> dict[str, Any]:
        handle = request.app.state.tasks.get(task_id)
        if handle is None:
            raise HTTPException(status_code=404, detail=f"unknown task {task_id}")
        if not handle.done():
            return {"objective_id": task_id, "state": "running"}

        exception = handle.exception()
        if exception is not None:
            # A task that crashed is reported as a failure with its reason,
            # never as a success with an empty body.
            return {
                "objective_id": task_id,
                "state": "crashed",
                "error": f"{type(exception).__name__}: {exception}",
            }

        outcome = handle.result()
        return {
            "objective_id": task_id,
            "task_id": outcome.task.id,
            "state": str(outcome.task.state),
            "succeeded": outcome.succeeded,
            "conclusion": outcome.conclusion,
            "stopped_because": outcome.stopped_because,
            "budget": outcome.budget,
            "steps": [
                {
                    "tool": item.call.tool_name,
                    "risk": str(item.call.risk_level),
                    "decision": str(item.verdict.decision),
                    "rule": item.verdict.rule,
                    "success": item.result.success,
                    "error": item.result.error,
                    "duration_ms": round(item.result.duration_ms, 1),
                }
                for item in outcome.executed
            ],
        }

    @router.get("/tasks/{task_id}/events", summary="Stream task events (SSE)")
    async def task_events(
        request: Request,
        task_id: str,
        replay: Annotated[bool, Query(description="Send buffered events first.")] = True,
    ) -> StreamingResponse:
        runtime = _runtime(request)
        handle = request.app.state.tasks.get(task_id)
        if handle is None:
            raise HTTPException(status_code=404, detail=f"unknown task {task_id}")

        resolved_id = runtime.task_id_for(task_id) or task_id
        subscription = runtime.bus.subscribe(task_id=resolved_id)

        async def stream() -> AsyncIterator[str]:
            try:
                if replay:
                    for event in runtime.bus.history(task_id=resolved_id):
                        yield _sse(event.model_dump(mode="json"))
                while True:
                    if await request.is_disconnected():
                        return
                    try:
                        event = await asyncio.wait_for(subscription.get(), timeout=15.0)
                    except TimeoutError:
                        yield ": keepalive\n\n"
                        continue
                    if event is None:
                        return
                    yield _sse(event.model_dump(mode="json"))
                    if event.type in {"task.completed", "task.failed"}:
                        return
            finally:
                subscription.close()

        return StreamingResponse(stream(), media_type="text/event-stream")

    @router.get("/approvals", summary="Pending approval requests")
    async def list_approvals(request: Request) -> dict[str, Any]:
        runtime = _runtime(request)
        pending = await runtime.approvals.pending()
        return {
            "pending": [item.model_dump(mode="json") for item in pending],
            "count": len(pending),
        }

    @router.post("/approvals/{approval_id}", summary="Resolve an approval request")
    async def resolve_approval(
        request: Request,
        approval_id: str,
        body: Annotated[ApprovalBody, Body()],
    ) -> dict[str, Any]:
        runtime = _runtime(request)
        decision = ApprovalDecision(
            request_id=approval_id,
            approved=body.approved,
            decided_by=body.decided_by,
            note=body.note,
            confirmation_phrase=body.confirmation_phrase,
        )
        try:
            resolved = await runtime.approvals.resolve(decision)
        except ApprovalNotFound as exc:
            raise HTTPException(status_code=404, detail=exc.message) from exc
        except ApprovalExpired as exc:
            raise HTTPException(status_code=410, detail=exc.message) from exc
        except ScrappyError as exc:
            # Covers "already resolved" and a missing confirmation phrase. Both
            # are client errors with a specific, actionable message.
            raise HTTPException(status_code=409, detail=exc.message) from exc

        return {
            "approval_id": resolved.id,
            "state": str(resolved.state),
            "tool_name": resolved.tool_name,
            "risk": str(resolved.risk),
        }

    @router.get("/audit", summary="Recent audit events")
    async def audit(
        request: Request,
        task_id: Annotated[str | None, Query(description="Filter to one task.")] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 50,
    ) -> dict[str, Any]:
        runtime = _runtime(request)
        if task_id:
            events = await runtime.audit.for_task(task_id, limit=limit)
            calls = await runtime.audit.calls_for_task(task_id)
            return {"task_id": task_id, "events": events, "calls": calls}
        return {"events": await runtime.audit.recent(limit=limit)}

    return router


def _track(app: FastAPI, objective_id: str, handle: Any) -> None:
    """Remember a task handle, evicting the oldest when the cap is reached."""
    tasks: dict[str, Any] = app.state.tasks
    tasks[objective_id] = handle
    while len(tasks) > MAX_TRACKED_TASKS:
        oldest = next(iter(tasks))
        tasks.pop(oldest, None)


def _sse(payload: dict[str, Any]) -> str:
    return f"data: {json.dumps(payload, default=str)}\n\n"


__all__ = ["MAX_TRACKED_TASKS", "ApprovalBody", "TaskRequest", "create_app"]
