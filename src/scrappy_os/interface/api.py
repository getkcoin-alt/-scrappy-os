"""The local HTTP API.

Every endpoint except ``GET /health`` requires a bearer token and a scope. The
credential is verified in :mod:`scrappy_os.interface.security`, which is the
only module that reads the ``Authorization`` header; endpoints below declare the
capability they need and receive an already-authenticated actor.

The endpoint policy, in full:

===========================  =============  ==================
Endpoint                     Authenticated  Scope
===========================  =============  ==================
``GET  /health``             optional       none (see below)
``GET  /status``             yes            ``system:read``
``POST /tasks``              yes            ``task:create``
``GET  /tasks/{id}``         yes            ``task:read``
``GET  /tasks/{id}/events``  yes            ``task:read``
``GET  /approvals``          yes            ``approval:read``
``POST /approvals/{id}``     yes            ``approval:grant``
``GET  /audit``              yes            ``audit:read``
===========================  =============  ==================

``/health`` is the one deliberate exception. Process supervisors, systemd and
container orchestrators need a liveness signal before any credential is
provisioned, and a health check that fails when a token expires causes the
outage it was meant to detect. Anonymously it answers only *is the process
alive*: status, version and uptime. Component detail, the provider name and the
tool inventory require ``system:read``, because "which model is configured and
what can it reach" is reconnaissance, not liveness.

Binding remains 127.0.0.1 by default. Authentication is a second control, not a
replacement for the first: a token makes remote exposure *survivable*, it does
not make it advisable. ``scrappy doctor`` escalates to FAIL when the API is
bound off-host with no credential configured.

The API still has no interactive approver. A task that needs approval parks at
``POST /approvals/{id}`` and waits for a human there - the HTTP layer can never
approve on its own, and nothing about "the client asked nicely" changes that.
What v0.2 adds is that the human is now *identified*: the approver recorded in
the audit trail comes from the verified credential, not from the request body.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from scrappy_os import __version__
from scrappy_os.core.config import ScrappySettings, get_settings
from scrappy_os.core.enums import EventType, RiskLevel, RuntimeStatus
from scrappy_os.core.errors import ApprovalExpired, ScrappyError
from scrappy_os.core.identity import Scope
from scrappy_os.core.models import ApprovalDecision, Objective
from scrappy_os.heart.runtime import Runtime
from scrappy_os.interface.security import (
    RequestSecurityContext,
    optional_identity,
    require_scope,
)
from scrappy_os.observability.logging import get_logger
from scrappy_os.security.approvals import ApprovalNotFound
from scrappy_os.security.authn import build_authenticator

logger = get_logger("api")

#: Seconds between SSE keepalive comments on an idle stream.
KEEPALIVE_SECONDS = 15.0

#: Tasks the API has run, kept in memory for GET /tasks/{id}.
#: Bounded so a long-lived daemon cannot grow without limit; the durable record
#: is the audit log, which this is only a convenience view over.
MAX_TRACKED_TASKS = 200


class TaskRequest(BaseModel):
    """Body of ``POST /tasks``.

    Note what is no longer here: ``actor``. In v0.1 a client named itself in the
    request body, which made the audit trail a record of what callers *claimed*.
    Identity now comes from the verified credential and only from there. With
    ``extra="forbid"``, a v0.1 client still sending ``actor`` gets a 422 telling
    it so, rather than having the field quietly ignored.
    """

    model_config = {"extra": "forbid"}

    objective: str = Field(min_length=1, max_length=8000)
    max_risk: RiskLevel = Field(
        default=RiskLevel.READ,
        description="Risk ceiling. Anything above READ still requires approval per step.",
    )
    dry_run: bool = False


class ApprovalBody(BaseModel):
    """Body of ``POST /approvals/{approval_id}``.

    ``decided_by`` is likewise gone. An approval is the most consequential thing
    this API accepts, and a caller that could name its own approver could attach
    someone else's name to a destructive action it authorised itself.
    """

    model_config = {"extra": "forbid"}

    approved: bool
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

    # Built once at app construction, not per request: the token is read from
    # configuration here and the digests are precomputed, so no request path
    # ever handles the configured secret.
    app.state.authenticator = build_authenticator(
        resolved.api_token,
        actor_id=resolved.api_token_actor_id,
        scopes=frozenset(resolved.api_token_scopes),
    )

    if not resolved.api_auth_configured:
        logger.warning(
            "api_auth_unconfigured",
            detail=(
                "no SCRAPPY_API_TOKEN is set; every authenticated endpoint will refuse. "
                "This is fail-closed, not open"
            ),
        )
    if not resolved.api_is_local_only:
        logger.warning(
            "api_bound_non_local",
            host=resolved.api_host,
            authenticated=resolved.api_auth_configured,
            detail=(
                "the API is reachable off this host; bearer tokens are the only thing "
                "standing in front of it"
            ),
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

    @router.get("/health", summary="Liveness, plus component health when authenticated")
    async def health(
        request: Request,
        security: Annotated[RequestSecurityContext, Depends(optional_identity)],
    ) -> dict[str, Any]:
        """Liveness for anyone; detail for ``system:read``.

        The anonymous body is deliberately thin. Component names, the model
        provider and the tool inventory describe what this host can be made to
        do, which is not something an unauthenticated caller needs in order to
        learn that the process is up.
        """
        runtime = _runtime(request)
        state = await runtime.health()
        healthy = state.status in {RuntimeStatus.HEALTHY, RuntimeStatus.DEGRADED}
        body: dict[str, Any] = {
            "healthy": healthy,
            "status": str(state.status),
            "version": state.version,
            "uptime_seconds": round(state.uptime_seconds, 1),
        }
        if security.actor.has_scope(Scope.SYSTEM_READ):
            body["components"] = [item.model_dump(mode="json") for item in state.components]
        return body

    @router.get("/status", summary="Full runtime state")
    async def status(
        request: Request,
        security: Annotated[
            RequestSecurityContext, Depends(require_scope(Scope.SYSTEM_READ))
        ],
    ) -> dict[str, Any]:
        runtime = _runtime(request)
        state = await runtime.health()
        return {
            **state.model_dump(mode="json"),
            "development_provider": runtime.router.is_development_provider,
            "tools": [tool.name for tool in runtime.registry.enabled()],
            "pending_approvals": len(await runtime.approvals.pending()),
        }

    @router.post("/tasks", status_code=202, summary="Submit an objective")
    async def create_task(
        request: Request,
        body: TaskRequest,
        security: Annotated[
            RequestSecurityContext, Depends(require_scope(Scope.TASK_CREATE))
        ],
    ) -> dict[str, Any]:
        runtime = _runtime(request)
        objective = Objective(
            text=body.objective,
            # The authenticated principal, not anything the body said. This is
            # the hand-off from the request context into the task, and every
            # later record of this run traces back to it.
            identity=security.actor,
            max_risk=body.max_risk,
            dry_run=body.dry_run,
        )
        handle = runtime.spawn(objective)
        _track(request.app, objective.id, handle)
        logger.info(
            "task_submitted",
            objective_id=objective.id,
            actor_id=security.actor.id,
            actor_type=str(security.actor.actor_type),
            max_risk=str(body.max_risk),
        )
        return {
            "objective_id": objective.id,
            "status": "accepted",
            "actor_id": security.actor.id,
            "max_risk": str(body.max_risk),
            "note": (
                "Steps above WRITE will park at an approval request. "
                "Resolve them with POST /approvals/{approval_id}."
            ),
            "events_url": f"/tasks/{objective.id}/events",
        }

    @router.get("/tasks/{task_id}", summary="Task result or progress")
    async def get_task(
        request: Request,
        task_id: str,
        security: Annotated[RequestSecurityContext, Depends(require_scope(Scope.TASK_READ))],
    ) -> dict[str, Any]:
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
        security: Annotated[RequestSecurityContext, Depends(require_scope(Scope.TASK_READ))],
        replay: Annotated[bool, Query(description="Send buffered events first.")] = True,
    ) -> StreamingResponse:
        runtime = _runtime(request)
        handle = request.app.state.tasks.get(task_id)
        if handle is None:
            raise HTTPException(status_code=404, detail=f"unknown task {task_id}")

        resolved_id = runtime.task_id_for(task_id) or task_id
        subscription = runtime.bus.subscribe(task_id=resolved_id)

        terminal = {EventType.TASK_COMPLETED, EventType.TASK_FAILED, EventType.TASK_CANCELLED}

        async def stream() -> AsyncIterator[str]:
            try:
                if replay:
                    for event in runtime.bus.history(task_id=resolved_id):
                        yield _sse(event.model_dump(mode="json"))
                        if event.type in terminal:
                            # The task already finished before this stream opened.
                            # Replaying its ending and then waiting for more would
                            # hold the connection open forever.
                            return
                if handle.done():
                    return
                while True:
                    if await request.is_disconnected():
                        return
                    try:
                        # A keepalive every 15s so proxies do not drop an idle
                        # stream while a long tool call is running.
                        async with asyncio.timeout(KEEPALIVE_SECONDS):
                            live = await subscription.get()
                    except TimeoutError:
                        yield ": keepalive\n\n"
                        continue
                    if live is None:
                        return
                    yield _sse(live.model_dump(mode="json"))
                    if live.type in terminal:
                        return
            finally:
                subscription.close()

        return StreamingResponse(stream(), media_type="text/event-stream")

    @router.get("/approvals", summary="Pending approval requests")
    async def list_approvals(
        request: Request,
        security: Annotated[
            RequestSecurityContext, Depends(require_scope(Scope.APPROVAL_READ))
        ],
    ) -> dict[str, Any]:
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
        security: Annotated[
            RequestSecurityContext, Depends(require_scope(Scope.APPROVAL_GRANT))
        ],
    ) -> dict[str, Any]:
        runtime = _runtime(request)
        decision = ApprovalDecision(
            request_id=approval_id,
            approved=body.approved,
            # The approver is the credential holder. Always.
            identity=security.actor,
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
            "decided_by": security.actor.label,
        }

    @router.get("/audit", summary="Recent audit events")
    async def audit(
        request: Request,
        security: Annotated[RequestSecurityContext, Depends(require_scope(Scope.AUDIT_READ))],
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


__all__ = ["KEEPALIVE_SECONDS", "MAX_TRACKED_TASKS", "ApprovalBody", "TaskRequest", "create_app"]
