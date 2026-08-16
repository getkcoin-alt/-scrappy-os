"""The Heart - lifecycle, supervision and health.

Owns startup order, shutdown order, and the answer to "is this thing working".
Everything else in Scrappy OS is constructed here and handed its dependencies,
so there is exactly one place to look to understand how the system is wired.

Startup order matters and is not arbitrary: the store comes up first because
the audit log depends on it, and the audit log attaches to the bus before any
component can publish - otherwise the first events of a run would go unrecorded.

Shutdown is graceful and idempotent: in-flight tasks are given a bounded chance
to finish, then the store is closed cleanly so the WAL is checkpointed.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
from types import TracebackType
from typing import Any, Self

from scrappy_os import __version__
from scrappy_os.brain.orchestrator import Orchestrator, TaskOutcome
from scrappy_os.core.config import ScrappySettings, get_settings
from scrappy_os.core.enums import ComponentStatus, EventType, RuntimeStatus
from scrappy_os.core.events import EventBus, InProcessEventBus, emit
from scrappy_os.core.models import ComponentHealth, Objective, RuntimeState, new_id, utc_now
from scrappy_os.memory.episodic import SQLiteEpisodicMemory
from scrappy_os.memory.semantic import NullSemanticMemory
from scrappy_os.memory.store import Store
from scrappy_os.models.registry import ModelRouter
from scrappy_os.observability.logging import configure_logging, get_logger
from scrappy_os.security.approvals import ApprovalManager
from scrappy_os.security.audit import AuditLog
from scrappy_os.security.policy import PolicyEngine
from scrappy_os.tools import build_default_registry
from scrappy_os.tools.base import ToolRegistry
from scrappy_os.tools.executor import ApprovalPrompt, ToolExecutor

logger = get_logger("heart")

#: How long a graceful shutdown waits for in-flight tasks.
SHUTDOWN_GRACE_SECONDS = 10.0


class Runtime:
    """The assembled control plane.

    Constructing a :class:`Runtime` performs no I/O; :meth:`start` does. That
    split keeps ``scrappy config show`` and the test suite from touching a
    database they do not need.
    """

    def __init__(
        self,
        settings: ScrappySettings | None = None,
        *,
        bus: EventBus | None = None,
        registry: ToolRegistry | None = None,
        router: ModelRouter | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.bus: EventBus = bus or InProcessEventBus()
        self.registry = registry or build_default_registry()
        self.router = router or ModelRouter(self.settings)

        self.store = Store(self.settings.db_path)
        self.audit = AuditLog(self.store)
        self.approvals = ApprovalManager(self.settings, self.store, self.bus)
        self.policy = PolicyEngine(self.settings)
        self.episodic = SQLiteEpisodicMemory(self.store)
        self.semantic = NullSemanticMemory()
        self.executor = ToolExecutor(
            settings=self.settings,
            registry=self.registry,
            policy=self.policy,
            approvals=self.approvals,
            audit=self.audit,
            bus=self.bus,
        )
        self.orchestrator = Orchestrator(
            settings=self.settings,
            router=self.router,
            registry=self.registry,
            executor=self.executor,
            bus=self.bus,
            episodic=self.episodic,
        )

        self.state = RuntimeState(
            version=__version__,
            hostname=socket.gethostname(),
            pid=os.getpid(),
            provider=self.router.provider.info.name,
            model=self.router.provider.info.model,
        )
        self._active: dict[str, asyncio.Task[TaskOutcome]] = {}
        self._task_ids: dict[str, str] = {}
        self._started = False
        self._heartbeat: Any | None = None

    # -- lifecycle ----------------------------------------------------------

    async def start(self, *, with_heartbeat: bool = False, configure_logs: bool = True) -> Self:
        """Bring the control plane up. Safe to call twice.

        ``configure_logs=False`` leaves logging alone, which is what the CLI
        wants: it has already chosen a level for the command being run and
        should not have it reset to the daemon default.
        """
        if self._started:
            return self

        if configure_logs:
            configure_logging(level=self.settings.log_level, fmt=self.settings.log_format)
        self.settings.ensure_directories()

        await self.store.connect()
        # Attach before anything publishes, so no event escapes the audit log.
        self.audit.attach(self.bus)
        self.bus.add_handler(self._track_task_counters)

        self.state.status = RuntimeStatus.HEALTHY
        self.state.started_at = utc_now()
        self._started = True

        if with_heartbeat:
            from scrappy_os.breath.heartbeat import Heartbeat

            self._heartbeat = Heartbeat(self)
            await self._heartbeat.start()

        await emit(
            self.bus,
            EventType.RUNTIME_STARTED,
            component="heart",
            version=__version__,
            pid=self.state.pid,
            hostname=self.state.hostname,
            provider=self.state.provider,
            model=self.state.model,
            tools=len(self.registry.enabled()),
        )
        logger.info(
            "runtime_started",
            version=__version__,
            provider=self.state.provider,
            tools=len(self.registry.enabled()),
            data_dir=str(self.settings.data_dir),
            outcome="started",
        )
        return self

    async def stop(self) -> None:
        """Shut down gracefully. Safe to call twice, and on a failed start."""
        if not self._started:
            await self.store.close()
            return

        self.state.status = RuntimeStatus.STOPPING
        if self._heartbeat is not None:
            await self._heartbeat.stop()
            self._heartbeat = None

        if self._active:
            logger.info("awaiting_active_tasks", count=len(self._active))
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(
                    asyncio.gather(*self._active.values(), return_exceptions=True),
                    timeout=SHUTDOWN_GRACE_SECONDS,
                )
        for task in self._active.values():
            if not task.done():
                task.cancel()

        await emit(
            self.bus,
            EventType.RUNTIME_STOPPED,
            component="heart",
            uptime_seconds=round(self.state.uptime_seconds, 1),
            completed_tasks=self.state.completed_tasks,
            failed_tasks=self.state.failed_tasks,
        )
        await self.router.aclose()
        await self.bus.aclose()
        await self.store.close()

        self.state.status = RuntimeStatus.STOPPED
        self._started = False
        logger.info("runtime_stopped", outcome="stopped")

    async def __aenter__(self) -> Self:
        return await self.start()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.stop()

    # -- work ---------------------------------------------------------------

    def set_approval_prompt(self, prompt: ApprovalPrompt | None) -> None:
        """Install an interactive approver (the CLI does; the API does not)."""
        self.executor.set_approval_prompt(prompt)

    async def submit(self, objective: Objective) -> TaskOutcome:
        """Run an objective to completion, tracking it as active while it runs."""
        if not self._started:
            raise RuntimeError("Runtime.start() must be awaited before submitting work")

        coroutine = self.orchestrator.run(objective)
        task: asyncio.Task[TaskOutcome] = asyncio.create_task(coroutine)
        placeholder = objective.id
        self._active[placeholder] = task
        self.state.active_task_ids = list(self._active)
        try:
            return await task
        finally:
            self._active.pop(placeholder, None)
            self.state.active_task_ids = list(self._active)

    def spawn(self, objective: Objective) -> asyncio.Task[TaskOutcome]:
        """Start an objective in the background. Used by the API.

        The task id is allocated here rather than inside the orchestrator, so a
        caller can subscribe to the task's events before the first one is
        published. Without that, an event stream opened immediately after
        submitting would miss the opening events of the run.
        """
        if not self._started:
            raise RuntimeError("Runtime.start() must be awaited before submitting work")

        task_id = new_id()
        self._task_ids[objective.id] = task_id
        handle: asyncio.Task[TaskOutcome] = asyncio.create_task(
            self.orchestrator.run(objective, task_id=task_id)
        )
        self._active[task_id] = handle
        self.state.active_task_ids = list(self._active)
        handle.add_done_callback(lambda _: self._forget(task_id))
        return handle

    def task_id_for(self, objective_id: str) -> str | None:
        """The internal task id allocated for a spawned objective."""
        return self._task_ids.get(objective_id)

    def _forget(self, task_id: str) -> None:
        self._active.pop(task_id, None)
        self.state.active_task_ids = list(self._active)

    # -- health -------------------------------------------------------------

    async def health(self) -> RuntimeState:
        """A fresh snapshot with component checks performed."""
        components: list[ComponentHealth] = []

        store_ok, store_detail = await self.store.health_check()
        components.append(
            ComponentHealth(
                name="store",
                status=ComponentStatus.UP if store_ok else ComponentStatus.DOWN,
                detail=store_detail,
            )
        )

        provider_health = await self.router.health_check()
        components.append(
            ComponentHealth(
                name="model_provider",
                status=ComponentStatus.UP if provider_health.healthy else ComponentStatus.DEGRADED,
                detail=f"{self.router.provider.info.name}: {provider_health.detail}",
            )
        )

        components.append(
            ComponentHealth(
                name="tools",
                status=ComponentStatus.UP,
                detail=f"{len(self.registry.enabled())} enabled, "
                f"{len(self.registry.disabled)} disabled",
            )
        )
        components.append(
            ComponentHealth(
                name="semantic_memory",
                status=ComponentStatus.UP if self.semantic.available else ComponentStatus.UNKNOWN,
                detail="not configured in v0.1" if not self.semantic.available else "ready",
            )
        )

        pending = await self.approvals.pending()
        components.append(
            ComponentHealth(
                name="approvals",
                status=ComponentStatus.UP,
                detail=f"{len(pending)} pending",
            )
        )

        self.state.components = components
        # A degraded provider is not a dead control plane: read-only tools and
        # the audit trail still work, and saying "healthy" would be a lie.
        if not store_ok:
            self.state.status = RuntimeStatus.DEGRADED
        elif self._started:
            self.state.status = (
                RuntimeStatus.HEALTHY if provider_health.healthy else RuntimeStatus.DEGRADED
            )
        return self.state

    async def _track_task_counters(self, event: Any) -> None:
        """Keep completion counters current from the event stream."""
        if event.type is EventType.TASK_COMPLETED:
            self.state.completed_tasks += 1
        elif event.type is EventType.TASK_FAILED:
            self.state.failed_tasks += 1
        elif event.type is EventType.HEARTBEAT:
            self.state.heartbeats += 1
            self.state.last_heartbeat_at = event.timestamp

    @property
    def started(self) -> bool:
        return self._started


__all__ = ["SHUTDOWN_GRACE_SECONDS", "Runtime"]
