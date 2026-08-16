"""The Breath - a periodic liveness signal, and nothing more.

A heartbeat publishes safe operational health on an interval. It is explicitly
**not** a trigger for autonomous work.

This is a design decision worth stating plainly, because the obvious next move
with a running daemon and an LLM is to let it "notice things and act". Scrappy
OS does not do that in v0.1. Work starts when a human states an objective. A
daemon that invents its own objectives is a daemon whose blast radius is
unbounded and whose audit trail nobody asked for. The seam for supervised
autonomy - a policy-bounded reaction to a named condition, still going through
the same approval gate - is noted in the roadmap, not smuggled in here.

The heartbeat also degrades safely: if collecting metrics fails, it publishes a
heartbeat that says collection failed rather than dying and leaving the runtime
looking alive but silent.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING, Any

import psutil

from scrappy_os.core.enums import EventType
from scrappy_os.core.events import emit
from scrappy_os.observability.logging import get_logger

if TYPE_CHECKING:
    from scrappy_os.heart.runtime import Runtime

logger = get_logger("breath")


class Heartbeat:
    """Publishes ``heartbeat`` events on a fixed interval."""

    def __init__(self, runtime: Runtime, *, interval: float | None = None) -> None:
        self._runtime = runtime
        self._interval = interval or runtime.settings.heartbeat_seconds
        self._task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()
        self.beats = 0

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self) -> None:
        if self.running:
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._loop(), name="scrappy-heartbeat")
        logger.info("heartbeat_started", interval_seconds=self._interval)

    async def stop(self) -> None:
        """Stop cleanly, waiting for the current beat to finish."""
        if self._task is None:
            return
        self._stopping.set()
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None
        logger.info("heartbeat_stopped", beats=self.beats)

    async def _loop(self) -> None:
        while not self._stopping.is_set():
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=self._interval)
                return  # stop() was called
            except TimeoutError:
                pass
            await self.beat()

    async def beat(self) -> dict[str, Any]:
        """Publish one heartbeat. Exposed so tests do not have to wait."""
        payload = self._collect()
        self.beats += 1
        await emit(
            self._runtime.bus,
            EventType.HEARTBEAT,
            component="breath",
            **payload,
        )
        return payload

    def _collect(self) -> dict[str, Any]:
        """Safe operational health.

        Deliberately narrow: uptime, load, memory, disk and task counters. No
        file contents, no process command lines, no configuration - a heartbeat
        is emitted constantly and lands in the audit log every time, so it must
        never carry anything sensitive.
        """
        state = self._runtime.state
        payload: dict[str, Any] = {
            "uptime_seconds": round(state.uptime_seconds, 1),
            "status": str(state.status),
            "active_tasks": len(state.active_task_ids),
            "completed_tasks": state.completed_tasks,
            "failed_tasks": state.failed_tasks,
            "beat": self.beats + 1,
        }
        try:
            memory = psutil.virtual_memory()
            payload["memory_percent"] = memory.percent
            payload["load_1m"] = round(psutil.getloadavg()[0], 2)
            payload["disk_percent"] = psutil.disk_usage("/").percent
        except (OSError, AttributeError, NotImplementedError) as exc:
            # Report the gap rather than dropping the beat: a heartbeat that
            # says "I could not read memory" is still a useful liveness signal.
            payload["metrics_error"] = f"{type(exc).__name__}: {exc}"
        return payload


__all__ = ["Heartbeat"]
