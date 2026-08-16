"""The event bus.

v0.1 ships a single-process asyncio implementation. Everything that publishes
or subscribes depends only on the :class:`EventBus` protocol, so swapping in
Redis Streams or NATS later is a new class in this package - not a rewrite of
the orchestrator.

Two delivery styles are supported because they solve different problems:

* **Handlers** - callbacks invoked inline, used by the audit sink and the
  runtime counters, where dropping an event would be a correctness bug.
* **Subscriptions** - bounded queues consumed by API streams and the CLI, where
  a slow reader must never stall the control plane. These drop oldest-first and
  say so.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from datetime import datetime
from types import TracebackType
from typing import Any, Protocol, Self, runtime_checkable

from pydantic import Field

from scrappy_os.core.enums import EventType
from scrappy_os.core.identity import Actor
from scrappy_os.core.models import ScrappyModel, new_id, utc_now

EventHandler = Callable[["Event"], Awaitable[None]]

DEFAULT_QUEUE_SIZE = 512
DEFAULT_HISTORY_SIZE = 2000


class Event(ScrappyModel):
    """Something that happened, published for anyone who cares."""

    id: str = Field(default_factory=new_id)
    type: EventType
    timestamp: datetime = Field(default_factory=utc_now)
    task_id: str | None = None
    component: str = "runtime"
    payload: dict[str, Any] = Field(default_factory=dict)

    def matches(self, *, types: frozenset[EventType] | None, task_id: str | None) -> bool:
        if types is not None and self.type not in types:
            return False
        return not (task_id is not None and self.task_id != task_id)


@runtime_checkable
class EventBus(Protocol):
    """The contract every transport must satisfy."""

    async def publish(self, event: Event) -> None:
        """Deliver an event to all handlers and subscribers."""
        ...

    def add_handler(
        self, handler: EventHandler, *, types: Iterable[EventType] | None = None
    ) -> None:
        """Register an inline callback. Handlers are awaited during publish."""
        ...

    def remove_handler(self, handler: EventHandler) -> None:
        """Deregister a callback. Unknown handlers are ignored."""
        ...

    def subscribe(
        self,
        *,
        types: Iterable[EventType] | None = None,
        task_id: str | None = None,
        maxsize: int = DEFAULT_QUEUE_SIZE,
    ) -> Subscription:
        """Open a bounded queue of matching events."""
        ...

    def history(self, *, task_id: str | None = None, limit: int = 200) -> list[Event]:
        """Recently published events, oldest first."""
        ...

    async def aclose(self) -> None:
        """Release resources and close open subscriptions."""
        ...


class Subscription:
    """A bounded, drop-oldest queue of events for one consumer.

    Backpressure policy is explicit: when a consumer falls behind, the *oldest*
    undelivered events are dropped and ``dropped`` counts them. A slow API
    client must never be able to block a tool invocation.
    """

    def __init__(
        self,
        *,
        types: Iterable[EventType] | None = None,
        task_id: str | None = None,
        maxsize: int = DEFAULT_QUEUE_SIZE,
        on_close: Callable[[Subscription], None] | None = None,
    ) -> None:
        self.types: frozenset[EventType] | None = frozenset(types) if types is not None else None
        self.task_id = task_id
        self.dropped = 0
        self._queue: asyncio.Queue[Event | None] = asyncio.Queue(maxsize=maxsize)
        self._on_close = on_close
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def offer(self, event: Event) -> bool:
        """Non-blocking enqueue. Returns False when the event did not match."""
        if self._closed or not event.matches(types=self.types, task_id=self.task_id):
            return False
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            with contextlib.suppress(asyncio.QueueEmpty):
                self._queue.get_nowait()
                self.dropped += 1
            with contextlib.suppress(asyncio.QueueFull):
                self._queue.put_nowait(event)
        return True

    async def get(self) -> Event | None:
        """Next event, or ``None`` once the subscription is closed."""
        return await self._queue.get()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(asyncio.QueueFull):
            self._queue.put_nowait(None)
        if self._on_close is not None:
            self._on_close(self)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    async def __aiter__(self) -> AsyncIterator[Event]:
        while True:
            event = await self.get()
            if event is None:
                return
            yield event


class InProcessEventBus:
    """Single-process asyncio bus. The v0.1 default.

    Handler exceptions are caught so one bad subscriber cannot break the
    control plane, but they are never hidden: each one is logged with full
    context and counted in :attr:`handler_errors`.
    """

    def __init__(self, *, history_size: int = DEFAULT_HISTORY_SIZE) -> None:
        self._handlers: list[tuple[EventHandler, frozenset[EventType] | None]] = []
        self._subscriptions: list[Subscription] = []
        self._history: deque[Event] = deque(maxlen=history_size)
        self._lock = asyncio.Lock()
        self.published = 0
        self.handler_errors = 0

    async def publish(self, event: Event) -> None:
        async with self._lock:
            self._history.append(event)
            self.published += 1
            handlers = list(self._handlers)
            subscriptions = list(self._subscriptions)

        for handler, types in handlers:
            if types is not None and event.type not in types:
                continue
            try:
                await handler(event)
            except Exception as exc:  # noqa: BLE001 - one bad sink must not halt the bus
                self.handler_errors += 1
                _log_handler_error(handler, event, exc)

        for subscription in subscriptions:
            subscription.offer(event)

    def add_handler(
        self, handler: EventHandler, *, types: Iterable[EventType] | None = None
    ) -> None:
        selected = frozenset(types) if types is not None else None
        self._handlers.append((handler, selected))

    def remove_handler(self, handler: EventHandler) -> None:
        self._handlers = [entry for entry in self._handlers if entry[0] is not handler]

    def subscribe(
        self,
        *,
        types: Iterable[EventType] | None = None,
        task_id: str | None = None,
        maxsize: int = DEFAULT_QUEUE_SIZE,
    ) -> Subscription:
        subscription = Subscription(
            types=types, task_id=task_id, maxsize=maxsize, on_close=self._drop_subscription
        )
        self._subscriptions.append(subscription)
        return subscription

    def _drop_subscription(self, subscription: Subscription) -> None:
        self._subscriptions = [item for item in self._subscriptions if item is not subscription]

    def history(self, *, task_id: str | None = None, limit: int = 200) -> list[Event]:
        events = [event for event in self._history if task_id is None or event.task_id == task_id]
        return events[-limit:]

    async def aclose(self) -> None:
        for subscription in list(self._subscriptions):
            subscription.close()
        self._subscriptions.clear()
        self._handlers.clear()


def _log_handler_error(handler: EventHandler, event: Event, exc: Exception) -> None:
    """Report a failing handler. Imported lazily to keep core free of cycles."""
    from scrappy_os.observability.logging import get_logger

    get_logger("event_bus").error(
        "event_handler_failed",
        handler=getattr(handler, "__qualname__", repr(handler)),
        event_type=str(event.type),
        task_id=event.task_id,
        error=str(exc),
        error_type=type(exc).__name__,
    )


async def emit(
    bus: EventBus,
    event_type: EventType,
    *,
    task_id: str | None = None,
    component: str = "runtime",
    identity: Actor | None = None,
    **payload: Any,
) -> Event:
    """Convenience publisher. Returns the event so callers can correlate ids.

    ``identity`` is expanded into the ``actor_id`` / ``actor_type`` /
    ``auth_method`` keys that the audit log promotes to indexed columns. It is a
    named parameter rather than something each call site splats in, because the
    alternative - remembering four keys at fifteen emit sites - is how half a
    task's events end up unattributed. That is worse than none of them being:
    the trail looks complete while a filter on ``actor_id`` silently misses rows.

    Named ``identity`` rather than ``actor`` on purpose. Several call sites
    already pass ``actor=`` as a payload *string* (the proximate requester, e.g.
    ``agent:brahma``), and both facts are worth keeping - one names who proposed
    the action, the other who is accountable for it.
    """
    if identity is not None:
        payload = {**identity.audit_fields(), **payload}
    event = Event(type=event_type, task_id=task_id, component=component, payload=payload)
    await bus.publish(event)
    return event


__all__ = [
    "DEFAULT_QUEUE_SIZE",
    "Event",
    "EventBus",
    "EventHandler",
    "InProcessEventBus",
    "Subscription",
    "emit",
]
