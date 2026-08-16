"""The event bus: delivery, filtering, backpressure and error containment."""

from __future__ import annotations

import asyncio

import pytest

from scrappy_os.core.enums import EventType
from scrappy_os.core.events import Event, EventBus, InProcessEventBus, emit


async def test_handlers_receive_published_events(bus: InProcessEventBus) -> None:
    received: list[Event] = []

    async def handler(event: Event) -> None:
        received.append(event)

    bus.add_handler(handler)
    await emit(bus, EventType.TASK_CREATED, task_id="t1", objective="check disk")

    assert len(received) == 1
    assert received[0].type is EventType.TASK_CREATED
    assert received[0].payload["objective"] == "check disk"


async def test_handlers_can_filter_by_event_type(bus: InProcessEventBus) -> None:
    security_events: list[Event] = []

    async def handler(event: Event) -> None:
        security_events.append(event)

    bus.add_handler(handler, types=[EventType.SECURITY_DENIED])
    await emit(bus, EventType.TASK_CREATED, task_id="t1")
    await emit(bus, EventType.SECURITY_DENIED, task_id="t1")

    assert [event.type for event in security_events] == [EventType.SECURITY_DENIED]


async def test_removed_handlers_stop_receiving(bus: InProcessEventBus) -> None:
    received: list[Event] = []

    async def handler(event: Event) -> None:
        received.append(event)

    bus.add_handler(handler)
    await emit(bus, EventType.HEARTBEAT)
    bus.remove_handler(handler)
    await emit(bus, EventType.HEARTBEAT)

    assert len(received) == 1


async def test_a_failing_handler_does_not_break_the_bus(bus: InProcessEventBus) -> None:
    """One bad sink must not stop the control plane - but it is counted, not hidden."""
    delivered: list[Event] = []

    async def broken(event: Event) -> None:
        raise RuntimeError("this handler is broken")

    async def working(event: Event) -> None:
        delivered.append(event)

    bus.add_handler(broken)
    bus.add_handler(working)
    await emit(bus, EventType.TASK_CREATED, task_id="t1")

    assert len(delivered) == 1
    assert bus.handler_errors == 1


async def test_subscriptions_filter_by_task(bus: InProcessEventBus) -> None:
    subscription = bus.subscribe(task_id="task-a")
    await emit(bus, EventType.TASK_CREATED, task_id="task-a")
    await emit(bus, EventType.TASK_CREATED, task_id="task-b")

    event = await asyncio.wait_for(subscription.get(), timeout=1.0)
    assert event is not None
    assert event.task_id == "task-a"

    subscription.close()
    assert await asyncio.wait_for(subscription.get(), timeout=1.0) is None


async def test_a_slow_subscriber_drops_events_rather_than_blocking(
    bus: InProcessEventBus,
) -> None:
    """Backpressure is explicit: a stalled API client cannot stall a tool call."""
    subscription = bus.subscribe(maxsize=4)
    for index in range(20):
        await emit(bus, EventType.HEARTBEAT, beat=index)

    assert subscription.dropped > 0
    event = await asyncio.wait_for(subscription.get(), timeout=1.0)
    assert event is not None, "the newest events survive; the oldest are dropped"


async def test_history_is_replayable_per_task(bus: InProcessEventBus) -> None:
    await emit(bus, EventType.TASK_CREATED, task_id="t1")
    await emit(bus, EventType.TOOL_STARTED, task_id="t1")
    await emit(bus, EventType.TASK_CREATED, task_id="t2")

    history = bus.history(task_id="t1")
    assert [event.type for event in history] == [
        EventType.TASK_CREATED,
        EventType.TOOL_STARTED,
    ]


async def test_history_is_bounded() -> None:
    """A long-running daemon must not accumulate events forever."""
    small = InProcessEventBus(history_size=10)
    for index in range(100):
        await emit(small, EventType.HEARTBEAT, beat=index)
    assert len(small.history(limit=1000)) == 10


async def test_close_ends_open_subscriptions(bus: InProcessEventBus) -> None:
    subscription = bus.subscribe()
    await bus.aclose()
    assert await asyncio.wait_for(subscription.get(), timeout=1.0) is None


async def test_in_process_bus_satisfies_the_protocol(bus: InProcessEventBus) -> None:
    """The seam for Redis/NATS is a runtime-checkable protocol, not a base class."""
    assert isinstance(bus, EventBus)


async def test_async_iteration_stops_cleanly(bus: InProcessEventBus) -> None:
    subscription = bus.subscribe(task_id="t1")
    await emit(bus, EventType.TASK_CREATED, task_id="t1")
    await emit(bus, EventType.TASK_COMPLETED, task_id="t1")
    subscription.close()

    seen = [event.type async for event in subscription]
    assert seen == [EventType.TASK_CREATED, EventType.TASK_COMPLETED]


@pytest.mark.parametrize(
    "event_type",
    [
        EventType.RUNTIME_STARTED,
        EventType.TASK_CREATED,
        EventType.PLAN_CREATED,
        EventType.TOOL_REQUESTED,
        EventType.TOOL_APPROVED,
        EventType.TOOL_COMPLETED,
        EventType.TOOL_FAILED,
        EventType.SECURITY_DENIED,
        EventType.HEARTBEAT,
    ],
)
def test_required_event_types_exist_with_stable_names(event_type: EventType) -> None:
    """These names are a wire contract for out-of-process transports."""
    assert "." in str(event_type) or str(event_type) == "heartbeat"
