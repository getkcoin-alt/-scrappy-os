from uuid import UUID

import pytest
from pydantic import ValidationError

from scrappy_os.core.syncbond import (
    ActorKind,
    EventType,
    Objective,
    ResolutionState,
    SYNCBOND_VERSION,
    envelope,
)


def test_syncbond_objective_envelope_is_stable() -> None:
    objective = Objective(
        statement="Inspect service health",
        success_criteria=["report verified status"],
    )

    event = envelope(
        actor_id="human:karnveer",
        actor_kind=ActorKind.HUMAN,
        event_type=EventType.OBJECTIVE_REQUESTED,
        source="command-center",
        payload=objective,
    )

    assert event.protocol == "SYNCBOND"
    assert event.schema_version == SYNCBOND_VERSION
    assert isinstance(event.event_id, UUID)
    assert isinstance(event.correlation_id, UUID)
    assert event.resolution is ResolutionState.KNOWN
    assert event.payload["statement"] == "Inspect service health"


def test_syncbond_rejects_fake_certainty() -> None:
    with pytest.raises(ValidationError):
        envelope(
            actor_id="node:ssn-01",
            actor_kind=ActorKind.NODE,
            event_type=EventType.WORLD_OBSERVED,
            source="scrappy-os",
            payload={"entity_id": "service:api"},
            confidence=1.01,
        )
