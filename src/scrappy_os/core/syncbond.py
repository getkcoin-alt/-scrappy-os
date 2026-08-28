"""SYNCBOND v5 cross-system contract primitives.

This module is intentionally small and transport-neutral.  It defines the
minimum envelope and world-state vocabulary shared with Vault Zeta, Scrappy
Forge and Karnveer Command Center without changing Scrappy OS execution policy.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

SYNCBOND_VERSION = "5.0.0"


class ResolutionState(StrEnum):
    KNOWN = "known"
    UNKNOWN = "unknown"
    PENDING = "pending"
    CONFLICTED = "conflicted"
    UNAUTHORIZED = "unauthorized"
    UNAVAILABLE = "unavailable"


class ActorKind(StrEnum):
    HUMAN = "human"
    SERVICE = "service"
    NODE = "node"
    AGENT = "agent"


class EventType(StrEnum):
    OBJECTIVE_REQUESTED = "objective.requested"
    OBJECTIVE_COMPLETED = "objective.completed"
    WORLD_OBSERVED = "world.observed"
    WORLD_ENTITY_CHANGED = "world.entity.changed"
    ACTION_PROPOSED = "action.proposed"
    ACTION_RESULT = "action.result"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_RESOLVED = "approval.resolved"
    EXPERIENCE_RECORDED = "experience.recorded"
    EXPERIMENT_REQUESTED = "experiment.requested"
    EXPERIMENT_RESULT = "experiment.result"
    NODE_STATUS = "node.status"


class ProvenanceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(min_length=1)
    observed_at: datetime
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    reference: str | None = None


class SyncEnvelope(BaseModel):
    """Stable event envelope used across every Scrappy continuity component."""

    model_config = ConfigDict(extra="forbid")

    protocol: Literal["SYNCBOND"] = "SYNCBOND"
    schema_version: Literal["5.0.0"] = SYNCBOND_VERSION
    event_id: UUID = Field(default_factory=uuid4)
    correlation_id: UUID = Field(default_factory=uuid4)
    actor_id: str = Field(min_length=1)
    actor_kind: ActorKind
    event_type: EventType
    source: str = Field(min_length=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolution: ResolutionState = ResolutionState.KNOWN
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    provenance: list[ProvenanceRef] = Field(default_factory=list)
    payload: dict[str, Any] = Field(default_factory=dict)


class Objective(BaseModel):
    model_config = ConfigDict(extra="forbid")

    objective_id: UUID = Field(default_factory=uuid4)
    statement: str = Field(min_length=1)
    constraints: list[str] = Field(default_factory=list)
    success_criteria: list[str] = Field(default_factory=list)
    max_risk: Literal["read", "write", "privileged", "destructive"] = "read"


class WorldObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_id: str = Field(min_length=1)
    entity_type: str = Field(min_length=1)
    attribute: str = Field(min_length=1)
    value: Any
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    state: ResolutionState = ResolutionState.KNOWN
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    provenance: list[ProvenanceRef] = Field(default_factory=list)


class Experience(BaseModel):
    model_config = ConfigDict(extra="forbid")

    objective_id: UUID | None = None
    summary: str = Field(min_length=1)
    outcome: Literal["succeeded", "failed", "partial", "blocked"]
    evidence: list[str] = Field(default_factory=list)
    lessons: list[str] = Field(default_factory=list)


def envelope(
    *,
    actor_id: str,
    actor_kind: ActorKind,
    event_type: EventType,
    source: str,
    payload: BaseModel | dict[str, Any],
    correlation_id: UUID | None = None,
    resolution: ResolutionState = ResolutionState.KNOWN,
    confidence: float | None = None,
    provenance: list[ProvenanceRef] | None = None,
) -> SyncEnvelope:
    """Create a validated v5 envelope without coupling callers to a transport."""

    body = payload.model_dump(mode="json") if isinstance(payload, BaseModel) else payload
    return SyncEnvelope(
        correlation_id=correlation_id or uuid4(),
        actor_id=actor_id,
        actor_kind=actor_kind,
        event_type=event_type,
        source=source,
        resolution=resolution,
        confidence=confidence,
        provenance=provenance or [],
        payload=body,
    )
