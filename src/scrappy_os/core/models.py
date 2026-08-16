"""The typed vocabulary of the control plane.

Everything that crosses a component boundary is one of these models. Agents
emit them, the policy engine reads them, the audit log persists them, and the
API serialises them. If a concept is not here, it does not exist in Scrappy OS.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from scrappy_os.core.enums import (
    AgentRole,
    ApprovalState,
    ComponentStatus,
    EventType,
    PolicyDecision,
    RiskLevel,
    RuntimeStatus,
    TaskState,
)
from scrappy_os.core.errors import InvalidStateTransition
from scrappy_os.core.identity import Actor


def new_id() -> str:
    """A fresh UUID4 string. Every task, call and approval gets one."""
    return str(uuid.uuid4())


def utc_now() -> datetime:
    """Timezone-aware UTC now. Naive datetimes are a bug in this codebase."""
    return datetime.now(UTC)


class ScrappyModel(BaseModel):
    """Shared model configuration.

    ``extra="forbid"`` is load-bearing: it is the first line of defence against
    an LLM inventing fields that a downstream component might trust.
    """

    model_config = ConfigDict(extra="forbid", frozen=False, use_enum_values=False)


# ---------------------------------------------------------------------------
# Objectives and tasks
# ---------------------------------------------------------------------------


class Objective(ScrappyModel):
    """What a human asked for, in their own words, plus how far we may go."""

    id: str = Field(default_factory=new_id)
    text: str = Field(min_length=1, max_length=8000)
    actor: str = Field(default="cli", description="Who asked, as a label. Never a model.")
    identity: Actor | None = Field(
        default=None,
        description=(
            "The authenticated principal behind this objective. Set by the interface that "
            "verified a credential; never accepted from a request body."
        ),
    )
    created_at: datetime = Field(default_factory=utc_now)
    max_risk: RiskLevel = Field(
        default=RiskLevel.READ,
        description="Ceiling for this objective; steps above it are refused outright.",
    )
    context: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = Field(
        default=False, description="When true, mutating steps are described, never executed."
    )

    @field_validator("text")
    @classmethod
    def _strip(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("objective text cannot be blank")
        return stripped

    @model_validator(mode="after")
    def _label_follows_identity(self) -> Self:
        """Keep the ``actor`` label honest when a real identity is attached.

        The two fields disagreeing is how a misleading audit trail starts, so
        the verified identity wins and the label becomes a rendering of it.
        """
        if self.identity is not None:
            self.actor = self.identity.label
        return self


TASK_TRANSITIONS: dict[TaskState, frozenset[TaskState]] = {
    TaskState.CREATED: frozenset({TaskState.PLANNING, TaskState.CANCELLED, TaskState.FAILED}),
    TaskState.PLANNING: frozenset(
        {
            TaskState.EXECUTING,
            TaskState.AWAITING_APPROVAL,
            TaskState.COMPLETED,
            TaskState.FAILED,
            TaskState.CANCELLED,
        }
    ),
    TaskState.AWAITING_APPROVAL: frozenset(
        {TaskState.EXECUTING, TaskState.PLANNING, TaskState.FAILED, TaskState.CANCELLED}
    ),
    TaskState.EXECUTING: frozenset(
        {
            TaskState.VERIFYING,
            TaskState.AWAITING_APPROVAL,
            TaskState.PLANNING,
            TaskState.ROLLING_BACK,
            TaskState.FAILED,
            TaskState.CANCELLED,
        }
    ),
    TaskState.VERIFYING: frozenset(
        {
            TaskState.EXECUTING,
            TaskState.PLANNING,
            TaskState.COMPLETED,
            TaskState.ROLLING_BACK,
            TaskState.FAILED,
            TaskState.CANCELLED,
        }
    ),
    TaskState.ROLLING_BACK: frozenset({TaskState.FAILED, TaskState.COMPLETED, TaskState.CANCELLED}),
    TaskState.COMPLETED: frozenset(),
    TaskState.FAILED: frozenset(),
    TaskState.CANCELLED: frozenset(),
}


def can_transition(current: TaskState, target: TaskState) -> bool:
    """Whether ``current -> target`` is a legal task transition."""
    return target in TASK_TRANSITIONS[current]


class Task(ScrappyModel):
    """One unit of autonomous work, from objective to conclusion."""

    id: str = Field(default_factory=new_id)
    objective: Objective
    state: TaskState = TaskState.CREATED
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    plan_id: str | None = None
    replan_count: int = 0
    model_calls: int = 0
    summary: str | None = Field(default=None, description="Human-facing conclusion.")
    error: str | None = None

    def transition_to(self, target: TaskState) -> Self:
        """Move to ``target`` or raise. Task state is never assigned directly."""
        if target == self.state:
            return self
        if not can_transition(self.state, target):
            raise InvalidStateTransition(
                f"Cannot move task from {self.state} to {target}",
                task_id=self.id,
                current=str(self.state),
                target=str(target),
            )
        self.state = target
        self.updated_at = utc_now()
        if target.is_terminal:
            self.finished_at = self.updated_at
        return self

    @property
    def duration_seconds(self) -> float:
        end = self.finished_at or utc_now()
        return (end - self.created_at).total_seconds()


# ---------------------------------------------------------------------------
# Plans
# ---------------------------------------------------------------------------


class PlanStep(ScrappyModel):
    """A single intended tool invocation, with its justification attached.

    ``expected_risk`` is what the planning agent *believes*; the tool's own
    classifier is authoritative at execution time. A mismatch is interesting
    and gets audited.
    """

    id: str = Field(default_factory=new_id)
    index: int = Field(ge=0)
    intent: str = Field(min_length=1, max_length=2000)
    tool_name: str = Field(min_length=1, max_length=64)
    arguments: dict[str, Any] = Field(default_factory=dict)
    expected_risk: RiskLevel = RiskLevel.READ
    expected_side_effects: list[str] = Field(default_factory=list)
    success_criteria: str | None = None
    rollback_hint: str | None = Field(
        default=None, description="What Mahesh should try if this step must be undone."
    )


class Plan(ScrappyModel):
    """Brahma's proposal for how to satisfy an objective."""

    id: str = Field(default_factory=new_id)
    task_id: str
    author: AgentRole = AgentRole.BRAHMA
    created_at: datetime = Field(default_factory=utc_now)
    reasoning: str = Field(default="", max_length=8000)
    steps: list[PlanStep] = Field(default_factory=list)
    revision: int = 0
    approved: bool = False
    review_notes: str | None = None

    @model_validator(mode="after")
    def _reindex(self) -> Self:
        for position, step in enumerate(self.steps):
            step.index = position
        return self

    @property
    def max_risk(self) -> RiskLevel:
        return RiskLevel.max(*(step.expected_risk for step in self.steps))


# ---------------------------------------------------------------------------
# Tool invocation
# ---------------------------------------------------------------------------


class ToolCall(ScrappyModel):
    """A concrete request to run one tool.

    Carries the full provenance the audit system needs: who asked, for what
    task, with which arguments, at what risk, and under whose approval.
    """

    id: str = Field(default_factory=new_id)
    task_id: str
    step_id: str | None = None
    tool_name: str = Field(min_length=1, max_length=64)
    arguments: dict[str, Any] = Field(default_factory=dict)
    actor: str = Field(
        default="scrappy",
        description="Proximate requester - usually the agent that proposed this step.",
    )
    identity: Actor | None = Field(
        default=None,
        description=(
            "The authenticated principal whose task this call belongs to. An agent proposes; "
            "a principal is accountable. Carried from the objective, never from tool arguments."
        ),
    )
    requested_at: datetime = Field(default_factory=utc_now)
    risk_level: RiskLevel = RiskLevel.READ
    approval_state: ApprovalState | None = None
    approval_id: str | None = None
    policy_decision: PolicyDecision | None = None
    policy_rule: str | None = None


class ToolResult(ScrappyModel):
    """The outcome of exactly one :class:`ToolCall`."""

    call_id: str
    task_id: str
    tool_name: str
    success: bool
    started_at: datetime = Field(default_factory=utc_now)
    duration_ms: float = Field(ge=0.0, default=0.0)
    output: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    truncated: bool = Field(default=False, description="Output was clipped to a size limit.")
    exit_code: int | None = None

    @model_validator(mode="after")
    def _failure_needs_reason(self) -> Self:
        if not self.success and not self.error:
            raise ValueError("a failed ToolResult must carry an error message")
        return self

    def summarise(self, limit: int = 2000) -> str:
        """A compact rendering for prompts. Never dumps unbounded output."""
        import json

        if not self.success:
            return f"FAILED: {self.error}"
        try:
            body = json.dumps(self.output, default=str, sort_keys=True)
        except (TypeError, ValueError):  # pragma: no cover - defensive
            body = str(self.output)
        if len(body) > limit:
            return body[:limit] + f"... [truncated, {len(body)} bytes total]"
        return body


class Observation(ScrappyModel):
    """What the system learned from a step. The unit of episodic memory."""

    id: str = Field(default_factory=new_id)
    task_id: str
    call_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    source: str = Field(description="Tool name, agent role, or 'system'.")
    content: str = Field(max_length=32000)
    success: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Agent output
# ---------------------------------------------------------------------------


class AgentDecision(ScrappyModel):
    """A reasoning turn's conclusion, recorded whether or not we act on it."""

    id: str = Field(default_factory=new_id)
    task_id: str
    role: AgentRole
    created_at: datetime = Field(default_factory=utc_now)
    decision: str = Field(description="continue | replan | rollback | complete | abort")
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 0.5
    reasoning: str = Field(default="", max_length=8000)
    concerns: list[str] = Field(default_factory=list)
    model: str | None = None
    provider: str | None = None
    duration_ms: float = 0.0


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------


class ApprovalRequest(ScrappyModel):
    """A specific operation held at the gate until a human answers.

    An approval authorises *this* request id and nothing else. There is no
    "approve all", no wildcard and no inheritance to later calls.
    """

    id: str = Field(default_factory=new_id)
    task_id: str
    call_id: str | None = None
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    risk: RiskLevel
    reason: str = Field(description="Why policy stopped here, in plain language.")
    summary: str = Field(description="One line describing the exact proposed operation.")
    requested_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None
    state: ApprovalState = ApprovalState.PENDING
    requires_confirmation_phrase: bool = Field(
        default=False,
        description="DESTRUCTIVE actions demand a typed phrase, not a keystroke.",
    )
    confirmation_phrase: str | None = None

    def is_expired(self, *, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        return (now or utc_now()) >= self.expires_at


class ApprovalDecision(ScrappyModel):
    """A human's answer to exactly one :class:`ApprovalRequest`."""

    request_id: str
    approved: bool
    decided_by: str = Field(default="operator", description="Who answered, as a label.")
    identity: Actor | None = Field(
        default=None,
        description=(
            "The authenticated principal that granted or refused. Over the API this comes "
            "from the verified credential, never from the request body - a caller that could "
            "name its own approver could launder an approval through someone else's name."
        ),
    )
    decided_at: datetime = Field(default_factory=utc_now)
    note: str | None = None
    confirmation_phrase: str | None = None

    @model_validator(mode="after")
    def _label_follows_identity(self) -> Self:
        if self.identity is not None:
            self.decided_by = self.identity.label
        return self


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class AuditEvent(ScrappyModel):
    """One durable, append-only record of something that happened.

    Payloads are redacted before they reach this model; see
    :mod:`scrappy_os.observability.redaction`.
    """

    id: str = Field(default_factory=new_id)
    timestamp: datetime = Field(default_factory=utc_now)
    event_type: EventType
    task_id: str | None = None
    actor: str = "scrappy"
    actor_id: str | None = Field(
        default=None, description="Authenticated principal id, when the action had one."
    )
    actor_type: str | None = Field(default=None, description="human | service | node | system.")
    auth_method: str | None = Field(
        default=None, description="How that principal was authenticated."
    )
    component: str = "runtime"
    tool_name: str | None = None
    risk: RiskLevel | None = None
    decision: PolicyDecision | None = None
    success: bool | None = None
    duration_ms: float | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    payload_sha256: str | None = Field(
        default=None, description="Set when the payload was hashed instead of stored."
    )


# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------


class ComponentHealth(ScrappyModel):
    """Health of a single subsystem."""

    name: str
    status: ComponentStatus = ComponentStatus.UNKNOWN
    detail: str | None = None
    checked_at: datetime = Field(default_factory=utc_now)


class RuntimeState(ScrappyModel):
    """A snapshot of the running control plane, as served by /status."""

    instance_id: str = Field(default_factory=new_id)
    version: str
    status: RuntimeStatus = RuntimeStatus.STARTING
    started_at: datetime = Field(default_factory=utc_now)
    hostname: str = ""
    pid: int = 0
    active_task_ids: list[str] = Field(default_factory=list)
    completed_tasks: int = 0
    failed_tasks: int = 0
    heartbeats: int = 0
    last_heartbeat_at: datetime | None = None
    components: list[ComponentHealth] = Field(default_factory=list)
    provider: str | None = None
    model: str | None = None

    @property
    def uptime_seconds(self) -> float:
        return (utc_now() - self.started_at).total_seconds()


__all__ = [
    "TASK_TRANSITIONS",
    "AgentDecision",
    "ApprovalDecision",
    "ApprovalRequest",
    "AuditEvent",
    "ComponentHealth",
    "Objective",
    "Observation",
    "Plan",
    "PlanStep",
    "RuntimeState",
    "ScrappyModel",
    "Task",
    "ToolCall",
    "ToolResult",
    "can_transition",
    "new_id",
    "utc_now",
]
