"""Enumerations shared across the control plane.

These are string enums on purpose: they land in JSON payloads, SQLite columns
and LLM prompts, and staying human-readable in all three is worth more than a
few bytes.
"""

from __future__ import annotations

from enum import StrEnum


class RiskLevel(StrEnum):
    """How much damage an operation can do if it is wrong.

    The ordering matters: :meth:`at_least` powers policy comparisons, so new
    members must be inserted in ascending order of danger.
    """

    READ = "read"
    """Observes state. Cannot change the machine."""

    WRITE = "write"
    """Creates or modifies data, confined to the configured workspace."""

    PRIVILEGED = "privileged"
    """Changes system state: services, packages, network configuration."""

    DESTRUCTIVE = "destructive"
    """Loses data or availability: deletion, formatting, shutdown, user removal."""

    @property
    def rank(self) -> int:
        return _RISK_ORDER[self]

    def at_least(self, other: RiskLevel) -> bool:
        """True when this level is as dangerous as ``other`` or worse."""
        return self.rank >= other.rank

    @classmethod
    def max(cls, *levels: RiskLevel) -> RiskLevel:
        """The most dangerous of the given levels; READ when none are given."""
        return max(levels, key=lambda level: level.rank, default=cls.READ)


_RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.READ: 0,
    RiskLevel.WRITE: 1,
    RiskLevel.PRIVILEGED: 2,
    RiskLevel.DESTRUCTIVE: 3,
}


class PolicyDecision(StrEnum):
    """The three outcomes the policy engine may return.

    There is deliberately no "allow with a warning" - an operation either
    proceeds, needs a human, or does not happen.
    """

    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class ApprovalState(StrEnum):
    """Lifecycle of a single approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CONSUMED = "consumed"
    """Approved *and* already spent. An approval authorises exactly one action."""


class TaskState(StrEnum):
    """Lifecycle of a task.

    Legal transitions live in :data:`scrappy_os.core.models.TASK_TRANSITIONS`.
    """

    CREATED = "created"
    PLANNING = "planning"
    AWAITING_APPROVAL = "awaiting_approval"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    ROLLING_BACK = "rolling_back"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in _TERMINAL_STATES


_TERMINAL_STATES: frozenset[TaskState] = frozenset(
    {TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED}
)


class AgentRole(StrEnum):
    """The three reasoning roles. Named for what they do, not who calls them."""

    BRAHMA = "brahma"
    """Creation: understands the objective and proposes a plan."""

    VISHNU = "vishnu"
    """Preservation: reviews plans, verifies postconditions, judges completion."""

    MAHESH = "mahesh"
    """Dissolution: rolls back, cleans up, diagnoses unrecoverable failure."""


class EventType(StrEnum):
    """Event names published on the bus.

    Keep these stable - they are a wire contract for anything subscribing,
    including future out-of-process transports.
    """

    RUNTIME_STARTED = "runtime.started"
    RUNTIME_STOPPED = "runtime.stopped"
    HEARTBEAT = "heartbeat"

    TASK_CREATED = "task.created"
    TASK_COMPLETED = "task.completed"
    TASK_FAILED = "task.failed"
    TASK_CANCELLED = "task.cancelled"

    PLAN_CREATED = "plan.created"
    PLAN_APPROVED = "plan.approved"
    PLAN_REJECTED = "plan.rejected"

    TOOL_REQUESTED = "tool.requested"
    TOOL_APPROVED = "tool.approved"
    TOOL_STARTED = "tool.started"
    TOOL_COMPLETED = "tool.completed"
    TOOL_FAILED = "tool.failed"

    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_RESOLVED = "approval.resolved"

    SECURITY_DENIED = "security.denied"

    AUTH_SUCCEEDED = "auth.succeeded"
    """A credential was presented and resolved to an actor."""

    AUTH_FAILED = "auth.failed"
    """A credential was missing, malformed or unrecognised. Never carries the credential."""

    AUTHZ_DENIED = "authz.denied"
    """A known actor lacked the scope required for the operation."""

    CREDENTIAL_CREATED = "credential.created"
    """A credential was issued. Records the id and the actor, never the token."""

    CREDENTIAL_ROTATED = "credential.rotated"
    """A replacement credential was issued for the same actor and scopes."""

    CREDENTIAL_REVOKED = "credential.revoked"
    """A credential was withdrawn and can no longer authenticate."""

    CREDENTIAL_PRUNED = "credential.pruned"
    """Expired or revoked credential records were deleted from the store."""

    AGENT_DECIDED = "agent.decided"
    ROLLBACK_STARTED = "rollback.started"
    ROLLBACK_COMPLETED = "rollback.completed"


class RuntimeStatus(StrEnum):
    """Coarse health of the runtime as a whole."""

    STARTING = "starting"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    STOPPING = "stopping"
    STOPPED = "stopped"


class ComponentStatus(StrEnum):
    """Health of one subsystem (store, provider, tools, ...)."""

    UP = "up"
    DEGRADED = "degraded"
    DOWN = "down"
    UNKNOWN = "unknown"
