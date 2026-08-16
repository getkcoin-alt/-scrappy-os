"""Core primitives: settings, typed domain models, events and errors."""

from __future__ import annotations

from scrappy_os.core.enums import (
    ApprovalState,
    EventType,
    PolicyDecision,
    RiskLevel,
    TaskState,
)
from scrappy_os.core.errors import (
    ApprovalRequired,
    PolicyViolation,
    ProviderError,
    ScrappyError,
    ToolError,
    ToolNotFound,
    ValidationFailed,
)
from scrappy_os.core.events import Event, EventBus, InProcessEventBus
from scrappy_os.core.models import (
    AgentDecision,
    ApprovalDecision,
    ApprovalRequest,
    AuditEvent,
    Objective,
    Observation,
    Plan,
    PlanStep,
    RuntimeState,
    Task,
    ToolCall,
    ToolResult,
)

__all__ = [
    "AgentDecision",
    "ApprovalDecision",
    "ApprovalRequest",
    "ApprovalRequired",
    "ApprovalState",
    "AuditEvent",
    "Event",
    "EventBus",
    "EventType",
    "InProcessEventBus",
    "Objective",
    "Observation",
    "Plan",
    "PlanStep",
    "PolicyDecision",
    "PolicyViolation",
    "ProviderError",
    "RiskLevel",
    "RuntimeState",
    "ScrappyError",
    "Task",
    "TaskState",
    "ToolCall",
    "ToolError",
    "ToolNotFound",
    "ToolResult",
    "ValidationFailed",
]
