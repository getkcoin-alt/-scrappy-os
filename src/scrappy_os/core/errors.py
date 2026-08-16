"""Exception hierarchy.

Rule of the house: errors are *raised and reported*, never swallowed. Every
exception here carries enough structured context to end up in the audit log
without a human having to re-read a traceback.
"""

from __future__ import annotations

from typing import Any

from scrappy_os.core.enums import PolicyDecision, RiskLevel


class ScrappyError(Exception):
    """Base class for every error Scrappy OS raises deliberately."""

    def __init__(self, message: str, **context: Any) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = context

    def to_dict(self) -> dict[str, Any]:
        return {"error": type(self).__name__, "message": self.message, **self.context}


class ConfigurationError(ScrappyError):
    """Settings are missing or internally inconsistent."""


class ValidationFailed(ScrappyError):
    """Input did not satisfy a typed schema or a domain invariant."""


class ToolNotFound(ScrappyError):
    """A tool was requested by a name the registry does not know.

    This is a security event, not a typo: unknown capability means deny.
    """

    def __init__(self, tool_name: str, *, known: list[str] | None = None) -> None:
        super().__init__(f"Unknown tool {tool_name!r}", tool_name=tool_name, known=known or [])
        self.tool_name = tool_name


class ToolError(ScrappyError):
    """A tool ran and failed. Distinct from the tool being refused."""

    def __init__(self, message: str, *, tool_name: str, **context: Any) -> None:
        super().__init__(message, tool_name=tool_name, **context)
        self.tool_name = tool_name


class ToolTimeout(ToolError):
    """A tool exceeded its wall-clock budget and was terminated."""


class PathNotAllowed(ScrappyError):
    """A filesystem path resolved outside every permitted root."""

    def __init__(self, path: str, *, reason: str) -> None:
        super().__init__(f"Path not allowed: {path} ({reason})", path=path, reason=reason)
        self.path = path
        self.reason = reason


class PolicyViolation(ScrappyError):
    """The policy engine refused an operation outright."""

    def __init__(
        self,
        message: str,
        *,
        tool_name: str,
        risk: RiskLevel,
        rule: str,
        decision: PolicyDecision = PolicyDecision.DENY,
    ) -> None:
        super().__init__(
            message, tool_name=tool_name, risk=str(risk), rule=rule, decision=str(decision)
        )
        self.tool_name = tool_name
        self.risk = risk
        self.rule = rule
        self.decision = decision


class ApprovalRequired(ScrappyError):
    """The operation is permitted in principle but needs a human first."""

    def __init__(self, message: str, *, approval_id: str, tool_name: str, risk: RiskLevel) -> None:
        super().__init__(message, approval_id=approval_id, tool_name=tool_name, risk=str(risk))
        self.approval_id = approval_id
        self.tool_name = tool_name
        self.risk = risk


class ApprovalExpired(ScrappyError):
    """An approval was granted but is no longer valid."""


class ProviderError(ScrappyError):
    """A model provider failed: transport, auth, rate limit or bad output."""

    def __init__(self, message: str, *, provider: str, **context: Any) -> None:
        super().__init__(message, provider=provider, **context)
        self.provider = provider


class ProviderUnavailable(ProviderError):
    """The provider could not be reached at all."""


class StructuredOutputError(ProviderError):
    """The model returned text that is not the structure we demanded."""


class LimitExceeded(ScrappyError):
    """An orchestration budget ran out. This is how runaway loops end."""

    def __init__(self, message: str, *, limit_name: str, limit_value: float) -> None:
        super().__init__(message, limit_name=limit_name, limit_value=limit_value)
        self.limit_name = limit_name
        self.limit_value = limit_value


class InvalidStateTransition(ScrappyError):
    """A task was pushed into a state it cannot legally reach."""


__all__ = [
    "ApprovalExpired",
    "ApprovalRequired",
    "ConfigurationError",
    "InvalidStateTransition",
    "LimitExceeded",
    "PathNotAllowed",
    "PolicyViolation",
    "ProviderError",
    "ProviderUnavailable",
    "ScrappyError",
    "StructuredOutputError",
    "ToolError",
    "ToolNotFound",
    "ToolTimeout",
    "ValidationFailed",
]
