"""The policy engine.

Every machine-changing action passes through :meth:`PolicyEngine.evaluate`.
There is no side door: tools are executed by the executor, and the executor
calls this first.

The rules, in evaluation order:

1. Unknown tool                      -> DENY   (unknown capability is not a capability)
2. Tool disabled by configuration    -> DENY
3. Risk above the objective ceiling  -> DENY
4. Approvals disabled and risk > WRITE -> DENY
5. READ                              -> ALLOW
6. WRITE inside the workspace        -> ALLOW
7. WRITE outside the workspace       -> REQUIRE_APPROVAL
8. PRIVILEGED                        -> REQUIRE_APPROVAL
9. DESTRUCTIVE                       -> REQUIRE_APPROVAL + typed confirmation
10. Anything unmatched               -> DENY   (fail closed)

Rule 10 is not decoration. If a future risk level is added and someone forgets
to write a rule for it, the engine denies rather than guesses.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.enums import PolicyDecision, RiskLevel
from scrappy_os.core.models import ToolCall


@dataclass(frozen=True, slots=True)
class PolicyVerdict:
    """The engine's answer about one proposed operation."""

    decision: PolicyDecision
    risk: RiskLevel
    rule: str
    reason: str
    requires_confirmation_phrase: bool = False

    @property
    def allowed(self) -> bool:
        return self.decision is PolicyDecision.ALLOW

    @property
    def needs_approval(self) -> bool:
        return self.decision is PolicyDecision.REQUIRE_APPROVAL

    @property
    def denied(self) -> bool:
        return self.decision is PolicyDecision.DENY

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": str(self.decision),
            "risk": str(self.risk),
            "rule": self.rule,
            "reason": self.reason,
            "requires_confirmation_phrase": self.requires_confirmation_phrase,
        }


@dataclass(slots=True)
class PolicyContext:
    """What the engine needs to know beyond the call itself."""

    max_risk: RiskLevel = RiskLevel.READ
    """Ceiling for the current objective. Steps above it are refused."""

    dry_run: bool = False
    known_tools: frozenset[str] = field(default_factory=frozenset)
    disabled_tools: frozenset[str] = field(default_factory=frozenset)
    paths: Sequence[Path] = ()
    """Resolved paths the operation touches, for workspace containment checks."""


class PolicyEngine:
    """Evaluates proposed operations against the configured policy."""

    def __init__(self, settings: ScrappySettings) -> None:
        self._settings = settings
        self._workspace = settings.workspace.expanduser().resolve(strict=False)

    @property
    def workspace(self) -> Path:
        return self._workspace

    def evaluate(
        self,
        call: ToolCall,
        *,
        risk: RiskLevel,
        context: PolicyContext,
        reason: str = "",
    ) -> PolicyVerdict:
        """Decide whether ``call`` may proceed at the given ``risk``.

        ``risk`` is the *effective* risk, already combining the tool's static
        classification with its argument-aware one. The engine does not
        re-derive it; it decides what to do about it.
        """
        detail = reason or f"{call.tool_name} classified {risk}"

        if context.known_tools and call.tool_name not in context.known_tools:
            return PolicyVerdict(
                PolicyDecision.DENY,
                RiskLevel.DESTRUCTIVE,
                rule="unknown-tool",
                reason=f"{call.tool_name!r} is not a registered tool; unknown actions are denied",
            )

        if call.tool_name in context.disabled_tools:
            return PolicyVerdict(
                PolicyDecision.DENY,
                risk,
                rule="tool-disabled",
                reason=f"{call.tool_name!r} is disabled by configuration",
            )

        if risk.at_least(RiskLevel.WRITE) and context.dry_run:
            return PolicyVerdict(
                PolicyDecision.DENY,
                risk,
                rule="dry-run",
                reason=(
                    "task is running in dry-run mode; mutating steps are described, not executed"
                ),
            )

        if risk.rank > context.max_risk.rank:
            return PolicyVerdict(
                PolicyDecision.DENY,
                risk,
                rule="risk-ceiling",
                reason=(
                    f"{risk} exceeds the ceiling {context.max_risk} set for this objective; "
                    "raise the ceiling explicitly to permit it"
                ),
            )

        if risk is RiskLevel.READ:
            return PolicyVerdict(PolicyDecision.ALLOW, risk, rule="read-allowed", reason=detail)

        if not self._settings.allow_approvals and risk.at_least(RiskLevel.PRIVILEGED):
            return PolicyVerdict(
                PolicyDecision.DENY,
                risk,
                rule="approvals-disabled",
                reason="approvals are disabled on this instance; privileged work is refused",
            )

        if risk is RiskLevel.WRITE:
            outside = [path for path in context.paths if not self._inside_workspace(path)]
            if outside:
                return PolicyVerdict(
                    PolicyDecision.REQUIRE_APPROVAL,
                    risk,
                    rule="write-outside-workspace",
                    reason=f"writes outside the workspace: {', '.join(str(p) for p in outside)}",
                )
            return PolicyVerdict(
                PolicyDecision.ALLOW, risk, rule="write-in-workspace", reason=detail
            )

        if risk is RiskLevel.PRIVILEGED:
            return PolicyVerdict(
                PolicyDecision.REQUIRE_APPROVAL,
                risk,
                rule="privileged-requires-approval",
                reason=detail,
            )

        if risk is RiskLevel.DESTRUCTIVE:
            return PolicyVerdict(
                PolicyDecision.REQUIRE_APPROVAL,
                risk,
                rule="destructive-requires-confirmation",
                reason=detail,
                requires_confirmation_phrase=True,
            )

        # Unreachable today: the branches above are exhaustive over RiskLevel,
        # which is why mypy flags this line. It stays because the failure mode of
        # a new RiskLevel arriving without a rule must be "deny", never "fall
        # through to allow" - and the compiler cannot enforce that for a future
        # edit, only this line can.
        return PolicyVerdict(  # type: ignore[unreachable]
            PolicyDecision.DENY,
            risk,
            rule="default-deny",
            reason=f"no rule matched risk {risk}; denying by default",
        )

    def _inside_workspace(self, path: Path) -> bool:
        resolved = Path(path).expanduser().resolve(strict=False)
        return resolved == self._workspace or resolved.is_relative_to(self._workspace)


__all__ = ["PolicyContext", "PolicyEngine", "PolicyVerdict"]
