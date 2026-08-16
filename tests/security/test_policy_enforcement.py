"""Policy must fail closed, and approvals must actually gate.

The properties under test:

* Unknown tools are denied, not guessed at.
* PRIVILEGED and DESTRUCTIVE operations cannot run without an approval.
* An approval authorises one operation, once.
* A denial is recorded in the audit log.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.enums import ApprovalState, EventType, PolicyDecision, RiskLevel
from scrappy_os.core.errors import ScrappyError
from scrappy_os.core.events import InProcessEventBus
from scrappy_os.core.models import ApprovalDecision, ApprovalRequest, ToolCall
from scrappy_os.security.approvals import CONFIRMATION_PHRASE, ApprovalManager
from scrappy_os.security.audit import AuditLog
from scrappy_os.security.policy import PolicyContext, PolicyEngine
from scrappy_os.tools.executor import ToolExecutor

pytestmark = pytest.mark.security


def _call(tool_name: str, **arguments: object) -> ToolCall:
    return ToolCall(task_id="task-1", tool_name=tool_name, arguments=dict(arguments))


# ---------------------------------------------------------------------------
# fail-closed behaviour
# ---------------------------------------------------------------------------


def test_unknown_tool_is_denied(policy: PolicyEngine) -> None:
    verdict = policy.evaluate(
        _call("definitely.not.a.tool"),
        risk=RiskLevel.READ,
        context=PolicyContext(max_risk=RiskLevel.DESTRUCTIVE, known_tools=frozenset({"fs.read"})),
    )
    assert verdict.decision is PolicyDecision.DENY
    assert verdict.rule == "unknown-tool"


def test_disabled_tool_is_denied(policy: PolicyEngine) -> None:
    verdict = policy.evaluate(
        _call("shell.run"),
        risk=RiskLevel.READ,
        context=PolicyContext(
            max_risk=RiskLevel.DESTRUCTIVE,
            known_tools=frozenset({"shell.run"}),
            disabled_tools=frozenset({"shell.run"}),
        ),
    )
    assert verdict.decision is PolicyDecision.DENY
    assert verdict.rule == "tool-disabled"


@pytest.mark.parametrize(
    ("risk", "ceiling"),
    [
        (RiskLevel.WRITE, RiskLevel.READ),
        (RiskLevel.PRIVILEGED, RiskLevel.WRITE),
        (RiskLevel.DESTRUCTIVE, RiskLevel.PRIVILEGED),
    ],
)
def test_risk_above_the_ceiling_is_denied_outright(
    policy: PolicyEngine, risk: RiskLevel, ceiling: RiskLevel
) -> None:
    """Above the ceiling means denied, never escalated to an approval prompt."""
    verdict = policy.evaluate(_call("fs.write"), risk=risk, context=PolicyContext(max_risk=ceiling))
    assert verdict.decision is PolicyDecision.DENY
    assert verdict.rule == "risk-ceiling"


def test_read_is_allowed_at_the_default_ceiling(policy: PolicyEngine) -> None:
    verdict = policy.evaluate(
        _call("system.disk"), risk=RiskLevel.READ, context=PolicyContext(max_risk=RiskLevel.READ)
    )
    assert verdict.decision is PolicyDecision.ALLOW


def test_write_inside_workspace_is_allowed(policy: PolicyEngine, workspace: Path) -> None:
    verdict = policy.evaluate(
        _call("fs.write"),
        risk=RiskLevel.WRITE,
        context=PolicyContext(max_risk=RiskLevel.WRITE, paths=[workspace / "note.txt"]),
    )
    assert verdict.decision is PolicyDecision.ALLOW
    assert verdict.rule == "write-in-workspace"


def test_write_outside_workspace_requires_approval(policy: PolicyEngine, tmp_path: Path) -> None:
    verdict = policy.evaluate(
        _call("fs.write"),
        risk=RiskLevel.WRITE,
        context=PolicyContext(max_risk=RiskLevel.WRITE, paths=[tmp_path / "elsewhere.txt"]),
    )
    assert verdict.decision is PolicyDecision.REQUIRE_APPROVAL


def test_privileged_requires_approval(policy: PolicyEngine) -> None:
    verdict = policy.evaluate(
        _call("shell.run"),
        risk=RiskLevel.PRIVILEGED,
        context=PolicyContext(max_risk=RiskLevel.PRIVILEGED),
    )
    assert verdict.decision is PolicyDecision.REQUIRE_APPROVAL
    assert not verdict.requires_confirmation_phrase


def test_destructive_requires_a_typed_confirmation(policy: PolicyEngine) -> None:
    verdict = policy.evaluate(
        _call("fs.delete"),
        risk=RiskLevel.DESTRUCTIVE,
        context=PolicyContext(max_risk=RiskLevel.DESTRUCTIVE),
    )
    assert verdict.decision is PolicyDecision.REQUIRE_APPROVAL
    assert verdict.requires_confirmation_phrase


def test_approvals_disabled_denies_privileged_work(
    settings: ScrappySettings,
) -> None:
    """An unattended deployment refuses rather than parking forever."""
    settings.allow_approvals = False
    engine = PolicyEngine(settings)
    verdict = engine.evaluate(
        _call("shell.run"),
        risk=RiskLevel.PRIVILEGED,
        context=PolicyContext(max_risk=RiskLevel.DESTRUCTIVE),
    )
    assert verdict.decision is PolicyDecision.DENY
    assert verdict.rule == "approvals-disabled"


def test_dry_run_denies_mutations_but_not_reads(policy: PolicyEngine, workspace: Path) -> None:
    write = policy.evaluate(
        _call("fs.write"),
        risk=RiskLevel.WRITE,
        context=PolicyContext(max_risk=RiskLevel.WRITE, dry_run=True, paths=[workspace / "x.txt"]),
    )
    assert write.decision is PolicyDecision.DENY
    assert write.rule == "dry-run"

    read = policy.evaluate(
        _call("system.disk"),
        risk=RiskLevel.READ,
        context=PolicyContext(max_risk=RiskLevel.READ, dry_run=True),
    )
    assert read.decision is PolicyDecision.ALLOW


# ---------------------------------------------------------------------------
# executor enforcement
# ---------------------------------------------------------------------------


async def test_privileged_operation_without_an_approver_does_not_run(
    executor: ToolExecutor,
) -> None:
    """No interactive approver means refusal, never silent execution."""
    outcome = await executor.execute(
        _call("shell.run", argv=["systemctl", "restart", "nginx"]),
        max_risk=RiskLevel.PRIVILEGED,
    )
    assert not outcome.result.success
    assert outcome.verdict.needs_approval
    assert "Approval" in (outcome.result.error or "")


async def test_declined_approval_does_not_run_the_tool(
    executor: ToolExecutor, bus: InProcessEventBus
) -> None:
    """A declined approval means the tool never starts, not that it fails late."""

    async def decline(request: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(request_id=request.id, approved=False, note="no thanks")

    executor.set_approval_prompt(decline)
    outcome = await executor.execute(
        _call("shell.run", argv=["systemctl", "restart", "nginx"]),
        max_risk=RiskLevel.PRIVILEGED,
    )

    assert not outcome.result.success
    assert "declined" in (outcome.result.error or "").lower()
    started = [event for event in bus.history() if event.type is EventType.TOOL_STARTED]
    assert not started, "the tool must never start when approval is declined"


async def test_deleting_inside_the_workspace_is_a_write_not_a_deletion_incident(
    executor: ToolExecutor, workspace: Path
) -> None:
    """Scratch files are ours to remove.

    Deletion is DESTRUCTIVE *outside* the workspace; inside it, the argument-aware
    classifier downgrades to WRITE so routine cleanup does not train operators to
    click through confirmations.
    """
    target = workspace / "scratch.txt"
    target.write_text("temporary")

    outcome = await executor.execute(_call("fs.delete", path=str(target)), max_risk=RiskLevel.WRITE)
    assert outcome.result.success
    assert outcome.call.risk_level is RiskLevel.WRITE
    assert not target.exists()


async def test_deleting_outside_the_workspace_is_destructive(
    executor: ToolExecutor, tmp_path: Path
) -> None:
    """And outside it, the same tool needs a DESTRUCTIVE-grade approval.

    Note the layering: policy escalates to an approval, and the filesystem tool
    *additionally* confines writes to the workspace. An approval widens what
    policy permits; it never widens where the filesystem tools may reach.
    """
    target = tmp_path / "not-ours.txt"
    target.write_text("someone else's data")

    outcome = await executor.execute(_call("fs.delete", path=str(target)), max_risk=RiskLevel.WRITE)
    assert not outcome.result.success
    assert outcome.verdict.rule == "risk-ceiling"
    assert target.exists(), "the file must survive"


async def test_unknown_tool_is_denied_by_the_executor(executor: ToolExecutor) -> None:
    outcome = await executor.execute(_call("os.rm_rf"), max_risk=RiskLevel.DESTRUCTIVE)
    assert not outcome.result.success
    assert outcome.verdict.rule == "unknown-tool"


async def test_denial_is_recorded_in_the_audit_log(executor: ToolExecutor, audit: AuditLog) -> None:
    """A refusal lands in both the event stream and the tool-call ledger."""
    await executor.execute(_call("made.up.tool"), max_risk=RiskLevel.DESTRUCTIVE)

    events = await audit.for_task("task-1")
    assert any(event["event_type"] == "security.denied" for event in events)

    calls = await audit.calls_for_task("task-1")
    assert calls, "a denied call must still be recorded"
    assert calls[0]["policy_decision"] == "deny"
    assert calls[0]["success"] == 0


async def test_invalid_arguments_never_reach_the_tool(executor: ToolExecutor) -> None:
    """Extra fields are rejected: a model cannot smuggle in an unknown option."""
    outcome = await executor.execute(
        _call("system.disk", include_pseudo=False, sudo=True), max_risk=RiskLevel.READ
    )
    assert not outcome.result.success
    assert outcome.verdict.rule == "invalid-arguments"


# ---------------------------------------------------------------------------
# approval semantics
# ---------------------------------------------------------------------------


async def test_approval_is_single_use(approvals: ApprovalManager) -> None:
    """A spent approval cannot authorise a second operation."""
    request = await approvals.request(
        _call("shell.run", argv=["systemctl", "restart", "nginx"]),
        risk=RiskLevel.PRIVILEGED,
        reason="service state will change",
    )
    await approvals.resolve(ApprovalDecision(request_id=request.id, approved=True))

    consumed = await approvals.consume(request.id)
    assert consumed.state is ApprovalState.CONSUMED

    with pytest.raises(ScrappyError, match="not approved"):
        await approvals.consume(request.id)


async def test_destructive_approval_requires_the_exact_phrase(
    approvals: ApprovalManager,
) -> None:
    request = await approvals.request(
        _call("fs.delete", path="/var/data"),
        risk=RiskLevel.DESTRUCTIVE,
        reason="deleting outside the workspace",
        requires_confirmation_phrase=True,
    )

    with pytest.raises(ScrappyError, match="confirmation phrase"):
        await approvals.resolve(
            ApprovalDecision(request_id=request.id, approved=True, confirmation_phrase="yes please")
        )

    resolved = await approvals.resolve(
        ApprovalDecision(
            request_id=request.id, approved=True, confirmation_phrase=CONFIRMATION_PHRASE
        )
    )
    assert resolved.state is ApprovalState.APPROVED


async def test_approval_cannot_be_resolved_twice(approvals: ApprovalManager) -> None:
    request = await approvals.request(
        _call("shell.run", argv=["systemctl", "restart", "nginx"]),
        risk=RiskLevel.PRIVILEGED,
        reason="service state will change",
    )
    await approvals.resolve(ApprovalDecision(request_id=request.id, approved=True))
    with pytest.raises(ScrappyError, match="already"):
        await approvals.resolve(ApprovalDecision(request_id=request.id, approved=False))


async def test_approval_summary_names_the_exact_operation(
    approvals: ApprovalManager,
) -> None:
    """An operator must be told *which* service, not just "restart a service"."""
    request = await approvals.request(
        _call("shell.run", argv=["systemctl", "restart", "nginx"]),
        risk=RiskLevel.PRIVILEGED,
        reason="service state will change",
    )
    assert "systemctl restart nginx" in request.summary


async def test_expired_approval_cannot_be_consumed(approvals: ApprovalManager) -> None:
    from datetime import UTC, datetime, timedelta

    request = await approvals.request(
        _call("shell.run", argv=["systemctl", "restart", "nginx"]),
        risk=RiskLevel.PRIVILEGED,
        reason="service state will change",
    )
    await approvals.resolve(ApprovalDecision(request_id=request.id, approved=True))

    # Rewind the expiry rather than sleeping through the TTL.
    # Reaching into the store beats making this a five-minute test.
    await approvals._store.execute(
        "UPDATE approvals SET expires_at = ? WHERE id = ?",
        ((datetime.now(UTC) - timedelta(minutes=1)).isoformat(), request.id),
    )
    with pytest.raises(ScrappyError):
        await approvals.consume(request.id)
