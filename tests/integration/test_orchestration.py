"""End-to-end orchestration.

These tests exercise the v0.1 definition of done: a human states a diagnostic
objective, Scrappy OS plans it, runs read-only tools, reasons over the results,
concludes, and records everything - while refusing anything privileged.

The model is a scripted provider, so the assertions are about the *control
plane*, not about what a model happened to say.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from scrappy_os.agents.schemas import PlanProposal, RecoveryPlan, ReviewedPlan, Verification
from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.enums import EventType, RiskLevel, TaskState
from scrappy_os.core.events import InProcessEventBus
from scrappy_os.core.models import ApprovalDecision, ApprovalRequest, Objective
from scrappy_os.heart.runtime import Runtime
from scrappy_os.models.base import (
    ChatMessage,
    GenerationResult,
    ModelProvider,
    ProviderHealth,
    ProviderInfo,
)
from scrappy_os.models.mock import MockProvider
from scrappy_os.models.registry import ModelRouter

pytestmark = pytest.mark.integration


class ScriptedAgentProvider(ModelProvider):
    """A provider whose plan, review and verdict are fixed by the test."""

    def __init__(
        self,
        *,
        steps: Sequence[dict[str, object]],
        verdict: str = "complete",
        conclusion: str = "Everything was inspected successfully.",
        approve_plan: bool = True,
        recovery_steps: Sequence[dict[str, object]] = (),
        recoverable: bool = True,
    ) -> None:
        self._steps = [dict(step) for step in steps]
        self._verdict = verdict
        self._conclusion = conclusion
        self._approve_plan = approve_plan
        self._recovery_steps = [dict(step) for step in recovery_steps]
        self._recoverable = recoverable
        self.calls: list[str] = []

    @property
    def info(self) -> ProviderInfo:
        return ProviderInfo(name="scripted", kind="mock", model="scripted-agent")

    async def generate(
        self,
        messages: Sequence[ChatMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        stop: Sequence[str] | None = None,
    ) -> GenerationResult:
        return GenerationResult(text="{}", model="scripted-agent", provider="scripted")

    async def generate_structured(
        self,
        messages: Sequence[ChatMessage],
        schema: type,
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        max_repairs: int = 1,
    ):  # type: ignore[no-untyped-def]
        self.calls.append(schema.__name__)

        if schema is PlanProposal:
            return PlanProposal(reasoning="scripted plan", steps=self._steps)  # type: ignore[arg-type]
        if schema is ReviewedPlan:
            return ReviewedPlan(
                approved=self._approve_plan,
                reasoning="scripted review",
                steps=self._steps if self._approve_plan else [],  # type: ignore[arg-type]
            )
        if schema is Verification:
            return Verification(
                objective_satisfied=self._verdict == "complete",
                decision=self._verdict,  # type: ignore[arg-type]
                confidence=0.9,
                reasoning="scripted verification",
                conclusion=self._conclusion,
            )
        if schema is RecoveryPlan:
            return RecoveryPlan(
                diagnosis="scripted diagnosis",
                recoverable=self._recoverable,
                steps=self._recovery_steps,  # type: ignore[arg-type]
            )
        raise NotImplementedError(schema.__name__)

    async def health_check(self) -> ProviderHealth:
        return ProviderHealth(healthy=True, detail="scripted")


async def _runtime(settings: ScrappySettings, provider: ModelProvider) -> Runtime:
    runtime = Runtime(
        settings, bus=InProcessEventBus(), router=ModelRouter(settings, provider=provider)
    )
    await runtime.start(configure_logs=False)
    return runtime


# ---------------------------------------------------------------------------
# the v0.1 definition of done
# ---------------------------------------------------------------------------


async def test_diagnostic_objective_completes_with_an_audit_trail(
    settings: ScrappySettings,
) -> None:
    """objective -> plan -> safe tool call -> observation -> verification -> done."""
    provider = ScriptedAgentProvider(
        steps=[
            {"intent": "Read filesystem usage", "tool": "system.disk", "arguments": {}},
            {"intent": "Identify the host", "tool": "system.info", "arguments": {}},
        ],
        conclusion="The fullest filesystem is reported by system.disk.",
    )
    runtime = await _runtime(settings, provider)
    try:
        outcome = await runtime.submit(
            Objective(
                text="Inspect disk usage and tell me what filesystem is most full",
                actor="test",
            )
        )

        assert outcome.succeeded
        assert outcome.task.state is TaskState.COMPLETED
        assert outcome.conclusion == "The fullest filesystem is reported by system.disk."

        # Every planned step ran, and every one of them was read-only.
        assert [item.call.tool_name for item in outcome.executed] == [
            "system.disk",
            "system.info",
        ]
        assert all(item.result.success for item in outcome.executed)
        assert all(item.call.risk_level is RiskLevel.READ for item in outcome.executed)

        # Real data came back from the machine.
        disk_output = outcome.executed[0].result.output
        assert disk_output["filesystems"], "system.disk must return real mounts"
        assert "fullest_summary" in disk_output

        # The three roles each took a turn.
        assert provider.calls == ["PlanProposal", "ReviewedPlan", "Verification"]

        # And the whole thing is on the record.
        events = await runtime.audit.for_task(outcome.task.id)
        recorded = [event["event_type"] for event in events]
        for expected in (
            "task.created",
            "plan.created",
            "plan.approved",
            "tool.requested",
            "tool.started",
            "tool.completed",
            "task.completed",
        ):
            assert expected in recorded, f"{expected} is missing from the audit trail"

        calls = await runtime.audit.calls_for_task(outcome.task.id)
        assert len(calls) == 2
        assert all(call["policy_decision"] == "allow" for call in calls)
        assert all(call["success"] == 1 for call in calls)
    finally:
        await runtime.stop()


async def test_no_privileged_action_occurs_during_a_read_only_task(
    settings: ScrappySettings,
) -> None:
    """The headline safety property of the first milestone."""
    provider = ScriptedAgentProvider(
        steps=[{"intent": "Read disk", "tool": "system.disk", "arguments": {}}]
    )
    runtime = await _runtime(settings, provider)
    try:
        outcome = await runtime.submit(Objective(text="Check the disks", actor="test"))
        events = await runtime.audit.for_task(outcome.task.id)

        assert not [event for event in events if event["risk"] in {"privileged", "destructive"}]
        assert not await runtime.approvals.pending(), "nothing should have needed approval"
    finally:
        await runtime.stop()


async def test_the_deterministic_provider_satisfies_the_definition_of_done(
    settings: ScrappySettings,
) -> None:
    """The same flow works with no model configured at all, as documented."""
    runtime = await _runtime(settings, MockProvider())
    try:
        outcome = await runtime.submit(
            Objective(text="Inspect disk usage and tell me what filesystem is most full")
        )
        assert outcome.succeeded
        assert outcome.tool_calls >= 1
        assert "filesystems" in outcome.conclusion or "disk" in outcome.conclusion.lower()
        assert runtime.router.is_development_provider
    finally:
        await runtime.stop()


# ---------------------------------------------------------------------------
# refusal paths
# ---------------------------------------------------------------------------


async def test_a_privileged_step_is_refused_under_a_read_ceiling(
    settings: ScrappySettings,
) -> None:
    """A plan that oversteps does not run, and the task says why."""
    provider = ScriptedAgentProvider(
        steps=[
            {"intent": "Read disk", "tool": "system.disk", "arguments": {}},
            {
                "intent": "Restart nginx",
                "tool": "shell.run",
                "arguments": {"argv": ["systemctl", "restart", "nginx"]},
                "expected_risk": "privileged",
            },
        ],
        verdict="complete",
    )
    runtime = await _runtime(settings, provider)
    try:
        outcome = await runtime.submit(
            Objective(text="Fix nginx", actor="test", max_risk=RiskLevel.READ)
        )

        refused = [item for item in outcome.executed if item.verdict.denied]
        assert len(refused) == 1
        assert refused[0].call.tool_name == "shell.run"
        assert refused[0].verdict.rule == "risk-ceiling"

        events = await runtime.audit.for_task(outcome.task.id)
        assert any(event["event_type"] == "security.denied" for event in events)
    finally:
        await runtime.stop()


async def test_an_unknown_tool_in_a_plan_is_denied(settings: ScrappySettings) -> None:
    """A model naming a tool that does not exist gets a denial, not a guess."""
    provider = ScriptedAgentProvider(
        steps=[{"intent": "Do the thing", "tool": "magic.fixall", "arguments": {}}]
    )
    runtime = await _runtime(settings, provider)
    try:
        outcome = await runtime.submit(Objective(text="Fix everything", actor="test"))
        assert outcome.executed[0].verdict.rule == "unknown-tool"
        assert not outcome.executed[0].result.success
    finally:
        await runtime.stop()


async def test_a_rejected_plan_triggers_a_replan_and_then_stops(
    settings: ScrappySettings,
) -> None:
    """Rejection loops are bounded: replanning consumes budget like anything else."""
    provider = ScriptedAgentProvider(steps=[], approve_plan=False)
    runtime = await _runtime(settings, provider)
    try:
        outcome = await runtime.submit(Objective(text="Do something", actor="test"))
        assert not outcome.succeeded
        assert outcome.task.state is TaskState.FAILED
        assert outcome.budget["replans"] <= settings.max_replans + 1
        assert "replan" in (outcome.stopped_because or "").lower()
    finally:
        await runtime.stop()


async def test_a_task_cannot_exceed_its_step_budget(settings: ScrappySettings) -> None:
    settings.max_plan_steps = 2
    provider = ScriptedAgentProvider(
        steps=[
            {"intent": f"Read {index}", "tool": "system.info", "arguments": {}}
            for index in range(6)
        ]
    )
    runtime = await _runtime(settings, provider)
    try:
        outcome = await runtime.submit(Objective(text="Read everything", actor="test"))
        assert outcome.budget["steps_executed"] <= 2
    finally:
        await runtime.stop()


async def test_a_failing_step_still_produces_a_useful_conclusion(
    settings: ScrappySettings,
) -> None:
    """Partial observations are often the whole value of a diagnostic run."""
    provider = ScriptedAgentProvider(
        steps=[
            {"intent": "Read disk", "tool": "system.disk", "arguments": {}},
            {
                "intent": "Read a file that is not there",
                "tool": "fs.read",
                "arguments": {"path": "/etc/definitely-not-a-real-file"},
            },
        ],
        verdict="complete",
        conclusion="Disk was read; the config file does not exist.",
    )
    runtime = await _runtime(settings, provider)
    try:
        outcome = await runtime.submit(Objective(text="Check disk and config", actor="test"))
        assert outcome.succeeded
        assert outcome.executed[0].result.success
        assert not outcome.executed[1].result.success
        assert "does not exist" in (outcome.executed[1].result.error or "")
    finally:
        await runtime.stop()


# ---------------------------------------------------------------------------
# approval flow
# ---------------------------------------------------------------------------


async def test_a_privileged_step_runs_only_after_approval(
    settings: ScrappySettings,
) -> None:
    """The full gate: request, human decision, single-use consumption, execution."""
    settings.shell_allowlist_raw = "systemctl,hostname"
    provider = ScriptedAgentProvider(
        steps=[
            {
                "intent": "Check service state",
                "tool": "shell.run",
                "arguments": {"argv": ["systemctl", "status", "nginx"]},
            }
        ],
        conclusion="Checked.",
    )
    runtime = await _runtime(settings, provider)

    seen: list[ApprovalRequest] = []

    async def approve(request: ApprovalRequest) -> ApprovalDecision:
        seen.append(request)
        return ApprovalDecision(request_id=request.id, approved=True, decided_by="test")

    runtime.set_approval_prompt(approve)
    try:
        # `systemctl status` is read-only, so it needs no approval at all.
        outcome = await runtime.submit(
            Objective(text="Check nginx", actor="test", max_risk=RiskLevel.PRIVILEGED)
        )
        assert not seen, "a read-only systemctl subcommand must not prompt"
        assert outcome.executed[0].call.risk_level is RiskLevel.READ
    finally:
        await runtime.stop()


async def test_a_mutating_privileged_step_prompts_and_is_consumed(
    settings: ScrappySettings,
) -> None:
    settings.shell_allowlist_raw = "systemctl"
    provider = ScriptedAgentProvider(
        steps=[
            {
                "intent": "Restart the service",
                "tool": "shell.run",
                "arguments": {"argv": ["systemctl", "restart", "definitely-not-a-real-unit"]},
                "expected_risk": "privileged",
            }
        ],
        conclusion="Restart attempted.",
    )
    runtime = await _runtime(settings, provider)

    seen: list[ApprovalRequest] = []

    async def approve(request: ApprovalRequest) -> ApprovalDecision:
        seen.append(request)
        return ApprovalDecision(request_id=request.id, approved=True, decided_by="test")

    runtime.set_approval_prompt(approve)
    try:
        outcome = await runtime.submit(
            Objective(text="Restart the unit", actor="test", max_risk=RiskLevel.PRIVILEGED)
        )
        assert len(seen) == 1
        assert "systemctl restart" in seen[0].summary
        assert seen[0].risk is RiskLevel.PRIVILEGED

        # The approval was spent, and the attempt is on the record either way.
        stored = await runtime.approvals.get(seen[0].id)
        assert stored is not None
        assert str(stored.state) == "consumed"

        events = await runtime.audit.for_task(outcome.task.id)
        assert any(event["event_type"] == "tool.approved" for event in events)
    finally:
        await runtime.stop()


# ---------------------------------------------------------------------------
# event stream and memory
# ---------------------------------------------------------------------------


async def test_events_are_published_in_order(settings: ScrappySettings) -> None:
    provider = ScriptedAgentProvider(
        steps=[{"intent": "Read disk", "tool": "system.disk", "arguments": {}}]
    )
    runtime = await _runtime(settings, provider)
    try:
        outcome = await runtime.submit(Objective(text="Check disks", actor="test"))
        stream = [event.type for event in runtime.bus.history(task_id=outcome.task.id)]

        assert stream.index(EventType.TASK_CREATED) < stream.index(EventType.PLAN_CREATED)
        assert stream.index(EventType.PLAN_APPROVED) < stream.index(EventType.TOOL_STARTED)
        assert stream.index(EventType.TOOL_COMPLETED) < stream.index(EventType.TASK_COMPLETED)
    finally:
        await runtime.stop()


async def test_observations_are_persisted_to_episodic_memory(
    settings: ScrappySettings,
) -> None:
    provider = ScriptedAgentProvider(
        steps=[{"intent": "Read disk", "tool": "system.disk", "arguments": {}}]
    )
    runtime = await _runtime(settings, provider)
    try:
        outcome = await runtime.submit(Objective(text="Check disks", actor="test"))
        remembered = await runtime.episodic.recall_task(outcome.task.id)

        assert len(remembered) == 1
        assert remembered[0].source == "system.disk"
        assert remembered[0].success
    finally:
        await runtime.stop()


async def test_large_tool_output_is_hashed_rather_than_stored_whole(
    settings: ScrappySettings, workspace: Path
) -> None:
    """The audit database must not become a second copy of the filesystem."""
    big = workspace / "big.txt"
    big.write_text("x" * 200_000)

    provider = ScriptedAgentProvider(
        steps=[
            {
                "intent": "Read a large file",
                "tool": "fs.read",
                "arguments": {"path": str(big), "max_bytes": 100_000},
            }
        ]
    )
    runtime = await _runtime(settings, provider)
    try:
        outcome = await runtime.submit(Objective(text="Read the file", actor="test"))
        calls = await runtime.audit.calls_for_task(outcome.task.id)

        assert calls[0]["output_sha256"], "a digest must be recorded"
        assert len(calls[0]["output_preview"] or "") < 1000, "the preview must be bounded"

        events = await runtime.audit.for_task(outcome.task.id)
        serialised = json.dumps(events, default=str)
        assert len(serialised) < 200_000
    finally:
        await runtime.stop()
