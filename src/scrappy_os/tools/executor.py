"""The tool executor: the one place a tool can actually run.

Every invocation, whoever asked for it, follows exactly this sequence:

1. Resolve the tool. Unknown name -> deny, audit, stop.
2. Validate arguments against the typed schema. Invalid -> fail, audit, stop.
3. Classify risk from the arguments, taking the worse of static and dynamic.
4. Evaluate policy. Deny -> audit as a security event, stop.
5. If approval is required, open a request and wait for a human.
6. Consume the approval (single use) and execute under a timeout.
7. Record the result, publish events, return a typed :class:`ToolResult`.

Agents never call ``tool.run`` directly - they hand a :class:`ToolCall` to this
class. That is what makes "every machine-changing action passes through the
policy engine" a structural property rather than a convention.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.enums import ApprovalState, EventType, PolicyDecision, RiskLevel
from scrappy_os.core.errors import (
    ApprovalExpired,
    ScrappyError,
    ToolError,
    ToolNotFound,
    ToolTimeout,
    ValidationFailed,
)
from scrappy_os.core.events import EventBus, emit
from scrappy_os.core.models import ApprovalDecision, ApprovalRequest, ToolCall, ToolResult, utc_now
from scrappy_os.observability.logging import get_logger
from scrappy_os.security.approvals import ApprovalManager
from scrappy_os.security.audit import AuditLog
from scrappy_os.security.policy import PolicyContext, PolicyEngine, PolicyVerdict
from scrappy_os.tools.base import ToolContext, ToolRegistry

logger = get_logger("executor")

#: Called with an approval request; returns the human's decision.
ApprovalPrompt = Callable[[ApprovalRequest], Awaitable[ApprovalDecision]]


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    """A tool call's full story: what was decided and what happened."""

    call: ToolCall
    result: ToolResult
    verdict: PolicyVerdict
    approval: ApprovalRequest | None = None

    @property
    def executed(self) -> bool:
        """Whether the tool actually ran, as opposed to being refused."""
        return self.result.success or (
            self.result.error is not None and self.result.duration_ms > 0
        )

    @property
    def refused(self) -> bool:
        return self.verdict.denied or (
            self.call.approval_state
            in {ApprovalState.DENIED, ApprovalState.EXPIRED, ApprovalState.PENDING}
        )


class ToolExecutor:
    """Runs tool calls under policy, approval, timeout and audit."""

    def __init__(
        self,
        *,
        settings: ScrappySettings,
        registry: ToolRegistry,
        policy: PolicyEngine,
        approvals: ApprovalManager,
        audit: AuditLog,
        bus: EventBus,
        approval_prompt: ApprovalPrompt | None = None,
    ) -> None:
        self._settings = settings
        self._registry = registry
        self._policy = policy
        self._approvals = approvals
        self._audit = audit
        self._bus = bus
        self._approval_prompt = approval_prompt

    def set_approval_prompt(self, prompt: ApprovalPrompt | None) -> None:
        """Install the interactive prompt. The CLI sets one; the API does not.

        Without a prompt, an operation needing approval is refused rather than
        blocking forever - the approval still exists and can be resolved out of
        band through ``scrappy approve`` or ``POST /approvals/{id}``.
        """
        self._approval_prompt = prompt

    async def execute(
        self,
        call: ToolCall,
        *,
        max_risk: RiskLevel = RiskLevel.READ,
        dry_run: bool = False,
        timeout: float | None = None,
    ) -> ExecutionOutcome:
        """Run one tool call end to end. Never raises for an expected refusal."""
        started_at = utc_now()
        ctx = ToolContext(
            settings=self._settings,
            task_id=call.task_id,
            actor=call.actor,
            identity=call.identity,
            call_id=call.id,
        )

        # 1. Resolve.
        try:
            tool = self._registry.get(call.tool_name)
        except ToolNotFound as exc:
            return await self._refuse(
                call,
                PolicyVerdict(
                    PolicyDecision.DENY,
                    RiskLevel.DESTRUCTIVE,
                    rule="unknown-tool",
                    reason=exc.message,
                ),
                started_at,
            )

        # 2. Validate.
        try:
            args = tool.parse_arguments(call.arguments)
        except ValidationFailed as exc:
            call.risk_level = tool.risk
            await self._audit.record_call(call)
            result = self._failure(call, exc.message, started_at, 0.0)
            await self._finish_failure(call, result, exc.message)
            return ExecutionOutcome(
                call=call,
                result=result,
                verdict=PolicyVerdict(
                    PolicyDecision.DENY, tool.risk, rule="invalid-arguments", reason=exc.message
                ),
            )

        # 3. Classify. The worse of static ceiling and argument-aware risk wins.
        try:
            dynamic_risk, reason = tool.classify(args, ctx)
        except ScrappyError as exc:
            dynamic_risk, reason = tool.risk, f"classification failed: {exc.message}"
        effective_risk = RiskLevel.max(dynamic_risk, RiskLevel.READ)
        if dynamic_risk.rank > tool.risk.rank:
            # A tool declaring a lower ceiling than its arguments justify is a
            # bug in that tool. Trust the arguments and say so.
            logger.warning(
                "risk_exceeds_declared_ceiling",
                tool=tool.name,
                declared=str(tool.risk),
                classified=str(dynamic_risk),
            )
        call.risk_level = effective_risk

        paths: list[Path] = [Path(path) for path in tool.affected_paths(args)]

        # 4. Policy.
        verdict = self._policy.evaluate(
            call,
            risk=effective_risk,
            context=PolicyContext(
                max_risk=max_risk,
                dry_run=dry_run,
                known_tools=self._registry.names,
                disabled_tools=self._registry.disabled,
                paths=paths,
                actor=call.identity,
            ),
            reason=reason,
        )
        call.policy_decision = verdict.decision
        call.policy_rule = verdict.rule
        await self._audit.record_call(call)

        await emit(
            self._bus,
            EventType.TOOL_REQUESTED,
            task_id=call.task_id,
            component="executor",
            call_id=call.id,
            tool_name=call.tool_name,
            risk=str(effective_risk),
            decision=str(verdict.decision),
            rule=verdict.rule,
        )

        if verdict.denied:
            return await self._refuse(call, verdict, started_at)

        # 5. Approval.
        approval: ApprovalRequest | None = None
        if verdict.needs_approval:
            approval = await self._approvals.request(
                call,
                risk=effective_risk,
                reason=verdict.reason,
                requires_confirmation_phrase=verdict.requires_confirmation_phrase,
            )
            call.approval_id = approval.id
            call.approval_state = ApprovalState.PENDING

            if self._approval_prompt is None:
                message = (
                    f"Approval {approval.id} is required for {call.tool_name} "
                    f"({effective_risk}) and no interactive approver is attached. "
                    "Resolve it with `scrappy approve` or POST /approvals/{id}."
                )
                result = self._failure(call, message, started_at, 0.0)
                await self._finish_failure(call, result, message)
                return ExecutionOutcome(
                    call=call, result=result, verdict=verdict, approval=approval
                )

            decision = await self._approval_prompt(approval)
            try:
                approval = await self._approvals.resolve(decision)
            except (ApprovalExpired, ScrappyError) as exc:
                call.approval_state = ApprovalState.EXPIRED
                result = self._failure(call, exc.message, started_at, 0.0)
                await self._finish_failure(call, result, exc.message)
                return ExecutionOutcome(
                    call=call, result=result, verdict=verdict, approval=approval
                )

            if not decision.approved:
                call.approval_state = ApprovalState.DENIED
                message = (
                    f"Operator declined {call.tool_name}: {decision.note or 'no reason given'}"
                )
                result = self._failure(call, message, started_at, 0.0)
                await self._finish_failure(call, result, message)
                await emit(
                    self._bus,
                    EventType.SECURITY_DENIED,
                    task_id=call.task_id,
                    component="approvals",
                    tool_name=call.tool_name,
                    risk=str(effective_risk),
                    decision=str(PolicyDecision.DENY),
                    reason="declined by operator",
                )
                return ExecutionOutcome(
                    call=call, result=result, verdict=verdict, approval=approval
                )

            # 6. Spend the approval. Single use, enforced by the manager.
            try:
                await self._approvals.consume(approval.id)
            except ScrappyError as exc:
                result = self._failure(call, exc.message, started_at, 0.0)
                await self._finish_failure(call, result, exc.message)
                return ExecutionOutcome(
                    call=call, result=result, verdict=verdict, approval=approval
                )

            call.approval_state = ApprovalState.CONSUMED
            await emit(
                self._bus,
                EventType.TOOL_APPROVED,
                task_id=call.task_id,
                component="executor",
                call_id=call.id,
                tool_name=call.tool_name,
                approval_id=approval.id,
                risk=str(effective_risk),
            )

        # 7. Execute.
        await emit(
            self._bus,
            EventType.TOOL_STARTED,
            task_id=call.task_id,
            component="executor",
            call_id=call.id,
            tool_name=call.tool_name,
            risk=str(effective_risk),
        )

        budget = timeout or self._settings.max_task_seconds
        started = time.perf_counter()
        try:
            output = await asyncio.wait_for(tool.run(args, ctx), timeout=budget)
        except TimeoutError:
            duration_ms = (time.perf_counter() - started) * 1000
            message = f"{call.tool_name} exceeded its {budget}s budget"
            result = self._failure(call, message, started_at, duration_ms)
            await self._finish_failure(call, result, message)
            return ExecutionOutcome(call=call, result=result, verdict=verdict, approval=approval)
        except (ToolTimeout, ToolError, ScrappyError) as exc:
            duration_ms = (time.perf_counter() - started) * 1000
            result = self._failure(call, exc.message, started_at, duration_ms)
            await self._finish_failure(call, result, exc.message)
            return ExecutionOutcome(call=call, result=result, verdict=verdict, approval=approval)
        except Exception as exc:
            # A bug in one tool must not take down the runtime. The traceback is
            # logged in full and the failure is audited - it is contained, not hidden.
            duration_ms = (time.perf_counter() - started) * 1000
            message = f"{type(exc).__name__}: {exc}"
            logger.exception("tool_crashed", tool=call.tool_name, task_id=call.task_id)
            result = self._failure(call, message, started_at, duration_ms)
            await self._finish_failure(call, result, message)
            return ExecutionOutcome(call=call, result=result, verdict=verdict, approval=approval)

        duration_ms = (time.perf_counter() - started) * 1000
        result = ToolResult(
            call_id=call.id,
            task_id=call.task_id,
            tool_name=call.tool_name,
            success=True,
            started_at=started_at,
            duration_ms=duration_ms,
            output=output,
            truncated=bool(output.get("truncated")) if isinstance(output, dict) else False,
            exit_code=output.get("exit_code") if isinstance(output, dict) else None,
        )
        await self._audit.record_result(result)
        await emit(
            self._bus,
            EventType.TOOL_COMPLETED,
            task_id=call.task_id,
            component="executor",
            call_id=call.id,
            tool_name=call.tool_name,
            risk=str(effective_risk),
            success=True,
            duration_ms=round(duration_ms, 1),
        )
        logger.info(
            "tool_completed",
            tool=call.tool_name,
            task_id=call.task_id,
            risk=str(effective_risk),
            duration_ms=round(duration_ms, 1),
            outcome="success",
        )
        return ExecutionOutcome(call=call, result=result, verdict=verdict, approval=approval)

    # -- helpers ------------------------------------------------------------

    async def _refuse(
        self, call: ToolCall, verdict: PolicyVerdict, started_at: object
    ) -> ExecutionOutcome:
        """Record and report a policy denial."""
        call.policy_decision = PolicyDecision.DENY
        call.policy_rule = verdict.rule
        call.risk_level = verdict.risk
        await self._audit.record_call(call)

        result = ToolResult(
            call_id=call.id,
            task_id=call.task_id,
            tool_name=call.tool_name,
            success=False,
            duration_ms=0.0,
            error=f"denied by policy ({verdict.rule}): {verdict.reason}",
        )
        await self._audit.record_result(result)
        await emit(
            self._bus,
            EventType.SECURITY_DENIED,
            task_id=call.task_id,
            component="policy",
            tool_name=call.tool_name,
            risk=str(verdict.risk),
            decision=str(PolicyDecision.DENY),
            rule=verdict.rule,
            reason=verdict.reason,
            success=False,
        )
        logger.warning(
            "tool_denied",
            tool=call.tool_name,
            task_id=call.task_id,
            rule=verdict.rule,
            risk=str(verdict.risk),
            outcome="denied",
        )
        return ExecutionOutcome(call=call, result=result, verdict=verdict)

    def _failure(
        self, call: ToolCall, message: str, started_at: object, duration_ms: float
    ) -> ToolResult:
        from datetime import datetime

        return ToolResult(
            call_id=call.id,
            task_id=call.task_id,
            tool_name=call.tool_name,
            success=False,
            started_at=started_at if isinstance(started_at, datetime) else utc_now(),
            duration_ms=duration_ms,
            error=message,
        )

    async def _finish_failure(self, call: ToolCall, result: ToolResult, message: str) -> None:
        await self._audit.record_result(result)
        await emit(
            self._bus,
            EventType.TOOL_FAILED,
            task_id=call.task_id,
            component="executor",
            call_id=call.id,
            tool_name=call.tool_name,
            risk=str(call.risk_level),
            success=False,
            error=message,
            duration_ms=round(result.duration_ms, 1),
        )
        logger.warning(
            "tool_failed",
            tool=call.tool_name,
            task_id=call.task_id,
            error=message,
            duration_ms=round(result.duration_ms, 1),
            outcome="failure",
        )


__all__ = ["ApprovalPrompt", "ExecutionOutcome", "ToolExecutor"]
