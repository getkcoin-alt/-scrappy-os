"""The orchestration loop.

::

    OBJECTIVE -> LOAD CONTEXT -> BRAHMA PLAN -> VISHNU REVIEW -> POLICY
      -> EXECUTE STEP -> OBSERVE -> VISHNU VERIFY
      -> {next step | replan | rollback | complete} -> MEMORY

The orchestrator owns every action. Agents return typed data; the executor
performs; the policy engine decides. Keeping those three separate is what makes
the security properties hold - there is no arrangement of model output that
reaches a syscall without passing the executor, and the executor always asks
policy first.

Termination is guaranteed by :class:`~scrappy_os.brain.limits.TaskBudget`:
every loop back-edge (next step, replan, rollback) consumes budget, and when
budget runs out the task ends with a reported reason instead of continuing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from scrappy_os.agents.brahma import Brahma
from scrappy_os.agents.mahesh import Mahesh
from scrappy_os.agents.schemas import Verification
from scrappy_os.agents.vishnu import Vishnu
from scrappy_os.brain.limits import TaskBudget
from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.enums import AgentRole, EventType, RiskLevel, TaskState
from scrappy_os.core.errors import LimitExceeded, ProviderError, ScrappyError
from scrappy_os.core.events import EventBus, emit
from scrappy_os.core.models import (
    AgentDecision,
    Objective,
    Observation,
    Plan,
    PlanStep,
    Task,
    ToolCall,
)
from scrappy_os.memory.episodic import SQLiteEpisodicMemory
from scrappy_os.memory.working import WorkingMemory
from scrappy_os.models.registry import ModelRouter
from scrappy_os.observability.logging import bind_task, get_logger
from scrappy_os.tools.base import ToolRegistry
from scrappy_os.tools.executor import ExecutionOutcome, ToolExecutor

logger = get_logger("orchestrator")


@dataclass(slots=True)
class TaskOutcome:
    """Everything a caller needs to report what happened."""

    task: Task
    conclusion: str
    succeeded: bool
    plans: list[Plan] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    decisions: list[AgentDecision] = field(default_factory=list)
    executed: list[ExecutionOutcome] = field(default_factory=list)
    budget: dict[str, float | int] = field(default_factory=dict)
    stopped_because: str | None = None

    @property
    def tool_calls(self) -> int:
        return len(self.executed)

    @property
    def refused(self) -> list[ExecutionOutcome]:
        """Steps policy or an operator declined. Worth surfacing to the user."""
        return [outcome for outcome in self.executed if outcome.verdict.denied]


class Orchestrator:
    """Drives one objective from statement to conclusion."""

    def __init__(
        self,
        *,
        settings: ScrappySettings,
        router: ModelRouter,
        registry: ToolRegistry,
        executor: ToolExecutor,
        bus: EventBus,
        episodic: SQLiteEpisodicMemory | None = None,
    ) -> None:
        self._settings = settings
        self._router = router
        self._registry = registry
        self._executor = executor
        self._bus = bus
        self._episodic = episodic

        self.brahma = Brahma(router.for_role(AgentRole.BRAHMA), registry)
        self.vishnu = Vishnu(router.for_role(AgentRole.VISHNU), registry)
        self.mahesh = Mahesh(router.for_role(AgentRole.MAHESH), registry)

    async def run(self, objective: Objective, *, task_id: str | None = None) -> TaskOutcome:
        """Execute one objective end to end. Never raises for an expected failure.

        ``task_id`` lets a caller allocate the id up front - the API needs it to
        subscribe to a task's event stream before the task has started emitting.
        """
        task = (
            Task(objective=objective) if task_id is None else Task(id=task_id, objective=objective)
        )
        memory = WorkingMemory(task_id=task.id, objective=objective.text)
        budget = TaskBudget.from_settings(self._settings)
        outcome = TaskOutcome(task=task, conclusion="", succeeded=False)

        with bind_task(task.id, objective=objective.text[:120]):
            await emit(
                self._bus,
                EventType.TASK_CREATED,
                task_id=task.id,
                component="orchestrator",
                # The principal that submitted this objective, carried onto every
                # event of the run so the trail can be filtered by who asked.
                identity=objective.identity,
                objective=objective.text,
                actor=objective.actor,
                max_risk=str(objective.max_risk),
                dry_run=objective.dry_run,
            )
            logger.info(
                "task_created",
                task_id=task.id,
                max_risk=str(objective.max_risk),
                provider=self._router.provider.info.name,
            )
            try:
                await self._drive(task, memory, budget, outcome)
            except LimitExceeded as exc:
                outcome.stopped_because = exc.message
                await self._fail(task, memory, outcome, exc.message, budget)
            except ProviderError as exc:
                outcome.stopped_because = exc.message
                await self._fail(
                    task, memory, outcome, f"model provider failed: {exc.message}", budget
                )
            except ScrappyError as exc:
                outcome.stopped_because = exc.message
                await self._fail(task, memory, outcome, exc.message, budget)

        outcome.budget = budget.snapshot()
        outcome.observations = list(memory.observations)
        outcome.plans = list(memory.plans)
        return outcome

    # -- the loop -----------------------------------------------------------

    async def _drive(
        self,
        task: Task,
        memory: WorkingMemory,
        budget: TaskBudget,
        outcome: TaskOutcome,
    ) -> None:
        feedback: str | None = None

        while True:
            budget.check_time()
            budget.check_model_calls()

            # --- BRAHMA PLAN ---
            task.transition_to(TaskState.PLANNING)
            remaining_steps = max(1, budget.max_plan_steps - budget.steps_executed)
            plan, brahma_decision = await self.brahma.plan(
                task, memory, max_steps=remaining_steps, feedback=feedback
            )
            budget.record_model_call()
            outcome.decisions.append(brahma_decision)
            await self._publish_decision(brahma_decision, task)
            await emit(
                self._bus,
                EventType.PLAN_CREATED,
                task_id=task.id,
                component="brahma",
                identity=task.objective.identity,
                plan_id=plan.id,
                steps=len(plan.steps),
                revision=plan.revision,
                max_risk=str(plan.max_risk),
            )

            # --- VISHNU REVIEW ---
            reviewed, review_decision = await self.vishnu.review(task, plan, memory)
            budget.record_model_call()
            outcome.decisions.append(review_decision)
            await self._publish_decision(review_decision, task)
            memory.add_plan(reviewed)
            task.plan_id = reviewed.id

            if not reviewed.approved or not reviewed.steps:
                await emit(
                    self._bus,
                    EventType.PLAN_REJECTED,
                    task_id=task.id,
                    component="vishnu",
                    identity=task.objective.identity,
                    plan_id=reviewed.id,
                    reason=reviewed.review_notes or "no acceptable steps",
                )
                budget.check_replans()
                budget.record_replan()
                task.replan_count += 1
                feedback = f"Vishnu rejected the plan: {reviewed.review_notes or 'no reason given'}"
                continue

            await emit(
                self._bus,
                EventType.PLAN_APPROVED,
                task_id=task.id,
                component="vishnu",
                identity=task.objective.identity,
                plan_id=reviewed.id,
                steps=len(reviewed.steps),
            )

            # --- EXECUTE + OBSERVE ---
            task.transition_to(TaskState.EXECUTING)
            executed_steps: list[PlanStep] = []
            step_failure: str | None = None

            for step in reviewed.steps:
                try:
                    budget.check_all()
                except LimitExceeded as exc:
                    step_failure = exc.message
                    outcome.stopped_because = exc.message
                    break

                result = await self._execute_step(task, step, memory, outcome)
                executed_steps.append(step)
                budget.record_step(success=result.result.success)

                if not result.result.success and result.verdict.denied:
                    # A refusal is information, not a crash: the loop continues so
                    # the task can still report what it did learn.
                    step_failure = result.result.error
                    break
                if not result.result.success:
                    step_failure = result.result.error

            # --- VISHNU VERIFY ---
            task.transition_to(TaskState.VERIFYING)
            verification, verify_decision = await self.vishnu.verify(task, memory)
            budget.record_model_call()
            outcome.decisions.append(verify_decision)
            await self._publish_decision(verify_decision, task)

            decided = verification.decision
            if decided == "complete":
                await self._complete(task, memory, outcome, verification, budget)
                return
            if decided == "abort":
                await self._fail(
                    task,
                    memory,
                    outcome,
                    verification.conclusion or "aborted by verification",
                    budget,
                )
                return
            if decided == "rollback":
                await self._rollback(
                    task,
                    memory,
                    outcome,
                    budget,
                    reason=step_failure or verification.reasoning,
                    executed_steps=executed_steps,
                )
                return

            # continue / replan both mean another cycle - and both cost budget.
            budget.check_replans()
            budget.record_replan()
            task.replan_count += 1
            feedback = f"Verification returned '{decided}': {verification.reasoning}" + (
                f" Last failure: {step_failure}" if step_failure else ""
            )

    # -- step execution -----------------------------------------------------

    async def _execute_step(
        self, task: Task, step: PlanStep, memory: WorkingMemory, outcome: TaskOutcome
    ) -> ExecutionOutcome:
        call = ToolCall(
            task_id=task.id,
            step_id=step.id,
            tool_name=step.tool_name,
            arguments=step.arguments,
            actor=f"agent:{self.brahma.role}",
            # The agent proposed this step; the principal below is accountable
            # for it. Both are recorded - see scrappy_os.core.identity.
            identity=task.objective.identity,
            risk_level=step.expected_risk,
        )
        execution = await self._executor.execute(
            call,
            max_risk=task.objective.max_risk,
            dry_run=task.objective.dry_run,
        )
        outcome.executed.append(execution)

        observation = memory.note_result(execution.result, source=step.tool_name)
        if self._episodic is not None:
            await self._episodic.remember(observation)
        return execution

    # -- terminal transitions ----------------------------------------------

    async def _complete(
        self,
        task: Task,
        memory: WorkingMemory,
        outcome: TaskOutcome,
        verification: Verification,
        budget: TaskBudget,
    ) -> None:
        task.summary = verification.conclusion or verification.reasoning
        task.transition_to(TaskState.COMPLETED)
        outcome.conclusion = task.summary
        outcome.succeeded = True
        await emit(
            self._bus,
            EventType.TASK_COMPLETED,
            task_id=task.id,
            component="orchestrator",
            identity=task.objective.identity,
            success=True,
            duration_ms=round(task.duration_seconds * 1000, 1),
            steps_executed=budget.steps_executed,
            confidence=verification.confidence,
        )
        logger.info(
            "task_completed",
            task_id=task.id,
            steps=budget.steps_executed,
            duration_s=round(task.duration_seconds, 2),
            outcome="success",
        )

    async def _fail(
        self,
        task: Task,
        memory: WorkingMemory,
        outcome: TaskOutcome,
        reason: str,
        budget: TaskBudget,
    ) -> None:
        task.error = reason
        task.summary = _failure_summary(task, memory, reason)
        if not task.state.is_terminal:
            task.transition_to(TaskState.FAILED)
        outcome.conclusion = task.summary
        outcome.succeeded = False
        await emit(
            self._bus,
            EventType.TASK_FAILED,
            task_id=task.id,
            component="orchestrator",
            identity=task.objective.identity,
            success=False,
            error=reason,
            steps_executed=budget.steps_executed,
        )
        logger.warning("task_failed", task_id=task.id, error=reason, outcome="failure")

    async def _rollback(
        self,
        task: Task,
        memory: WorkingMemory,
        outcome: TaskOutcome,
        budget: TaskBudget,
        *,
        reason: str,
        executed_steps: list[PlanStep],
    ) -> None:
        """Hand a failed task to Mahesh.

        Recovery steps go through the *same* executor with the *same* risk
        ceiling. Being in a recovery path grants no additional authority.
        """
        task.transition_to(TaskState.ROLLING_BACK)
        await emit(
            self._bus,
            EventType.ROLLBACK_STARTED,
            task_id=task.id,
            component="mahesh",
            identity=task.objective.identity,
            reason=reason,
        )

        recovery_plan, recovery, decision = await self.mahesh.recover(
            task, memory, failure_reason=reason, executed_steps=executed_steps
        )
        budget.record_model_call()
        outcome.decisions.append(decision)
        await self._publish_decision(decision, task)

        recovered_steps = 0
        for step in recovery_plan.steps:
            try:
                budget.check_time()
                budget.check_steps()
            except LimitExceeded:
                break
            execution = await self._execute_step(task, step, memory, outcome)
            budget.record_step(success=execution.result.success)
            if execution.result.success:
                recovered_steps += 1

        await emit(
            self._bus,
            EventType.ROLLBACK_COMPLETED,
            task_id=task.id,
            component="mahesh",
            identity=task.objective.identity,
            recoverable=recovery.recoverable,
            steps_attempted=len(recovery_plan.steps),
            steps_succeeded=recovered_steps,
        )

        summary = (
            f"{recovery.diagnosis}\n\n"
            f"Recovery: {recovered_steps} of {len(recovery_plan.steps)} steps completed."
            if recovery_plan.steps
            else recovery.diagnosis
        )
        task.error = reason
        task.summary = summary
        task.transition_to(TaskState.FAILED)
        outcome.conclusion = summary
        outcome.succeeded = False
        await emit(
            self._bus,
            EventType.TASK_FAILED,
            task_id=task.id,
            component="orchestrator",
            identity=task.objective.identity,
            success=False,
            error=reason,
            rolled_back=True,
        )

    async def _publish_decision(self, decision: AgentDecision, task: Task) -> None:
        """Publish one reasoning turn.

        Takes the task purely to attribute the event. A reasoning turn is still
        somebody's reasoning turn - it happened inside a principal's task, and an
        `agent.decided` row with a null actor would be the one hole in a filter
        over everything that principal caused.
        """
        await emit(
            self._bus,
            EventType.AGENT_DECIDED,
            task_id=decision.task_id,
            component=str(decision.role),
            identity=task.objective.identity,
            decision=decision.decision,
            confidence=decision.confidence,
            reasoning=decision.reasoning[:1000],
            concerns=decision.concerns,
            duration_ms=round(decision.duration_ms, 1),
        )


def _failure_summary(task: Task, memory: WorkingMemory, reason: str) -> str:
    """A useful message even when the task did not finish.

    Partial observations are frequently the whole value of a diagnostic run, so
    a failed task reports what it did learn rather than only that it failed.
    """
    lines = [f"Task did not complete: {reason}"]
    if memory.has_observations:
        lines.append("")
        lines.append(f"{len(memory.observations)} observation(s) were collected before stopping:")
        for observation in list(memory.observations)[-3:]:
            status = "ok" if observation.success else "failed"
            lines.append(f"- {observation.source} ({status}): {observation.content[:300]}")
    return "\n".join(lines)


def default_max_risk(settings: ScrappySettings) -> RiskLevel:
    """The risk ceiling applied when a caller does not choose one."""
    return settings.default_max_risk


__all__ = ["Orchestrator", "TaskOutcome", "default_max_risk"]
