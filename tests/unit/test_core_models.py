"""Typed domain models: identity, state transitions and validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from scrappy_os.core.enums import RiskLevel, TaskState
from scrappy_os.core.errors import InvalidStateTransition
from scrappy_os.core.models import (
    Objective,
    Plan,
    PlanStep,
    Task,
    ToolResult,
    can_transition,
)

# ---------------------------------------------------------------------------
# identity
# ---------------------------------------------------------------------------


def test_every_task_gets_a_unique_uuid() -> None:
    import uuid

    tasks = [Task(objective=Objective(text=f"objective {index}")) for index in range(50)]
    ids = {task.id for task in tasks}
    assert len(ids) == 50
    for value in ids:
        uuid.UUID(value)  # raises if malformed


def test_timestamps_are_timezone_aware() -> None:
    """Naive datetimes are a bug: audit rows are compared across processes."""
    task = Task(objective=Objective(text="x"))
    assert task.created_at.tzinfo is not None


# ---------------------------------------------------------------------------
# state machine
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "target"),
    [
        (TaskState.CREATED, TaskState.PLANNING),
        (TaskState.PLANNING, TaskState.EXECUTING),
        (TaskState.EXECUTING, TaskState.VERIFYING),
        (TaskState.VERIFYING, TaskState.COMPLETED),
        (TaskState.EXECUTING, TaskState.ROLLING_BACK),
        (TaskState.AWAITING_APPROVAL, TaskState.EXECUTING),
    ],
)
def test_legal_transitions_are_permitted(source: TaskState, target: TaskState) -> None:
    assert can_transition(source, target)


@pytest.mark.parametrize(
    ("source", "target"),
    [
        (TaskState.CREATED, TaskState.COMPLETED),  # cannot finish without doing anything
        (TaskState.COMPLETED, TaskState.EXECUTING),  # terminal means terminal
        (TaskState.FAILED, TaskState.COMPLETED),
        (TaskState.CANCELLED, TaskState.PLANNING),
        (TaskState.PLANNING, TaskState.VERIFYING),  # nothing has run to verify
    ],
)
def test_illegal_transitions_are_refused(source: TaskState, target: TaskState) -> None:
    assert not can_transition(source, target)


def test_illegal_transition_raises_with_context() -> None:
    task = Task(objective=Objective(text="x"))
    with pytest.raises(InvalidStateTransition) as excinfo:
        task.transition_to(TaskState.COMPLETED)
    assert excinfo.value.context["current"] == "created"
    assert excinfo.value.context["target"] == "completed"


def test_transition_to_the_same_state_is_a_no_op() -> None:
    task = Task(objective=Objective(text="x"))
    assert task.transition_to(TaskState.CREATED).state is TaskState.CREATED


def test_terminal_states_record_a_finish_time() -> None:
    task = Task(objective=Objective(text="x"))
    task.transition_to(TaskState.PLANNING).transition_to(TaskState.FAILED)
    assert task.finished_at is not None
    assert task.state.is_terminal


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------


def test_blank_objectives_are_refused() -> None:
    for text in ("", "   ", "\n\t"):
        with pytest.raises(ValidationError):
            Objective(text=text)


def test_objective_text_is_stripped() -> None:
    assert Objective(text="  check disk  ").text == "check disk"


def test_unknown_fields_are_rejected() -> None:
    """Extra-field rejection is the first defence against invented arguments."""
    with pytest.raises(ValidationError):
        Objective(text="x", bypass_policy=True)  # type: ignore[call-arg]


def test_failed_tool_result_must_explain_itself() -> None:
    """A failure with no reason would be an error hidden in a data structure."""
    with pytest.raises(ValidationError, match="error message"):
        ToolResult(call_id="c", task_id="t", tool_name="fs.read", success=False)


def test_successful_tool_result_needs_no_error() -> None:
    result = ToolResult(call_id="c", task_id="t", tool_name="fs.read", success=True)
    assert result.error is None


def test_tool_result_summary_is_bounded() -> None:
    """Prompts must not be able to grow without limit from one tool's output."""
    result = ToolResult(
        call_id="c",
        task_id="t",
        tool_name="fs.read",
        success=True,
        output={"content": "x" * 100_000},
    )
    summary = result.summarise(limit=1000)
    assert len(summary) < 1100
    assert "truncated" in summary


def test_failed_tool_result_summarises_as_the_failure() -> None:
    result = ToolResult(
        call_id="c", task_id="t", tool_name="fs.read", success=False, error="no such file"
    )
    assert result.summarise() == "FAILED: no such file"


# ---------------------------------------------------------------------------
# plans
# ---------------------------------------------------------------------------


def test_plan_steps_are_reindexed_on_construction() -> None:
    """Step order is the plan's meaning; indices cannot be allowed to lie."""
    plan = Plan(
        task_id="t",
        steps=[
            PlanStep(index=99, intent="second", tool_name="system.info"),
            PlanStep(index=0, intent="first", tool_name="system.disk"),
        ],
    )
    assert [step.index for step in plan.steps] == [0, 1]
    assert plan.steps[0].intent == "second"


def test_plan_max_risk_is_the_worst_step() -> None:
    plan = Plan(
        task_id="t",
        steps=[
            PlanStep(index=0, intent="read", tool_name="system.disk"),
            PlanStep(
                index=1,
                intent="delete",
                tool_name="fs.delete",
                expected_risk=RiskLevel.DESTRUCTIVE,
            ),
        ],
    )
    assert plan.max_risk is RiskLevel.DESTRUCTIVE


def test_empty_plan_is_read_risk() -> None:
    assert Plan(task_id="t").max_risk is RiskLevel.READ


# ---------------------------------------------------------------------------
# risk ordering
# ---------------------------------------------------------------------------


def test_risk_levels_are_ordered_by_danger() -> None:
    assert RiskLevel.DESTRUCTIVE.rank > RiskLevel.PRIVILEGED.rank
    assert RiskLevel.PRIVILEGED.rank > RiskLevel.WRITE.rank
    assert RiskLevel.WRITE.rank > RiskLevel.READ.rank


def test_risk_max_picks_the_worst() -> None:
    assert RiskLevel.max(RiskLevel.READ, RiskLevel.PRIVILEGED, RiskLevel.WRITE) is (
        RiskLevel.PRIVILEGED
    )
    assert RiskLevel.max() is RiskLevel.READ


def test_at_least_is_inclusive() -> None:
    assert RiskLevel.WRITE.at_least(RiskLevel.WRITE)
    assert RiskLevel.PRIVILEGED.at_least(RiskLevel.WRITE)
    assert not RiskLevel.READ.at_least(RiskLevel.WRITE)
