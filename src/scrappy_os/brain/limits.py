"""Execution budgets.

An autonomous loop without budgets is a loop that eventually costs money,
saturates a machine, or hammers an API until it is rate-limited. Every limit
here is checked *before* the expensive thing happens, and running out of budget
is an ordinary, well-reported task outcome rather than a crash.

The wall-clock budget is checked at every step rather than enforced with a
single ``asyncio.timeout`` around the whole run, so that a task which runs out
of time still has its partial observations, its audit trail and a conclusion.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.errors import LimitExceeded


@dataclass(slots=True)
class TaskBudget:
    """Mutable budget for one task run."""

    max_plan_steps: int
    max_replans: int
    max_task_seconds: float
    max_consecutive_tool_failures: int
    max_model_calls: int

    started_at: float = 0.0
    steps_executed: int = 0
    replans: int = 0
    consecutive_failures: int = 0
    model_calls: int = 0

    @classmethod
    def from_settings(cls, settings: ScrappySettings) -> TaskBudget:
        return cls(
            max_plan_steps=settings.max_plan_steps,
            max_replans=settings.max_replans,
            max_task_seconds=settings.max_task_seconds,
            max_consecutive_tool_failures=settings.max_consecutive_tool_failures,
            max_model_calls=settings.max_model_calls,
            started_at=time.monotonic(),
        )

    def start(self) -> None:
        self.started_at = time.monotonic()

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.started_at

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.max_task_seconds - self.elapsed_seconds)

    def check_time(self) -> None:
        if self.elapsed_seconds >= self.max_task_seconds:
            raise LimitExceeded(
                f"Task exceeded its {self.max_task_seconds}s budget",
                limit_name="max_task_seconds",
                limit_value=self.max_task_seconds,
            )

    def check_steps(self) -> None:
        if self.steps_executed >= self.max_plan_steps:
            raise LimitExceeded(
                f"Task reached its {self.max_plan_steps}-step limit",
                limit_name="max_plan_steps",
                limit_value=self.max_plan_steps,
            )

    def check_model_calls(self) -> None:
        if self.model_calls >= self.max_model_calls:
            raise LimitExceeded(
                f"Task reached its {self.max_model_calls}-inference limit",
                limit_name="max_model_calls",
                limit_value=self.max_model_calls,
            )

    def check_failures(self) -> None:
        if self.consecutive_failures >= self.max_consecutive_tool_failures:
            raise LimitExceeded(
                f"{self.consecutive_failures} consecutive tool failures; stopping",
                limit_name="max_consecutive_tool_failures",
                limit_value=self.max_consecutive_tool_failures,
            )

    def check_replans(self) -> None:
        if self.replans >= self.max_replans:
            raise LimitExceeded(
                f"Task reached its {self.max_replans}-replan limit",
                limit_name="max_replans",
                limit_value=self.max_replans,
            )

    def check_all(self) -> None:
        """Every budget, checked before the next expensive operation."""
        self.check_time()
        self.check_steps()
        self.check_model_calls()
        self.check_failures()

    def record_step(self, *, success: bool) -> None:
        self.steps_executed += 1
        self.consecutive_failures = 0 if success else self.consecutive_failures + 1

    def record_model_call(self) -> None:
        self.model_calls += 1

    def record_replan(self) -> None:
        self.replans += 1

    def snapshot(self) -> dict[str, float | int]:
        return {
            "steps_executed": self.steps_executed,
            "max_plan_steps": self.max_plan_steps,
            "replans": self.replans,
            "max_replans": self.max_replans,
            "model_calls": self.model_calls,
            "max_model_calls": self.max_model_calls,
            "consecutive_failures": self.consecutive_failures,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "max_task_seconds": self.max_task_seconds,
        }


__all__ = ["TaskBudget"]
