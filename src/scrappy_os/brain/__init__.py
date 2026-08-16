"""The brain: orchestration and execution budgets.

The orchestrator owns the loop; the budget owns termination. Agents live in
:mod:`scrappy_os.agents`, providers in :mod:`scrappy_os.models`.
"""

from __future__ import annotations

from scrappy_os.brain.limits import TaskBudget
from scrappy_os.brain.orchestrator import Orchestrator, TaskOutcome

__all__ = ["Orchestrator", "TaskBudget", "TaskOutcome"]
