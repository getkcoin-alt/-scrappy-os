"""The three reasoning roles.

Brahma proposes, Vishnu validates, Mahesh recovers. None of them can execute
anything - they return typed data to the orchestrator, which owns every action.
"""

from __future__ import annotations

from scrappy_os.agents.base import Agent, load_prompt, render_context
from scrappy_os.agents.brahma import Brahma
from scrappy_os.agents.mahesh import Mahesh
from scrappy_os.agents.schemas import (
    PlanProposal,
    ProposedStep,
    RecoveryPlan,
    ReviewedPlan,
    Verification,
)
from scrappy_os.agents.vishnu import Vishnu, render_plan

__all__ = [
    "Agent",
    "Brahma",
    "Mahesh",
    "PlanProposal",
    "ProposedStep",
    "RecoveryPlan",
    "ReviewedPlan",
    "Verification",
    "Vishnu",
    "load_prompt",
    "render_context",
    "render_plan",
]
