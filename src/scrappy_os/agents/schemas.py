"""The structured shapes agents are allowed to emit.

Model output becomes an action only by validating into one of these. Because
:class:`~scrappy_os.core.models.ScrappyModel` forbids extra fields, a model
that invents ``"sudo": true`` fails validation rather than having its
invention quietly ignored - and a failed validation is visible, not silent.

Nothing here grants authority. A validated :class:`ProposedStep` is still just
a request; the policy engine decides whether it runs.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field, field_validator

from scrappy_os.core.enums import RiskLevel
from scrappy_os.core.models import ScrappyModel

Decision = Literal["continue", "replan", "complete", "rollback", "abort"]


class ProposedStep(ScrappyModel):
    """One step an agent would like to take."""

    intent: str = Field(min_length=1, max_length=500, description="Why this step exists.")
    tool: str = Field(min_length=1, max_length=64, description="Registered tool name.")
    arguments: dict[str, Any] = Field(default_factory=dict)
    expected_risk: RiskLevel = RiskLevel.READ
    expected_side_effects: list[str] = Field(default_factory=list, max_length=20)
    success_criteria: str | None = Field(default=None, max_length=500)
    rollback_hint: str | None = Field(default=None, max_length=500)

    @field_validator("tool")
    @classmethod
    def _clean_tool_name(cls, value: str) -> str:
        """Reject anything that is not a plain tool identifier.

        A model that emits ``fs.read; rm -rf /`` gets a validation error here
        rather than a lookup miss three layers down.
        """
        cleaned = value.strip()
        if not cleaned.replace(".", "").replace("_", "").isalnum():
            raise ValueError(f"tool name {value!r} contains illegal characters")
        return cleaned


class PlanProposal(ScrappyModel):
    """Brahma's output: a candidate plan plus its predicted consequences."""

    reasoning: str = Field(default="", max_length=4000)
    steps: list[ProposedStep] = Field(default_factory=list, max_length=50)
    required_capabilities: list[str] = Field(default_factory=list, max_length=20)
    predicted_side_effects: list[str] = Field(default_factory=list, max_length=20)


class ReviewedPlan(ScrappyModel):
    """Vishnu's verdict on a proposed plan, with its own corrected step list."""

    approved: bool
    reasoning: str = Field(default="", max_length=4000)
    concerns: list[str] = Field(default_factory=list, max_length=20)
    steps: list[ProposedStep] = Field(
        default_factory=list,
        max_length=50,
        description="The plan Vishnu is willing to run - may drop or reorder Brahma's steps.",
    )


class Verification(ScrappyModel):
    """Vishnu's judgement after observing results."""

    objective_satisfied: bool
    decision: Decision
    confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 0.5
    reasoning: str = Field(default="", max_length=4000)
    conclusion: str = Field(
        default="",
        max_length=8000,
        description="The answer a human reads. Written from observations, not assumptions.",
    )
    concerns: list[str] = Field(default_factory=list, max_length=20)


class RecoveryPlan(ScrappyModel):
    """Mahesh's output: how to get back to a safe state, or why we cannot."""

    diagnosis: str = Field(default="", max_length=4000)
    recoverable: bool = True
    reasoning: str = Field(default="", max_length=4000)
    steps: list[ProposedStep] = Field(default_factory=list, max_length=20)


__all__ = [
    "Decision",
    "PlanProposal",
    "ProposedStep",
    "RecoveryPlan",
    "ReviewedPlan",
    "Verification",
]
