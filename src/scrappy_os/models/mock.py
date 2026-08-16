"""The deterministic development provider.

**This is not a language model.** It is a rule table that produces valid,
predictable structured output so the control plane can be developed, tested and
demonstrated without a network call, an API key or a GPU. It cannot generalise,
and it is not a fallback for a real provider - `scrappy doctor` reports it as a
development provider, and the API reports the same.

It exists for three reasons:

1. The definition of done for v0.1 must be reproducible in CI.
2. Security boundaries need tests that do not depend on what a model felt like
   saying that day.
3. An operator evaluating Scrappy OS should be able to see the orchestration
   loop work before deciding to point it at an LLM.

The rules map objective keywords to *read-only* tool sequences. There is no
rule anywhere in this file that proposes a mutating step.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any, TypeVar

from pydantic import BaseModel

from scrappy_os.models.base import (
    ChatMessage,
    GenerationResult,
    ModelProvider,
    ProviderHealth,
    ProviderInfo,
)

SchemaT = TypeVar("SchemaT", bound=BaseModel)

#: Keyword -> read-only steps. Order matters; the first match wins.
PLAYBOOK: tuple[tuple[re.Pattern[str], str, tuple[tuple[str, str, dict[str, Any]], ...]], ...] = (
    (
        re.compile(r"\b(disk|filesystem|storage|space|full|df)\b", re.I),
        "The objective concerns storage, so inspect mounted filesystems and their usage.",
        (
            ("List filesystem usage for every mount point", "system.disk", {}),
            ("Capture host identity so the report names the right machine", "system.info", {}),
        ),
    ),
    (
        re.compile(r"\b(memory|ram|oom|swap|free)\b", re.I),
        "The objective concerns memory pressure, so read memory and load.",
        (
            ("Read total, used and available memory", "system.memory", {}),
            ("Read load averages to see whether pressure is sustained", "system.load", {}),
        ),
    ),
    (
        re.compile(r"\b(cpu|load|slow|performance|busy)\b", re.I),
        "The objective concerns CPU load, so read load averages and the process table.",
        (
            ("Read load averages and CPU counts", "system.load", {}),
            ("List the heaviest processes", "process.list", {"limit": 10, "sort_by": "cpu"}),
        ),
    ),
    (
        re.compile(r"\b(process|pid|running|daemon)\b", re.I),
        "The objective concerns running processes, so enumerate them.",
        (("List running processes by memory footprint", "process.list", {"limit": 20}),),
    ),
    (
        re.compile(r"\b(nginx|apache|service|systemd|unit|failing|failed)\b", re.I),
        "The objective concerns a service, so gather service state and recent context "
        "before proposing any change.",
        (
            ("Check whether the service process is running at all", "process.list", {"limit": 20}),
            ("Read host and uptime context", "system.info", {}),
            ("Check disk, a common cause of service start failures", "system.disk", {}),
        ),
    ),
    (
        re.compile(r"\b(network|interface|ip|port|socket)\b", re.I),
        "The objective concerns networking, so read interface configuration.",
        (("List network interfaces and addresses", "system.network", {}),),
    ),
    (
        re.compile(r"\b(git|repo|repository|branch|commit)\b", re.I),
        "The objective concerns a repository, so read its state without mutating it.",
        (
            ("Read working-tree status", "git.status", {}),
            ("Read recent commits for context", "git.log", {"limit": 10}),
        ),
    ),
    (
        re.compile(r"\b(uptime|reboot|boot|how long)\b", re.I),
        "The objective concerns uptime.",
        (("Read uptime and boot time", "system.uptime", {}),),
    ),
)

#: Used when nothing matches: a broad, harmless survey.
FALLBACK_STEPS: tuple[tuple[str, str, dict[str, Any]], ...] = (
    ("Establish baseline host identity and OS version", "system.info", {}),
    ("Read filesystem usage", "system.disk", {}),
    ("Read memory usage", "system.memory", {}),
)


class MockProvider(ModelProvider):
    """Deterministic, offline, read-only-by-construction provider."""

    def __init__(self, *, model: str = "mock-deterministic-v1") -> None:
        self._model = model
        self.calls = 0

    @property
    def info(self) -> ProviderInfo:
        return ProviderInfo(
            name="mock",
            kind="mock",
            model=self._model,
            base_url=None,
            supports_structured_output=True,
            requires_network=False,
            requires_credentials=False,
        )

    async def generate(
        self,
        messages: Sequence[ChatMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        stop: Sequence[str] | None = None,
    ) -> GenerationResult:
        self.calls += 1
        objective = _last_user_content(messages)
        return GenerationResult(
            text=(
                "Deterministic development provider: no language model was consulted. "
                f"Objective seen: {objective[:200]}"
            ),
            model=self._model,
            provider="mock",
            duration_ms=0.0,
            finish_reason="stop",
        )

    async def generate_structured(
        self,
        messages: Sequence[ChatMessage],
        schema: type[SchemaT],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        max_repairs: int = 1,
    ) -> SchemaT:
        """Build the requested structure directly from the rule table.

        Bypasses text generation entirely, so mock runs cannot fail on JSON
        parsing and tests stay about the thing under test.
        """
        # Imported here rather than at module scope: the agent package depends
        # on the provider interface, and this keeps that arrow pointing one way.
        from scrappy_os.agents.schemas import (
            PlanProposal,
            ProposedStep,
            RecoveryPlan,
            ReviewedPlan,
            Verification,
        )

        self.calls += 1
        text = _user_text(messages)
        objective = _last_user_content(messages)

        if schema is PlanProposal:
            reasoning, steps = _plan_for(objective)
            return schema.model_validate(
                PlanProposal(
                    reasoning=reasoning,
                    steps=[
                        ProposedStep(intent=intent, tool=tool, arguments=dict(args))
                        for intent, tool, args in steps
                    ],
                    required_capabilities=sorted({tool for _, tool, _ in steps}),
                    predicted_side_effects=["none: every step is read-only"],
                ).model_dump()
            )

        if schema is ReviewedPlan:
            proposed = _parse_proposed_steps(text)
            return schema.model_validate(
                ReviewedPlan(
                    approved=True,
                    reasoning=(
                        "All proposed steps are read-only inspections of local system state. "
                        "No step mutates the machine, so the plan is safe to run as written."
                    ),
                    concerns=[],
                    steps=proposed,
                ).model_dump()
            )

        if schema is Verification:
            observations = _observation_block(text)
            satisfied = bool(observations.strip())
            return schema.model_validate(
                Verification(
                    objective_satisfied=satisfied,
                    decision="complete" if satisfied else "abort",
                    confidence=0.9 if satisfied else 0.2,
                    reasoning=(
                        "Every planned step ran and returned data."
                        if satisfied
                        else "No observations were collected, so nothing can be concluded."
                    ),
                    conclusion=_summarise(objective, observations),
                    concerns=[] if satisfied else ["no observations were collected"],
                ).model_dump()
            )

        if schema is RecoveryPlan:
            return schema.model_validate(
                RecoveryPlan(
                    diagnosis=(
                        "The deterministic provider does not attempt automated recovery. "
                        "Nothing was mutated, so there is nothing to roll back."
                    ),
                    recoverable=False,
                    reasoning="Recovery planning requires a real model provider.",
                    steps=[],
                ).model_dump()
            )

        # An unknown schema is a programming error, not something to improvise.
        raise NotImplementedError(
            f"MockProvider has no rule for {schema.__name__}. "
            "Add one, or run this path against a real provider."
        )

    async def health_check(self) -> ProviderHealth:
        return ProviderHealth(
            healthy=True,
            detail="deterministic development provider (no model, no network)",
            latency_ms=0.0,
        )


def _plan_for(objective: str) -> tuple[str, tuple[tuple[str, str, dict[str, Any]], ...]]:
    for pattern, reasoning, steps in PLAYBOOK:
        if pattern.search(objective):
            return reasoning, steps
    return (
        "No specific subsystem was named, so gather a broad read-only baseline.",
        FALLBACK_STEPS,
    )


def _last_user_content(messages: Sequence[ChatMessage]) -> str:
    """The objective, pulled out of the orchestrator's rendered prompt.

    Prompts start with an ``OBJECTIVE`` section; a real model reads the whole
    thing, but the rule table only needs the objective text.
    """
    for message in reversed(messages):
        if message.role != "user":
            continue
        content = message.content
        marker = "OBJECTIVE\n"
        if content.startswith(marker):
            return content[len(marker) :].split("\n\n", 1)[0].strip()
        return content
    return messages[-1].content if messages else ""


def _user_text(messages: Sequence[ChatMessage]) -> str:
    """Only the user turns.

    System prompts mention the word OBSERVATIONS when they explain the trust
    boundary; searching them too would match the instruction rather than the
    data.
    """
    return "\n".join(message.content for message in messages if message.role == "user")


def _parse_proposed_steps(text: str) -> list[Any]:
    """Recover the step list from the review prompt.

    The orchestrator renders the plan as ``N. intent [tool=NAME args={...}]``.
    Parsing our own prompt is fine for a development provider; a real model
    reads the same text.
    """
    from scrappy_os.agents.schemas import ProposedStep

    steps: list[ProposedStep] = []
    pattern = re.compile(r"^\s*\d+\.\s+(.*?)\s+\[tool=([\w.]+)\s+args=(\{.*?\})\]\s*$", re.M)
    for match in pattern.finditer(text):
        intent, tool, raw_args = match.groups()
        try:
            import json

            arguments = json.loads(raw_args)
        except ValueError:
            arguments = {}
        steps.append(
            ProposedStep(intent=intent, tool=tool, arguments=arguments, expected_side_effects=[])
        )
    return steps


#: Delimiters that :meth:`WorkingMemory.render_observations` wraps tool output in.
_OBSERVATION_START = "--- BEGIN TOOL OUTPUT"
_OBSERVATION_END = "--- END TOOL OUTPUT ---"


def _observation_block(text: str) -> str:
    """The tool output the orchestrator put in the prompt, and nothing else."""
    start = text.find(_OBSERVATION_START)
    if start == -1:
        return ""
    body_start = text.find("\n", start)
    end = text.find(_OBSERVATION_END, start)
    if body_start == -1:
        return ""
    return text[body_start : end if end != -1 else len(text)].strip()


#: Conclusions are capped well under the schema limit so a large observation
#: block can never turn into a validation error at the end of a working run.
MAX_CONCLUSION_CHARS = 6000


def _summarise(objective: str, observations: str) -> str:
    if not observations.strip():
        return (
            "No observations were collected, so no conclusion can be drawn about: "
            f"{objective.strip()[:500]}"
        )
    header = f"Objective: {objective.strip()[:500]}\n\nRead directly from this machine:\n"
    footer = (
        "\n\nNote: this summary was assembled by the deterministic development provider, "
        "which reports tool output verbatim and does not interpret it. Configure a real "
        "model provider (SCRAPPY_MODEL_PROVIDER=openai or ollama) for analysis."
    )
    room = MAX_CONCLUSION_CHARS - len(header) - len(footer)
    body = observations.strip()[:room]
    return header + body + footer


__all__ = ["FALLBACK_STEPS", "PLAYBOOK", "MockProvider"]
