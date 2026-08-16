"""Shared agent machinery.

An agent is a role, a prompt, and a schema it must produce. It has no
privileges: it cannot call a tool, read a file or change the machine. It
returns typed data to the orchestrator, which decides what to do about it.

That separation is the whole point of the design. Prompt injection against an
agent yields *a request*, and a request still has to survive schema validation,
the policy engine, the risk ceiling and - above WRITE - a human.
"""

from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

from scrappy_os.core.enums import AgentRole
from scrappy_os.core.models import AgentDecision, Task
from scrappy_os.memory.working import WorkingMemory
from scrappy_os.models.base import ChatMessage, ModelProvider
from scrappy_os.observability.logging import get_logger
from scrappy_os.tools.base import ToolRegistry

SchemaT = TypeVar("SchemaT", bound=BaseModel)


def _prompt_dirs() -> tuple[Path, ...]:
    """Where prompt overrides are looked for, most specific first."""
    candidates = []
    override = os.environ.get("SCRAPPY_PROMPT_DIR")
    if override:
        candidates.append(Path(override).expanduser())
    # Source checkout: src/scrappy_os/agents/base.py -> <repo>/prompts
    candidates.append(Path(__file__).resolve().parents[3] / "prompts")
    candidates.append(Path.cwd() / "prompts")
    return tuple(candidates)


class Agent(ABC):
    """Base class for Brahma, Vishnu and Mahesh."""

    role: AgentRole

    def __init__(self, provider: ModelProvider, registry: ToolRegistry) -> None:
        self._provider = provider
        self._registry = registry
        self._logger = get_logger(f"agent.{self.role}")

    @property
    def provider(self) -> ModelProvider:
        return self._provider

    @abstractmethod
    def system_prompt(self) -> str:
        """The role's standing instructions."""

    async def _ask(
        self,
        user_prompt: str,
        schema: type[SchemaT],
        *,
        task: Task,
    ) -> tuple[SchemaT, float]:
        """One structured turn. Returns the parsed result and its duration."""
        started = time.perf_counter()
        messages = [
            ChatMessage.system(self.system_prompt()),
            ChatMessage.user(user_prompt),
        ]
        result = await self._provider.generate_structured(messages, schema)
        duration_ms = (time.perf_counter() - started) * 1000
        task.model_calls += 1
        self._logger.debug(
            "agent_turn",
            role=str(self.role),
            schema=schema.__name__,
            duration_ms=round(duration_ms, 1),
            model_calls=task.model_calls,
        )
        return result, duration_ms

    def _decision(
        self,
        task: Task,
        *,
        decision: str,
        reasoning: str,
        confidence: float = 0.5,
        concerns: list[str] | None = None,
        duration_ms: float = 0.0,
    ) -> AgentDecision:
        info = self._provider.info
        return AgentDecision(
            task_id=task.id,
            role=self.role,
            decision=decision,
            confidence=confidence,
            reasoning=reasoning,
            concerns=concerns or [],
            model=info.model,
            provider=info.name,
            duration_ms=duration_ms,
        )


def load_prompt(name: str, fallback: str) -> str:
    """Read a prompt from ``prompts/``, falling back to the built-in text.

    Prompts live on disk so an operator can tune them without editing Python,
    but the code never depends on the file existing - a missing or unreadable
    prompt file degrades to the embedded default rather than failing a boot.
    """
    for directory in _prompt_dirs():
        path = directory / f"{name}.md"
        try:
            if path.is_file():
                return path.read_text(encoding="utf-8").strip()
        except OSError:
            get_logger("agent").warning("prompt_unreadable", path=str(path), using="next candidate")
    return fallback.strip()


def render_context(
    task: Task,
    memory: WorkingMemory,
    registry: ToolRegistry,
    *,
    include_observations: bool = True,
) -> str:
    """The shared context block every agent prompt starts from."""
    sections = [
        f"OBJECTIVE\n{task.objective.text}",
        f"RISK CEILING\nSteps above `{task.objective.max_risk}` will be refused by policy.",
        f"AVAILABLE TOOLS\n{registry.catalogue(ceiling=task.objective.max_risk)}",
    ]
    if memory.facts:
        sections.append(f"KNOWN FACTS\n{memory.render_facts()}")
    if include_observations:
        sections.append(f"OBSERVATIONS\n{memory.render_observations()}")
    return "\n\n".join(sections)


__all__ = ["Agent", "load_prompt", "render_context"]
