"""The tool protocol.

A tool is the only way Scrappy OS touches the machine. Each one declares a
typed input schema, a static risk ceiling, the permissions it needs, and how to
classify a *specific* set of arguments. The executor - not the tool - handles
policy, approval, audit and timing, so a tool author cannot forget to.

Adding a tool is deliberately a small, reviewable act: subclass :class:`Tool`,
declare a Pydantic input model, implement :meth:`Tool.run`, register it. See
``docs/TOOL_PROTOCOL.md``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, ValidationError

from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.enums import RiskLevel
from scrappy_os.core.errors import ToolNotFound, ValidationFailed


@dataclass(slots=True)
class ToolContext:
    """Everything a tool may know about the invocation.

    Note what is *absent*: no event bus, no policy engine, no store. Tools
    observe and act; they do not get to decide whether they were allowed to.
    """

    settings: ScrappySettings
    task_id: str
    actor: str = "scrappy"
    call_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def workspace(self) -> Path:
        return self.settings.workspace.expanduser().resolve(strict=False)

    @property
    def read_roots(self) -> tuple[Path, ...]:
        return self.settings.allowed_read_roots


@dataclass(frozen=True, slots=True)
class RollbackSpec:
    """How a tool's effect can be undone, if it can be.

    Advisory metadata consumed by Mahesh. A tool that cannot be undone says so,
    which is more useful than pretending otherwise.
    """

    supported: bool
    description: str
    inverse_tool: str | None = None


class EmptyArgs(BaseModel):
    """Input model for tools that take no arguments."""

    model_config = {"extra": "forbid"}


class Tool(ABC):
    """Base class for every machine capability."""

    #: Dotted, stable, and what the model must emit to call it.
    name: ClassVar[str] = ""
    #: One line. Goes into the planning prompt, so write it for a reader.
    description: ClassVar[str] = ""
    #: Typed arguments. Extra fields are rejected.
    input_model: ClassVar[type[BaseModel]] = EmptyArgs
    #: The worst this tool can do with any arguments. A ceiling, not a guess.
    risk: ClassVar[RiskLevel] = RiskLevel.READ
    #: Capability labels, for future role-based grants.
    required_permissions: ClassVar[tuple[str, ...]] = ()
    #: Undo metadata for Mahesh.
    rollback: ClassVar[RollbackSpec | None] = None

    def parse_arguments(self, arguments: dict[str, Any]) -> BaseModel:
        """Validate raw arguments into the typed input model.

        The first thing that happens to model-proposed arguments. A dict that
        does not validate never reaches :meth:`run`.
        """
        try:
            return self.input_model.model_validate(arguments)
        except ValidationError as exc:
            problems = "; ".join(
                f"{'.'.join(str(part) for part in err['loc'])}: {err['msg']}"
                for err in exc.errors()[:5]
            )
            raise ValidationFailed(
                f"Invalid arguments for {self.name}: {problems}",
                tool_name=self.name,
            ) from exc

    def classify(self, args: BaseModel, ctx: ToolContext) -> tuple[RiskLevel, str]:
        """Risk of running with *these* arguments.

        Default is the static ceiling. Tools whose danger depends on inputs -
        shell, filesystem writes, deletion - override this. The classification
        is authoritative: the executor uses it rather than whatever risk a
        planning agent guessed, and a mismatch between the two is audited.

        ``ctx`` is passed rather than read from a global so that classification
        is a pure function of (arguments, configuration) and stays testable.
        """
        return self.risk, f"{self.name} is classified {self.risk}"

    def affected_paths(self, args: BaseModel) -> Sequence[Path]:
        """Filesystem paths this invocation would touch.

        Used by the policy engine for workspace containment. Returning nothing
        means "no filesystem effect", so be accurate here.
        """
        return ()

    @abstractmethod
    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        """Do the work and return a JSON-serialisable result.

        Raise :class:`~scrappy_os.core.errors.ToolError` on failure. Never
        return a success-shaped dict describing a failure - the executor
        distinguishes the two and the audit log records which happened.
        """

    def json_schema(self) -> dict[str, Any]:
        """Machine-readable description handed to the planning agent."""
        return {
            "name": self.name,
            "description": self.description,
            "risk": str(self.risk),
            "parameters": self.input_model.model_json_schema(),
        }

    def describe(self) -> str:
        """One-line rendering for prompts and ``scrappy tools``."""
        return f"{self.name} [{self.risk}] - {self.description}"


class ToolRegistry:
    """The set of capabilities this instance has.

    A tool that is not registered does not exist: the policy engine denies
    unknown names outright rather than searching for something close.
    """

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}
        self._disabled: set[str] = set()

    def register(self, tool: Tool, *, replace: bool = False) -> Tool:
        if not tool.name:
            raise ValueError(f"{type(tool).__name__} must declare a name")
        if tool.name in self._tools and not replace:
            raise ValueError(f"Tool {tool.name!r} is already registered")
        self._tools[tool.name] = tool
        return tool

    def disable(self, name: str) -> None:
        """Turn a registered tool off without removing it, so audit still resolves it."""
        self._disabled.add(name)

    def enable(self, name: str) -> None:
        self._disabled.discard(name)

    def get(self, name: str) -> Tool:
        tool = self._tools.get(name)
        if tool is None:
            raise ToolNotFound(name, known=sorted(self._tools))
        return tool

    def has(self, name: str) -> bool:
        return name in self._tools

    @property
    def names(self) -> frozenset[str]:
        return frozenset(self._tools)

    @property
    def disabled(self) -> frozenset[str]:
        return frozenset(self._disabled)

    def all(self) -> list[Tool]:
        return [self._tools[name] for name in sorted(self._tools)]

    def enabled(self) -> list[Tool]:
        return [tool for tool in self.all() if tool.name not in self._disabled]

    def by_max_risk(self, ceiling: RiskLevel) -> list[Tool]:
        """Tools whose static risk is at or below ``ceiling``.

        Used to build the planning prompt: an agent working under a READ
        ceiling is not shown tools it could never be permitted to run.
        """
        return [tool for tool in self.enabled() if tool.risk.rank <= ceiling.rank]

    def catalogue(self, *, ceiling: RiskLevel | None = None) -> str:
        """The tool list as it appears in a planning prompt."""
        tools = self.by_max_risk(ceiling) if ceiling is not None else self.enabled()
        if not tools:
            return "(no tools available at this risk ceiling)"
        lines = []
        for tool in tools:
            schema = tool.input_model.model_json_schema()
            properties = schema.get("properties", {})
            required = set(schema.get("required", []))
            params = ", ".join(
                f"{key}{'' if key in required else '?'}:{value.get('type', 'any')}"
                for key, value in properties.items()
            )
            lines.append(f"- {tool.name}({params}) [{tool.risk}] {tool.description}")
        return "\n".join(lines)

    def schemas(self) -> list[dict[str, Any]]:
        return [tool.json_schema() for tool in self.enabled()]


__all__ = [
    "EmptyArgs",
    "RollbackSpec",
    "Tool",
    "ToolContext",
    "ToolRegistry",
]
