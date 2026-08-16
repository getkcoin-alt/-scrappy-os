"""Memory interfaces.

Three layers, deliberately separated because they have different lifetimes,
different trust levels and different eventual storage:

* **Working** - in-process, task-scoped, discarded when the task ends.
* **Episodic** - durable, append-only history of what happened.
* **Semantic** - distilled knowledge about *this machine*, retrievable by
  similarity. v0.1 defines the interface and ships a null implementation; it
  does not add a vector database that nobody has a use for yet.

Everything read out of memory is **untrusted input**. Episodic records contain
tool output, and tool output contains whatever was in a file or a log line.
Memory poisoning is a real attack: a crafted log entry that reads like an
instruction gets recalled later and treated as one. Callers render recalled
content inside explicit data delimiters and never as instructions.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from scrappy_os.core.models import Observation


@runtime_checkable
class EpisodicMemory(Protocol):
    """Durable history of tasks, actions and their outcomes."""

    async def remember(self, observation: Observation) -> None:
        """Persist one observation."""
        ...

    async def recall_task(self, task_id: str, *, limit: int = 200) -> list[Observation]:
        """Everything observed during one task, oldest first."""
        ...

    async def recent(self, *, limit: int = 50) -> list[Observation]:
        """Most recent observations across all tasks."""
        ...

    async def search(self, query: str, *, limit: int = 20) -> list[Observation]:
        """Find observations matching a query."""
        ...


@runtime_checkable
class SemanticMemory(Protocol):
    """Distilled, retrievable knowledge about this machine.

    The seam for pgvector, Qdrant or sqlite-vec. Implementations embed on
    :meth:`store` and retrieve by similarity on :meth:`retrieve`.
    """

    async def store(self, content: str, *, metadata: dict[str, Any] | None = None) -> str:
        """Persist a fact and return its id."""
        ...

    async def retrieve(self, query: str, *, limit: int = 5) -> list[tuple[str, float]]:
        """Return ``(content, score)`` pairs ordered by relevance."""
        ...

    @property
    def available(self) -> bool:
        """Whether this implementation can actually retrieve anything."""
        ...


__all__ = ["EpisodicMemory", "SemanticMemory"]
