"""Semantic memory - interface now, implementation later.

v0.1 ships :class:`NullSemanticMemory`, which stores nothing and retrieves
nothing, and says so. That is a deliberate choice over adding a vector database
to a system whose first milestone is "read the disk and explain what you see":
embeddings would be infrastructure with no consumer.

What the eventual implementation has to get right, recorded here so the next
person does not have to rediscover it:

* **Retrieved memories are untrusted.** Anything stored came from tool output
  or model text. A retrieved "fact" that reads like an instruction is a
  poisoned-memory attack, and retrieval must render into the same data-delimited
  block that :mod:`scrappy_os.memory.working` uses.
* **Facts need provenance and an expiry.** "nginx listens on 8080" was true in
  March. A store that cannot say when and how it learned something will
  confidently mislead.
* **Writes are a privileged act.** Deciding what is worth remembering forever
  should be a reviewed step, not a side effect of every task.
"""

from __future__ import annotations

from typing import Any

from scrappy_os.core.models import new_id
from scrappy_os.observability.logging import get_logger

logger = get_logger("memory.semantic")


class NullSemanticMemory:
    """The v0.1 implementation: honest about doing nothing.

    Not a silent no-op - :meth:`store` logs at debug level and
    :attr:`available` is ``False``, so callers and ``scrappy doctor`` can tell
    that semantic recall is unavailable rather than merely empty.
    """

    def __init__(self) -> None:
        self._notice_logged = False

    async def store(self, content: str, *, metadata: dict[str, Any] | None = None) -> str:
        if not self._notice_logged:
            logger.debug(
                "semantic_memory_unavailable",
                detail="NullSemanticMemory discards writes; no vector backend is configured",
            )
            self._notice_logged = True
        return new_id()

    async def retrieve(self, query: str, *, limit: int = 5) -> list[tuple[str, float]]:
        return []

    @property
    def available(self) -> bool:
        return False


__all__ = ["NullSemanticMemory"]
