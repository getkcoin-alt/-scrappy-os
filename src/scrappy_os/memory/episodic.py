"""Episodic memory - the durable record of what actually happened.

Backed by the same SQLite file as the audit log, but a different table and a
different purpose: audit answers "what did this system do and under whose
authority", episodic answers "what has this machine looked like before".

Search is LIKE-based. That is the honest v0.1 answer - it is enough to find
"the last time we looked at nginx" and it introduces no dependency. Similarity
search belongs in :class:`~scrappy_os.memory.base.SemanticMemory`.
"""

from __future__ import annotations

from datetime import datetime

from scrappy_os.core.models import Observation
from scrappy_os.memory.store import Store, dumps, loads
from scrappy_os.observability.redaction import redact, redact_text


class SQLiteEpisodicMemory:
    """Durable observation history."""

    def __init__(self, store: Store) -> None:
        self._store = store

    async def remember(self, observation: Observation) -> None:
        """Persist one observation, redacted.

        Redaction happens here rather than at the call site: observations carry
        raw tool output, and tool output is exactly where a credential shows up
        by accident.
        """
        await self._store.execute(
            """
            INSERT OR REPLACE INTO observations
                (id, task_id, call_id, created_at, source, success, content, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                observation.id,
                observation.task_id,
                observation.call_id,
                observation.created_at.isoformat(),
                observation.source,
                int(observation.success),
                redact_text(observation.content),
                dumps(redact(observation.metadata)),
            ),
        )

    async def recall_task(self, task_id: str, *, limit: int = 200) -> list[Observation]:
        rows = await self._store.fetch_all(
            "SELECT * FROM observations WHERE task_id = ? ORDER BY created_at ASC LIMIT ?",
            (task_id, limit),
        )
        return [_to_observation(row) for row in rows]

    async def recent(self, *, limit: int = 50) -> list[Observation]:
        rows = await self._store.fetch_all(
            "SELECT * FROM observations ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        return [_to_observation(row) for row in rows]

    async def search(self, query: str, *, limit: int = 20) -> list[Observation]:
        """Substring search over observation text and source.

        The query is bound as a parameter, never interpolated - an objective is
        attacker-influenced text and must not be able to shape SQL.
        """
        pattern = f"%{query}%"
        rows = await self._store.fetch_all(
            """
            SELECT * FROM observations
             WHERE content LIKE ? OR source LIKE ?
             ORDER BY created_at DESC
             LIMIT ?
            """,
            (pattern, pattern, limit),
        )
        return [_to_observation(row) for row in rows]

    async def count(self) -> int:
        row = await self._store.fetch_one("SELECT COUNT(*) AS n FROM observations")
        return int(row["n"]) if row else 0


def _to_observation(row: dict[str, object]) -> Observation:
    return Observation(
        id=str(row["id"]),
        task_id=str(row["task_id"]),
        call_id=str(row["call_id"]) if row["call_id"] else None,
        created_at=datetime.fromisoformat(str(row["created_at"])),
        source=str(row["source"]),
        success=bool(row["success"]),
        content=str(row["content"]),
        metadata=loads(str(row["metadata"]) if row["metadata"] else None),
    )


__all__ = ["SQLiteEpisodicMemory"]
