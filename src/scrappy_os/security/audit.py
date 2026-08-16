"""The audit log: an append-only record of everything Scrappy OS did.

Design rules:

* **Write on the way in, not on the way out.** A tool call is audited when it
  is requested, not only when it succeeds - a denied or crashed operation is
  exactly the one you want a record of.
* **Redact before persist.** Payloads pass through
  :func:`~scrappy_os.observability.redaction.redact` on the way to disk. There
  is no code path that writes a raw payload.
* **Hash what you cannot store.** Large or sensitive tool output is replaced by
  a SHA-256 digest plus a short preview, so integrity is checkable without the
  database becoming a secondary copy of ``/etc``.

The audit log subscribes to the event bus, so components do not call it
directly - they publish, and the record follows.
"""

from __future__ import annotations

from typing import Any

from scrappy_os.core.enums import EventType, PolicyDecision, RiskLevel
from scrappy_os.core.events import Event, EventBus
from scrappy_os.core.models import AuditEvent, ToolCall, ToolResult, utc_now
from scrappy_os.memory.store import Store, dumps, loads
from scrappy_os.observability.logging import get_logger
from scrappy_os.observability.redaction import redact, sha256_of

logger = get_logger("audit")

#: Output longer than this is hashed and previewed rather than stored whole.
MAX_STORED_OUTPUT_CHARS = 4000
PREVIEW_CHARS = 500


class AuditLog:
    """Durable, append-only history of objectives, decisions and actions."""

    def __init__(self, store: Store) -> None:
        self._store = store

    # -- ingestion ----------------------------------------------------------

    def attach(self, bus: EventBus) -> None:
        """Subscribe to the bus so every published event is recorded."""
        bus.add_handler(self._on_event)

    async def _on_event(self, event: Event) -> None:
        await self.record(
            AuditEvent(
                event_type=event.type,
                task_id=event.task_id,
                component=event.component,
                actor=str(event.payload.get("actor", "scrappy")),
                tool_name=_optional_str(event.payload.get("tool_name")),
                risk=_optional_risk(event.payload.get("risk")),
                decision=_optional_decision(event.payload.get("decision")),
                success=_optional_bool(event.payload.get("success")),
                duration_ms=_optional_float(event.payload.get("duration_ms")),
                payload=event.payload,
            )
        )

    async def record(self, event: AuditEvent) -> AuditEvent:
        """Persist one audit event, redacting the payload first."""
        payload = redact(event.payload)
        encoded = dumps(payload)
        digest: str | None = None
        if len(encoded) > MAX_STORED_OUTPUT_CHARS:
            digest = sha256_of(encoded)
            payload = {
                "_hashed": True,
                "_sha256": digest,
                "_bytes": len(encoded),
                "_preview": encoded[:PREVIEW_CHARS],
            }
            encoded = dumps(payload)

        await self._store.execute(
            """
            INSERT INTO audit_events (
                id, timestamp, event_type, task_id, actor, component,
                tool_name, risk, decision, success, duration_ms, payload, payload_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.id,
                event.timestamp.isoformat(),
                str(event.event_type),
                event.task_id,
                event.actor,
                event.component,
                event.tool_name,
                str(event.risk) if event.risk else None,
                str(event.decision) if event.decision else None,
                None if event.success is None else int(event.success),
                event.duration_ms,
                encoded,
                digest,
            ),
        )
        return event

    # -- tool call ledger ---------------------------------------------------

    async def record_call(self, call: ToolCall) -> None:
        """Insert a tool call at request time, before it is allowed to run."""
        await self._store.execute(
            """
            INSERT OR REPLACE INTO tool_calls (
                id, task_id, step_id, tool_name, arguments, actor, requested_at,
                risk_level, policy_decision, policy_rule, approval_id, approval_state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                call.id,
                call.task_id,
                call.step_id,
                call.tool_name,
                dumps(redact(call.arguments)),
                call.actor,
                call.requested_at.isoformat(),
                str(call.risk_level),
                str(call.policy_decision) if call.policy_decision else None,
                call.policy_rule,
                call.approval_id,
                str(call.approval_state) if call.approval_state else None,
            ),
        )

    async def record_result(self, result: ToolResult) -> None:
        """Complete the tool-call row with the outcome."""
        encoded = dumps(redact(result.output))
        digest = sha256_of(encoded)
        preview = encoded if len(encoded) <= MAX_STORED_OUTPUT_CHARS else encoded[:PREVIEW_CHARS]
        await self._store.execute(
            """
            UPDATE tool_calls
               SET success = ?, duration_ms = ?, error = ?,
                   output_sha256 = ?, output_preview = ?
             WHERE id = ?
            """,
            (
                int(result.success),
                result.duration_ms,
                result.error,
                digest,
                preview,
                result.call_id,
            ),
        )

    # -- queries ------------------------------------------------------------

    async def recent(self, *, limit: int = 50) -> list[dict[str, Any]]:
        """Most recent audit events, newest first."""
        rows = await self._store.fetch_all(
            "SELECT * FROM audit_events ORDER BY timestamp DESC, rowid DESC LIMIT ?",
            (limit,),
        )
        return [_decode(row) for row in rows]

    async def for_task(self, task_id: str, *, limit: int = 500) -> list[dict[str, Any]]:
        """Everything recorded for one task, oldest first - the trace of a run."""
        rows = await self._store.fetch_all(
            "SELECT * FROM audit_events WHERE task_id = ?"
            " ORDER BY timestamp ASC, rowid ASC LIMIT ?",
            (task_id, limit),
        )
        return [_decode(row) for row in rows]

    async def calls_for_task(self, task_id: str) -> list[dict[str, Any]]:
        rows = await self._store.fetch_all(
            "SELECT * FROM tool_calls WHERE task_id = ? ORDER BY requested_at ASC",
            (task_id,),
        )
        for row in rows:
            row["arguments"] = loads(row.get("arguments"))
        return rows

    async def count(self) -> int:
        row = await self._store.fetch_one("SELECT COUNT(*) AS n FROM audit_events")
        return int(row["n"]) if row else 0


def _decode(row: dict[str, Any]) -> dict[str, Any]:
    row["payload"] = loads(row.get("payload"))
    if row.get("success") is not None:
        row["success"] = bool(row["success"])
    return row


def _optional_str(value: Any) -> str | None:
    return str(value) if isinstance(value, str) and value else None


def _optional_bool(value: Any) -> bool | None:
    return bool(value) if isinstance(value, bool) else None


def _optional_float(value: Any) -> float | None:
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None


def _optional_risk(value: Any) -> RiskLevel | None:
    try:
        return RiskLevel(value) if value else None
    except ValueError:
        return None


def _optional_decision(value: Any) -> PolicyDecision | None:
    try:
        return PolicyDecision(value) if value else None
    except ValueError:
        return None


async def audit_denied(
    audit: AuditLog,
    *,
    task_id: str,
    tool_name: str,
    risk: RiskLevel,
    rule: str,
    reason: str,
) -> None:
    """Record a refusal. Denials are the most valuable rows in the table."""
    await audit.record(
        AuditEvent(
            event_type=EventType.SECURITY_DENIED,
            task_id=task_id,
            component="policy",
            tool_name=tool_name,
            risk=risk,
            decision=PolicyDecision.DENY,
            success=False,
            timestamp=utc_now(),
            payload={"rule": rule, "reason": reason},
        )
    )


__all__ = ["MAX_STORED_OUTPUT_CHARS", "AuditLog", "audit_denied"]
