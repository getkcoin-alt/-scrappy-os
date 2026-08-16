"""The approval gate.

An approval authorises **one specific operation**: this tool, these arguments,
this task, once, before this deadline. It is not a session, not a role, and not
a grant that a later call can reuse. That is enforced structurally - approvals
move to :data:`~scrappy_os.core.enums.ApprovalState.CONSUMED` when spent, and
:meth:`ApprovalManager.consume` refuses anything that is not exactly
``APPROVED``.

Requests are persisted, so a pending approval survives a restart and shows up
in ``scrappy approvals`` rather than silently disappearing.
"""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from typing import Any

from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.enums import ApprovalState, EventType, RiskLevel
from scrappy_os.core.errors import ApprovalExpired, ScrappyError
from scrappy_os.core.events import EventBus, emit
from scrappy_os.core.models import ApprovalDecision, ApprovalRequest, ToolCall, utc_now
from scrappy_os.memory.store import Store, dumps, loads
from scrappy_os.observability.logging import get_logger
from scrappy_os.observability.redaction import redact

logger = get_logger("approvals")

#: Typed exactly, by a human, for DESTRUCTIVE operations.
CONFIRMATION_PHRASE = "I ACCEPT THE RISK"


class ApprovalNotFound(ScrappyError):
    """An approval id does not exist in this instance's store."""


class ApprovalManager:
    """Creates, persists and resolves approval requests."""

    def __init__(
        self,
        settings: ScrappySettings,
        store: Store,
        bus: EventBus | None = None,
    ) -> None:
        self._settings = settings
        self._store = store
        self._bus = bus
        self._waiters: dict[str, asyncio.Future[ApprovalDecision]] = {}

    # -- creation -----------------------------------------------------------

    async def request(
        self,
        call: ToolCall,
        *,
        risk: RiskLevel,
        reason: str,
        requires_confirmation_phrase: bool = False,
    ) -> ApprovalRequest:
        """Open a pending approval for ``call`` and publish the event."""
        ttl = timedelta(minutes=self._settings.approval_ttl_minutes)
        request = ApprovalRequest(
            task_id=call.task_id,
            call_id=call.id,
            tool_name=call.tool_name,
            arguments=redact(call.arguments),
            risk=risk,
            reason=reason,
            summary=describe_operation(call.tool_name, call.arguments),
            expires_at=utc_now() + ttl,
            requires_confirmation_phrase=requires_confirmation_phrase,
            confirmation_phrase=CONFIRMATION_PHRASE if requires_confirmation_phrase else None,
        )
        await self._persist(request)
        logger.info(
            "approval_requested",
            approval_id=request.id,
            task_id=request.task_id,
            tool=request.tool_name,
            risk=str(risk),
        )
        if self._bus is not None:
            await emit(
                self._bus,
                EventType.APPROVAL_REQUESTED,
                task_id=request.task_id,
                component="approvals",
                approval_id=request.id,
                tool_name=request.tool_name,
                risk=str(risk),
                summary=request.summary,
                reason=reason,
            )
        return request

    # -- resolution ---------------------------------------------------------

    async def resolve(self, decision: ApprovalDecision) -> ApprovalRequest:
        """Apply a human decision to a pending request.

        Raises if the request is unknown, already resolved, expired, or if a
        DESTRUCTIVE request was approved without the typed confirmation phrase.
        """
        request = await self.get(decision.request_id)
        if request is None:
            raise ApprovalNotFound(
                f"No approval request {decision.request_id}", approval_id=decision.request_id
            )

        if request.state is not ApprovalState.PENDING:
            raise ScrappyError(
                f"Approval {request.id} is already {request.state}",
                approval_id=request.id,
                state=str(request.state),
            )

        if request.is_expired():
            request.state = ApprovalState.EXPIRED
            await self._update_state(request, decision, expired=True)
            raise ApprovalExpired(
                f"Approval {request.id} expired at {request.expires_at}",
                approval_id=request.id,
            )

        if (
            decision.approved
            and request.requires_confirmation_phrase
            and decision.confirmation_phrase != request.confirmation_phrase
        ):
            raise ScrappyError(
                "Destructive operations require the exact confirmation phrase",
                approval_id=request.id,
                expected=request.confirmation_phrase,
            )

        request.state = ApprovalState.APPROVED if decision.approved else ApprovalState.DENIED
        await self._update_state(request, decision)

        logger.info(
            "approval_resolved",
            approval_id=request.id,
            task_id=request.task_id,
            approved=decision.approved,
            decided_by=decision.decided_by,
        )
        if self._bus is not None:
            await emit(
                self._bus,
                EventType.APPROVAL_RESOLVED,
                task_id=request.task_id,
                component="approvals",
                approval_id=request.id,
                approved=decision.approved,
                decided_by=decision.decided_by,
                tool_name=request.tool_name,
            )

        waiter = self._waiters.pop(request.id, None)
        if waiter is not None and not waiter.done():
            waiter.set_result(decision)
        return request

    async def wait_for(self, approval_id: str, *, timeout: float) -> ApprovalDecision:
        """Block until a decision arrives, the request expires, or time runs out.

        Used by the API path, where a human answers out of band. The CLI
        prompts inline and calls :meth:`resolve` directly.
        """
        existing = await self.get(approval_id)
        if existing is None:
            raise ApprovalNotFound(f"No approval request {approval_id}", approval_id=approval_id)
        if existing.state is ApprovalState.APPROVED:
            return ApprovalDecision(request_id=approval_id, approved=True, decided_by="stored")
        if existing.state in {ApprovalState.DENIED, ApprovalState.EXPIRED}:
            return ApprovalDecision(request_id=approval_id, approved=False, decided_by="stored")

        loop = asyncio.get_running_loop()
        waiter: asyncio.Future[ApprovalDecision] = loop.create_future()
        self._waiters[approval_id] = waiter
        try:
            return await asyncio.wait_for(waiter, timeout=timeout)
        except TimeoutError:
            await self.expire(approval_id)
            return ApprovalDecision(
                request_id=approval_id,
                approved=False,
                decided_by="timeout",
                note=f"no answer within {timeout:.0f}s",
            )
        finally:
            self._waiters.pop(approval_id, None)

    async def consume(self, approval_id: str) -> ApprovalRequest:
        """Spend an approval. Single use, enforced here and nowhere else.

        Called immediately before execution. Any state other than APPROVED -
        including an approval that was already used - raises.
        """
        request = await self.get(approval_id)
        if request is None:
            raise ApprovalNotFound(f"No approval request {approval_id}", approval_id=approval_id)
        if request.state is not ApprovalState.APPROVED:
            raise ScrappyError(
                f"Approval {approval_id} is {request.state}, not approved",
                approval_id=approval_id,
                state=str(request.state),
            )
        if request.is_expired():
            request.state = ApprovalState.EXPIRED
            await self._store.execute(
                "UPDATE approvals SET state = ? WHERE id = ?",
                (str(ApprovalState.EXPIRED), approval_id),
            )
            raise ApprovalExpired(
                f"Approval {approval_id} expired before it was used", approval_id=approval_id
            )
        request.state = ApprovalState.CONSUMED
        await self._store.execute(
            "UPDATE approvals SET state = ? WHERE id = ?",
            (str(ApprovalState.CONSUMED), approval_id),
        )
        return request

    async def expire(self, approval_id: str) -> None:
        await self._store.execute(
            "UPDATE approvals SET state = ? WHERE id = ? AND state = ?",
            (str(ApprovalState.EXPIRED), approval_id, str(ApprovalState.PENDING)),
        )

    # -- queries ------------------------------------------------------------

    async def get(self, approval_id: str) -> ApprovalRequest | None:
        row = await self._store.fetch_one("SELECT * FROM approvals WHERE id = ?", (approval_id,))
        return _row_to_request(row) if row else None

    async def pending(self, *, task_id: str | None = None) -> list[ApprovalRequest]:
        if task_id:
            rows = await self._store.fetch_all(
                "SELECT * FROM approvals WHERE state = ? AND task_id = ? ORDER BY requested_at",
                (str(ApprovalState.PENDING), task_id),
            )
        else:
            rows = await self._store.fetch_all(
                "SELECT * FROM approvals WHERE state = ? ORDER BY requested_at",
                (str(ApprovalState.PENDING),),
            )
        return [_row_to_request(row) for row in rows]

    # -- persistence --------------------------------------------------------

    async def _persist(self, request: ApprovalRequest) -> None:
        await self._store.execute(
            """
            INSERT INTO approvals (
                id, task_id, call_id, tool_name, arguments, risk, reason,
                summary, requested_at, expires_at, state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.id,
                request.task_id,
                request.call_id,
                request.tool_name,
                dumps(request.arguments),
                str(request.risk),
                request.reason,
                request.summary,
                request.requested_at.isoformat(),
                request.expires_at.isoformat() if request.expires_at else None,
                str(request.state),
            ),
        )

    async def _update_state(
        self, request: ApprovalRequest, decision: ApprovalDecision, *, expired: bool = False
    ) -> None:
        await self._store.execute(
            "UPDATE approvals SET state = ?, decided_by = ?, decided_at = ?, note = ? WHERE id = ?",
            (
                str(request.state),
                decision.decided_by,
                decision.decided_at.isoformat(),
                "expired before decision" if expired else decision.note,
                request.id,
            ),
        )


def describe_operation(tool_name: str, arguments: dict[str, Any]) -> str:
    """One line a human can judge without reading JSON.

    The summary is what an operator actually sees at the prompt, so it must
    describe the *exact* operation - vague summaries make approval meaningless.
    """
    safe = redact(arguments)
    if tool_name == "shell.run":
        argv = safe.get("argv") or []
        rendered = " ".join(str(part) for part in argv) if isinstance(argv, list) else str(argv)
        return f"run: {rendered}"
    if tool_name.startswith("fs."):
        path = safe.get("path") or safe.get("source") or "?"
        action = tool_name.split(".", 1)[1]
        return f"{action} {path}"
    if tool_name == "http.get":
        return f"HTTP GET {safe.get('url', '?')}"
    if tool_name == "process.kill":
        return f"send signal {safe.get('signal', 'TERM')} to pid {safe.get('pid', '?')}"
    try:
        rendered_args = json.dumps(safe, sort_keys=True, default=str)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        rendered_args = str(safe)
    return f"{tool_name} {rendered_args[:200]}"


def render_prompt(request: ApprovalRequest, *, objective: str = "") -> str:
    """The block shown at a terminal when policy stops for a human."""
    lines = [
        "",
        "  Approval required",
        f"  Task:   {objective or request.task_id}",
        f"  Action: {request.summary}",
        f"  Risk:   {str(request.risk).upper()}",
        f"  Reason: {request.reason}",
    ]
    if request.expires_at:
        lines.append(f"  Expires: {request.expires_at.isoformat(timespec='seconds')}")
    if request.requires_confirmation_phrase:
        lines.append(f"  This is DESTRUCTIVE. Type exactly: {request.confirmation_phrase}")
    lines.append("")
    return "\n".join(lines)


def _row_to_request(row: dict[str, Any]) -> ApprovalRequest:
    from datetime import datetime

    return ApprovalRequest(
        id=row["id"],
        task_id=row["task_id"],
        call_id=row["call_id"],
        tool_name=row["tool_name"],
        arguments=loads(row["arguments"]),
        risk=RiskLevel(row["risk"]),
        reason=row["reason"],
        summary=row["summary"],
        requested_at=datetime.fromisoformat(row["requested_at"]),
        expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
        state=ApprovalState(row["state"]),
        requires_confirmation_phrase=RiskLevel(row["risk"]) is RiskLevel.DESTRUCTIVE,
        confirmation_phrase=(
            CONFIRMATION_PHRASE if RiskLevel(row["risk"]) is RiskLevel.DESTRUCTIVE else None
        ),
    )


__all__ = [
    "CONFIRMATION_PHRASE",
    "ApprovalManager",
    "ApprovalNotFound",
    "describe_operation",
    "render_prompt",
]
