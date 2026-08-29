"""SYNCBOND-aware HTTP wrapper for the existing Scrappy OS API.

The execution API remains the authority for authentication, scopes, risk policy,
approvals and task execution.  This module adds only continuity metadata at the
ASGI boundary:

* validate optional SYNCBOND task headers;
* associate a caller-provided correlation UUID with an accepted objective;
* return that correlation on task creation/status;
* enrich SSE task events with the same correlation.

A correlation id is never invented for a standalone request.  That distinction
matters: no protocol metadata is better than a false continuity claim.
"""

from __future__ import annotations

import json
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from typing import Any
from uuid import UUID

from fastapi import FastAPI
from starlette.types import Message, Receive, Scope, Send

from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.syncbond import SYNCBOND_VERSION
from scrappy_os.interface.api import MAX_TRACKED_TASKS, create_app as create_base_app

_HEADER_CORRELATION = b"x-syncbond-correlation-id"
_HEADER_VERSION = b"x-syncbond-version"


def _headers(scope: Scope) -> dict[bytes, bytes]:
    return {key.lower(): value for key, value in scope.get("headers", [])}


def _task_id_from_path(path: str) -> str | None:
    parts = path.strip("/").split("/")
    if len(parts) >= 2 and parts[0] == "tasks" and parts[1]:
        return parts[1]
    return None


def _replace_content_length(headers: list[tuple[bytes, bytes]], length: int) -> list[tuple[bytes, bytes]]:
    kept = [(key, value) for key, value in headers if key.lower() != b"content-length"]
    kept.append((b"content-length", str(length).encode("ascii")))
    return kept


class SyncbondTaskMiddleware:
    """Pure-ASGI continuity metadata layer; deliberately no execution authority."""

    def __init__(self, app: Callable[..., Awaitable[None]]) -> None:
        self.app = app
        self._correlations: OrderedDict[str, str] = OrderedDict()

    def _remember(self, objective_id: str, correlation_id: str) -> None:
        self._correlations[objective_id] = correlation_id
        self._correlations.move_to_end(objective_id)
        while len(self._correlations) > MAX_TRACKED_TASKS:
            self._correlations.popitem(last=False)

    @staticmethod
    def _validated_task_headers(scope: Scope) -> tuple[str | None, str | None]:
        headers = _headers(scope)
        raw_version = headers.get(_HEADER_VERSION)
        raw_correlation = headers.get(_HEADER_CORRELATION)

        version = raw_version.decode("ascii", errors="replace").strip() if raw_version else None
        if version is not None and version != SYNCBOND_VERSION:
            raise ValueError(
                f"unsupported SYNCBOND version {version!r}; supported version is {SYNCBOND_VERSION}"
            )

        if raw_correlation is None:
            return None, version
        text = raw_correlation.decode("ascii", errors="replace").strip()
        try:
            correlation = str(UUID(text))
        except (ValueError, AttributeError) as exc:
            raise ValueError("X-Syncbond-Correlation-ID must be a UUID") from exc
        return correlation, version

    async def _bad_request(self, send: Send, detail: str) -> None:
        body = json.dumps({"detail": detail}, separators=(",", ":")).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 400,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = str(scope.get("method", "GET")).upper()
        path = str(scope.get("path", ""))
        is_create = method == "POST" and path == "/tasks"
        task_id = _task_id_from_path(path)
        is_events = method == "GET" and task_id is not None and path.endswith("/events")
        is_status = method == "GET" and task_id is not None and not is_events

        submitted_correlation: str | None = None
        if is_create:
            try:
                submitted_correlation, _ = self._validated_task_headers(scope)
            except ValueError as exc:
                await self._bad_request(send, str(exc))
                return

        if is_events:
            correlation = self._correlations.get(task_id or "")
            if correlation is None:
                await self.app(scope, receive, send)
                return
            await self._stream_events(scope, receive, send, correlation)
            return

        if is_create or is_status:
            correlation = submitted_correlation if is_create else self._correlations.get(task_id or "")
            await self._buffer_json_response(
                scope,
                receive,
                send,
                correlation=correlation,
                remember_creation=is_create,
            )
            return

        await self.app(scope, receive, send)

    async def _buffer_json_response(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        correlation: str | None,
        remember_creation: bool,
    ) -> None:
        start: Message | None = None
        chunks: list[bytes] = []

        async def capture(message: Message) -> None:
            nonlocal start
            if message["type"] == "http.response.start":
                start = message
                return
            if message["type"] != "http.response.body":
                await send(message)
                return
            chunks.append(message.get("body", b""))
            if message.get("more_body", False):
                return

            if start is None:
                raise RuntimeError("response body arrived before response start")
            status = int(start["status"])
            body = b"".join(chunks)
            content_type = next(
                (
                    value.decode("latin-1")
                    for key, value in start.get("headers", [])
                    if key.lower() == b"content-type"
                ),
                "",
            )
            if status < 400 and "application/json" in content_type:
                try:
                    payload = json.loads(body)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    payload = None
                if isinstance(payload, dict):
                    if remember_creation:
                        objective_id = str(payload.get("objective_id") or "").strip()
                        if objective_id and correlation is not None:
                            self._remember(objective_id, correlation)
                    payload["correlation_id"] = correlation
                    if correlation is not None:
                        payload["syncbond_version"] = SYNCBOND_VERSION
                    body = json.dumps(payload, default=str, separators=(",", ":")).encode("utf-8")

            outgoing = dict(start)
            outgoing["headers"] = _replace_content_length(list(start.get("headers", [])), len(body))
            await send(outgoing)
            await send({"type": "http.response.body", "body": body, "more_body": False})

        await self.app(scope, receive, capture)

    async def _stream_events(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        correlation: str,
    ) -> None:
        pending = bytearray()

        async def transform(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (key, value)
                    for key, value in message.get("headers", [])
                    if key.lower() != b"content-length"
                ]
                outgoing = dict(message)
                outgoing["headers"] = headers
                await send(outgoing)
                return
            if message["type"] != "http.response.body":
                await send(message)
                return

            pending.extend(message.get("body", b""))
            while b"\n\n" in pending:
                block, _, rest = pending.partition(b"\n\n")
                pending.clear()
                pending.extend(rest)
                await send(
                    {
                        "type": "http.response.body",
                        "body": self._enrich_sse_block(block, correlation) + b"\n\n",
                        "more_body": True,
                    }
                )

            if not message.get("more_body", False):
                if pending:
                    await send(
                        {
                            "type": "http.response.body",
                            "body": self._enrich_sse_block(bytes(pending), correlation),
                            "more_body": True,
                        }
                    )
                    pending.clear()
                await send({"type": "http.response.body", "body": b"", "more_body": False})

        await self.app(scope, receive, transform)

    @staticmethod
    def _enrich_sse_block(block: bytes, correlation: str) -> bytes:
        if not block.startswith(b"data: "):
            return block
        try:
            payload = json.loads(block[6:])
        except (json.JSONDecodeError, UnicodeDecodeError):
            return block
        if not isinstance(payload, dict):
            return block
        payload["correlation_id"] = correlation
        payload["syncbond_version"] = SYNCBOND_VERSION
        return b"data: " + json.dumps(payload, default=str, separators=(",", ":")).encode("utf-8")


def create_app(settings: ScrappySettings | None = None, *, with_heartbeat: bool = True) -> FastAPI:
    """Build the normal API plus the additive SYNCBOND continuity middleware."""

    app = create_base_app(settings, with_heartbeat=with_heartbeat)
    app.add_middleware(SyncbondTaskMiddleware)
    return app


__all__ = ["SyncbondTaskMiddleware", "create_app"]
