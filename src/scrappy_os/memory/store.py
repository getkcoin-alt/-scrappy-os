"""Durable local state: one SQLite file, opened once, migrated on connect.

SQLite is enough for a single-node v0.1 and has the property that matters most
here - the audit trail survives a crash without any daemon being up. The schema
is deliberately narrow and the access layer is a thin typed wrapper, so moving
to Postgres later means writing a second :class:`Store` implementation rather
than unpicking ORM models.

WAL is enabled so a long-running write never blocks ``scrappy audit``.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import aiosqlite

from scrappy_os.core.errors import ScrappyError
from scrappy_os.observability.logging import get_logger

logger = get_logger("store")

SCHEMA_VERSION = 2

#: Columns added after v1, applied to databases that predate them.
#: Additive only: this mechanism can introduce a nullable column and nothing
#: else. Anything that rewrites or drops data belongs in a real migration with a
#: backup step, not in a startup path that runs unattended.
ADDITIVE_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("audit_events", "actor_id", "TEXT"),
    ("audit_events", "actor_type", "TEXT"),
    ("audit_events", "auth_method", "TEXT"),
    ("tool_calls", "actor_id", "TEXT"),
    ("tool_calls", "actor_type", "TEXT"),
    ("approvals", "decided_by_actor_id", "TEXT"),
)

SCHEMA_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS schema_meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tasks (
        id            TEXT PRIMARY KEY,
        objective     TEXT NOT NULL,
        actor         TEXT NOT NULL,
        state         TEXT NOT NULL,
        created_at    TEXT NOT NULL,
        updated_at    TEXT NOT NULL,
        finished_at   TEXT,
        summary       TEXT,
        error         TEXT,
        max_risk      TEXT NOT NULL DEFAULT 'read',
        model_calls   INTEGER NOT NULL DEFAULT 0,
        replan_count  INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_events (
        id             TEXT PRIMARY KEY,
        timestamp      TEXT NOT NULL,
        event_type     TEXT NOT NULL,
        task_id        TEXT,
        actor          TEXT NOT NULL,
        component      TEXT NOT NULL,
        tool_name      TEXT,
        risk           TEXT,
        decision       TEXT,
        success        INTEGER,
        duration_ms    REAL,
        payload        TEXT NOT NULL,
        payload_sha256 TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tool_calls (
        id              TEXT PRIMARY KEY,
        task_id         TEXT NOT NULL,
        step_id         TEXT,
        tool_name       TEXT NOT NULL,
        arguments       TEXT NOT NULL,
        actor           TEXT NOT NULL,
        requested_at    TEXT NOT NULL,
        risk_level      TEXT NOT NULL,
        policy_decision TEXT,
        policy_rule     TEXT,
        approval_id     TEXT,
        approval_state  TEXT,
        success         INTEGER,
        duration_ms     REAL,
        error           TEXT,
        output_sha256   TEXT,
        output_preview  TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS approvals (
        id           TEXT PRIMARY KEY,
        task_id      TEXT NOT NULL,
        call_id      TEXT,
        tool_name    TEXT NOT NULL,
        arguments    TEXT NOT NULL,
        risk         TEXT NOT NULL,
        reason       TEXT NOT NULL,
        summary      TEXT NOT NULL,
        requested_at TEXT NOT NULL,
        expires_at   TEXT,
        state        TEXT NOT NULL,
        decided_by   TEXT,
        decided_at   TEXT,
        note         TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS observations (
        id         TEXT PRIMARY KEY,
        task_id    TEXT NOT NULL,
        call_id    TEXT,
        created_at TEXT NOT NULL,
        source     TEXT NOT NULL,
        success    INTEGER NOT NULL,
        content    TEXT NOT NULL,
        metadata   TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS plans (
        id         TEXT PRIMARY KEY,
        task_id    TEXT NOT NULL,
        author     TEXT NOT NULL,
        revision   INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        approved   INTEGER NOT NULL DEFAULT 0,
        reasoning  TEXT NOT NULL,
        steps      TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_audit_task ON audit_events(task_id, timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(timestamp DESC)",
    "CREATE INDEX IF NOT EXISTS idx_calls_task ON tool_calls(task_id, requested_at)",
    "CREATE INDEX IF NOT EXISTS idx_obs_task ON observations(task_id, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_approvals_state ON approvals(state, requested_at)",
    "CREATE INDEX IF NOT EXISTS idx_plans_task ON plans(task_id, revision)",
)


class StoreError(ScrappyError):
    """The durable store could not be read or written."""


async def _apply_additive_columns(conn: aiosqlite.Connection) -> None:
    """Add any :data:`ADDITIVE_COLUMNS` a pre-existing database is missing.

    ``CREATE TABLE IF NOT EXISTS`` does nothing for a table that already exists,
    so a v0.1 database upgraded in place would silently lack the identity
    columns and every actor would read as NULL. Existing rows keep that NULL,
    which is the truth: those actions predate identity being recorded.
    """
    for table, column, column_type in ADDITIVE_COLUMNS:
        cursor = await conn.execute(f"PRAGMA table_info({table})")
        existing = {str(row[1]) for row in await cursor.fetchall()}
        await cursor.close()
        if column in existing:
            continue
        # Table and column names are module constants, never user input.
        await conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")
        logger.info("schema_column_added", table=table, column=column)


class Store:
    """Async SQLite access. One instance per process, shared by every subsystem.

    Not a general query interface on purpose: callers get typed methods on the
    audit log and memory classes, which keeps SQL in one place.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._conn: aiosqlite.Connection | None = None

    @property
    def path(self) -> Path:
        return self._path

    @property
    def is_open(self) -> bool:
        return self._conn is not None

    async def connect(self) -> Self:
        """Open the database and apply the schema. Safe to call twice."""
        if self._conn is not None:
            return self
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            conn = await aiosqlite.connect(self._path)
            conn.row_factory = aiosqlite.Row
            await conn.execute("PRAGMA journal_mode=WAL")
            await conn.execute("PRAGMA synchronous=NORMAL")
            await conn.execute("PRAGMA foreign_keys=ON")
            for statement in SCHEMA_STATEMENTS:
                await conn.execute(statement)
            await _apply_additive_columns(conn)
            await conn.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('version', ?)",
                (str(SCHEMA_VERSION),),
            )
            await conn.commit()
        except (OSError, aiosqlite.Error) as exc:
            raise StoreError(f"Cannot open state database at {self._path}: {exc}") from exc

        self._conn = conn
        # 0600: the audit trail records what the machine was asked to do.
        try:
            self._path.chmod(0o600)
        except OSError:  # pragma: no cover - e.g. exotic filesystems
            logger.warning("store_chmod_failed", path=str(self._path))
        logger.debug("store_connected", path=str(self._path), schema_version=SCHEMA_VERSION)
        return self

    async def close(self) -> None:
        if self._conn is None:
            return
        await self._conn.close()
        self._conn = None

    def _require(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise StoreError("Store is not connected; call connect() first")
        return self._conn

    async def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        conn = self._require()
        try:
            await conn.execute(sql, tuple(params))
            await conn.commit()
        except aiosqlite.Error as exc:
            raise StoreError(f"Write failed: {exc}", sql=sql.split("(")[0].strip()) from exc

    async def fetch_all(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        conn = self._require()
        try:
            async with conn.execute(sql, tuple(params)) as cursor:
                rows = await cursor.fetchall()
        except aiosqlite.Error as exc:
            raise StoreError(f"Read failed: {exc}", sql=sql.split("FROM")[0].strip()) from exc
        return [dict(row) for row in rows]

    async def fetch_one(self, sql: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
        rows = await self.fetch_all(sql, params)
        return rows[0] if rows else None

    async def health_check(self) -> tuple[bool, str]:
        """Cheap liveness probe used by ``scrappy doctor`` and ``/health``."""
        try:
            row = await self.fetch_one("SELECT value FROM schema_meta WHERE key='version'")
        except StoreError as exc:
            return False, str(exc)
        if row is None:
            return False, "schema_meta is empty; database may be corrupt"
        return True, f"schema v{row['value']} at {self._path}"

    async def __aenter__(self) -> Self:
        return await self.connect()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()


@asynccontextmanager
async def open_store(path: Path) -> AsyncIterator[Store]:
    """Context-managed store, for CLI commands that need one-shot access."""
    store = Store(path)
    try:
        await store.connect()
        yield store
    finally:
        await store.close()


def dumps(value: Any) -> str:
    """JSON encoding used for every blob column. Deterministic and lossy-safe."""
    return json.dumps(value, default=str, sort_keys=True, ensure_ascii=False)


def loads(value: str | None) -> Any:
    """Decode a blob column, tolerating rows written by an older version."""
    if not value:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {"_unparseable": value[:500]}


__all__ = ["SCHEMA_VERSION", "Store", "StoreError", "dumps", "loads", "open_store"]
