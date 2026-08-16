"""Persistence for credentials.

A protocol plus one SQLite implementation. The protocol exists so the
authenticator depends on "somewhere credentials live" rather than on SQLite:
when node identities or a shared control plane arrive, they implement this and
nothing above changes. It is a seam that already has a second implementation in
view, not speculative abstraction.

Nothing here decides whether a credential may authenticate. The store reads and
writes rows; :mod:`scrappy_os.security.authn` decides. Keeping that split means
there is exactly one place where "is this usable" is answered, and it cannot be
bypassed by a query that forgot a ``WHERE`` clause.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from scrappy_os.core.identity import ActorType, AuthMethod, Scope
from scrappy_os.memory.store import Store, StoreError
from scrappy_os.observability.logging import get_logger
from scrappy_os.security.credentials import Credential, CredentialError

logger = get_logger("security.credential_store")


def _row_to_credential(row: dict[str, Any]) -> Credential:
    """Rebuild a credential from a database row.

    Unknown scope strings are dropped rather than raising. A scope that no
    longer exists in this build cannot be granted by definition, so the safe
    reading of an unrecognised name is "this credential does not have it" -
    which is what dropping it produces. Refusing to load the row instead would
    turn a removed scope into an outage, and would make a credential
    unrevokable through the CLI at exactly the wrong moment.
    """
    stored = json.loads(row["scopes"])
    scopes: set[Scope] = set()
    for name in stored:
        try:
            scopes.add(Scope(name))
        except ValueError:
            logger.warning(
                "credential_unknown_scope_dropped",
                credential_id=row["credential_id"],
                scope=str(name),
            )

    def _at(key: str) -> datetime | None:
        raw = row.get(key)
        return datetime.fromisoformat(raw).astimezone(UTC) if raw else None

    created = _at("created_at")
    if created is None:  # pragma: no cover - NOT NULL in the schema
        raise CredentialError(f"credential {row['credential_id']} has no created_at")

    return Credential(
        credential_id=row["credential_id"],
        actor_id=row["actor_id"],
        actor_type=ActorType(row["actor_type"]),
        display_name=row["display_name"],
        scopes=frozenset(scopes),
        verifier=row["verifier"],
        created_at=created,
        expires_at=_at("expires_at"),
        revoked_at=_at("revoked_at"),
        last_used_at=_at("last_used_at"),
        auth_method=AuthMethod(row["auth_method"]),
        metadata=json.loads(row["metadata"]),
    )


def _credential_params(credential: Credential) -> tuple[Any, ...]:
    return (
        credential.credential_id,
        credential.actor_id,
        str(credential.actor_type),
        credential.display_name,
        json.dumps(sorted(str(scope) for scope in credential.scopes)),
        credential.verifier,
        credential.created_at.isoformat(),
        credential.expires_at.isoformat() if credential.expires_at else None,
        credential.revoked_at.isoformat() if credential.revoked_at else None,
        credential.last_used_at.isoformat() if credential.last_used_at else None,
        str(credential.auth_method),
        json.dumps(credential.metadata),
    )


_INSERT = """
    INSERT INTO credentials (
        credential_id, actor_id, actor_type, display_name, scopes, verifier,
        created_at, expires_at, revoked_at, last_used_at, auth_method, metadata
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


@runtime_checkable
class CredentialStore(Protocol):
    """Where credentials live. Implementations must not interpret status."""

    async def create(self, credential: Credential) -> None:
        """Persist a new credential. Raises if the id already exists."""

    async def get(self, credential_id: str) -> Credential | None:
        """One credential by id, whatever its state, or None."""

    async def list(self, *, actor_id: str | None = None) -> list[Credential]:
        """Every credential, newest first, optionally narrowed to one actor."""

    async def revoke(self, credential_id: str, *, when: datetime) -> Credential | None:
        """Mark a credential revoked. Returns the updated row, or None."""

    async def update_last_used(self, credential_id: str, *, when: datetime) -> None:
        """Record a successful authentication."""

    async def rotate(
        self, credential_id: str, replacement: Credential, *, revoke_old_at: datetime | None
    ) -> Credential | None:
        """Atomically add ``replacement`` and optionally revoke the original."""


class SqliteCredentialStore:
    """Credentials in the same SQLite database as the audit trail.

    Same file on purpose: an operator backing up the audit trail gets the
    credentials that produced it, and the two cannot drift apart or be restored
    to inconsistent points in time.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    async def create(self, credential: Credential) -> None:
        try:
            await self._store.execute(_INSERT, _credential_params(credential))
        except StoreError as exc:
            raise CredentialError(
                f"could not store credential {credential.credential_id}: {exc}"
            ) from exc

    async def get(self, credential_id: str) -> Credential | None:
        row = await self._store.fetch_one(
            "SELECT * FROM credentials WHERE credential_id = ?", (credential_id,)
        )
        return _row_to_credential(row) if row else None

    async def list(self, *, actor_id: str | None = None) -> list[Credential]:
        if actor_id is None:
            rows = await self._store.fetch_all(
                "SELECT * FROM credentials ORDER BY created_at DESC"
            )
        else:
            rows = await self._store.fetch_all(
                "SELECT * FROM credentials WHERE actor_id = ? ORDER BY created_at DESC",
                (actor_id,),
            )
        return [_row_to_credential(row) for row in rows]

    async def revoke(self, credential_id: str, *, when: datetime) -> Credential | None:
        existing = await self.get(credential_id)
        if existing is None:
            return None
        if existing.revoked_at is not None:
            # Idempotent: re-revoking keeps the original timestamp, because the
            # moment authority was withdrawn is a fact and a second command
            # should not rewrite it.
            return existing
        await self._store.execute(
            "UPDATE credentials SET revoked_at = ? WHERE credential_id = ?",
            (when.isoformat(), credential_id),
        )
        return existing.with_revoked_at(when)

    async def update_last_used(self, credential_id: str, *, when: datetime) -> None:
        await self._store.execute(
            "UPDATE credentials SET last_used_at = ? WHERE credential_id = ?",
            (when.isoformat(), credential_id),
        )

    async def rotate(
        self, credential_id: str, replacement: Credential, *, revoke_old_at: datetime | None
    ) -> Credential | None:
        """Insert ``replacement`` and optionally revoke the original, atomically.

        Both statements share one transaction so the pair cannot half-apply. The
        failure this prevents is the expensive one: the original revoked and the
        replacement missing leaves an actor with no working credential and no
        way to authenticate to fix it.
        """
        existing = await self.get(credential_id)
        if existing is None:
            return None

        async with self._store.transaction() as conn:
            await conn.execute(_INSERT, _credential_params(replacement))
            if revoke_old_at is not None and existing.revoked_at is None:
                await conn.execute(
                    "UPDATE credentials SET revoked_at = ? WHERE credential_id = ?",
                    (revoke_old_at.isoformat(), credential_id),
                )
        return existing

    async def delete_many(self, credential_ids: Sequence[str]) -> int:
        """Remove rows outright. Only ``scrappy token prune`` calls this.

        Deletion loses history, which is why nothing on the authentication path
        can reach it: revocation is the normal end of a credential's life and it
        keeps the record.
        """
        if not credential_ids:
            return 0
        async with self._store.transaction() as conn:
            for credential_id in credential_ids:
                await conn.execute(
                    "DELETE FROM credentials WHERE credential_id = ?", (credential_id,)
                )
        return len(credential_ids)

    async def count_active(self, *, now: datetime) -> int:
        """How many credentials could authenticate right now."""
        credentials = await self.list()
        return sum(1 for credential in credentials if credential.is_usable_at(now))


__all__ = ["CredentialStore", "SqliteCredentialStore"]
