"""Credential lifecycle operations, each one audited.

Every way a credential comes into existence, changes state or leaves goes through
this class. Putting them together is what makes "administrative changes to
authority are always recorded" a property of the design rather than a habit: the
store below it has no idea what an audit log is, and the CLI above it cannot
reach the store directly.

Authority to call any of this is the local-process boundary. Whoever runs
``scrappy token`` can already read the database, the pepper and the environment
file, so a credential check here would be theatre. That is documented in
``docs/CREDENTIALS.md`` rather than enforced, because pretending otherwise would
be the more dangerous choice.
"""

from __future__ import annotations

import builtins
from dataclasses import dataclass
from datetime import UTC, datetime

from scrappy_os.core.enums import EventType
from scrappy_os.core.identity import Actor, ActorType, Scope
from scrappy_os.core.models import AuditEvent
from scrappy_os.observability.logging import get_logger
from scrappy_os.security.audit import AuditLog
from scrappy_os.security.credential_store import CredentialStore, SupportsDeletion
from scrappy_os.security.credentials import (
    Credential,
    CredentialError,
    CredentialStatus,
    IssuedCredential,
    issue_credential,
)

logger = get_logger("security.credential_service")


class CredentialNotFound(CredentialError):
    """No credential with that id. Raised to a local operator, never to a client."""


@dataclass(frozen=True, slots=True)
class RotationResult:
    """What a rotation produced.

    ``previous`` is returned so a caller can tell the operator whether the old
    credential is still live, which is the entire point of overlap rotation.
    """

    issued: IssuedCredential
    previous: Credential
    previous_revoked: bool


class CredentialService:
    """Create, inspect, rotate and revoke credentials, writing audit as it goes."""

    def __init__(
        self,
        store: CredentialStore,
        audit: AuditLog,
        *,
        pepper: str,
        actor: Actor,
    ) -> None:
        self._store = store
        self._audit = audit
        self._pepper = pepper
        #: Who is performing the administration. Recorded on every event so the
        #: audit trail answers "who issued this credential", not just "one was
        #: issued".
        self._actor = actor

    async def _record(
        self,
        event_type: EventType,
        credential: Credential,
        **extra: object,
    ) -> None:
        # audit_fields() carries actor_scopes, which is payload detail rather
        # than a column on AuditEvent. Only the three identity columns are
        # promoted; the rest travels in the payload.
        identity = self._actor.audit_fields()
        await self._audit.record(
            AuditEvent(
                event_type=event_type,
                actor=self._actor.label,
                component="credentials",
                actor_id=identity["actor_id"],
                actor_type=identity["actor_type"],
                auth_method=identity["auth_method"],
                payload={
                    **credential.audit_fields(),
                    "scopes": sorted(str(scope) for scope in credential.scopes),
                    "administered_by": self._actor.id,
                    "administrator_scopes": identity["actor_scopes"],
                    **extra,
                },
            )
        )

    async def create(
        self,
        *,
        actor_id: str,
        actor_type: ActorType,
        scopes: frozenset[Scope],
        display_name: str | None = None,
        expires_at: datetime | None = None,
    ) -> IssuedCredential:
        """Issue a credential. The returned token is the only time it exists."""
        issued = issue_credential(
            actor_id=actor_id,
            actor_type=actor_type,
            scopes=scopes,
            pepper=self._pepper,
            display_name=display_name,
            expires_at=expires_at,
            metadata={"created_by": self._actor.id},
        )
        await self._store.create(issued.credential)
        await self._record(EventType.CREDENTIAL_CREATED, issued.credential)
        logger.info(
            "credential_created",
            credential_id=issued.credential.credential_id,
            actor_id=actor_id,
            scope_count=len(scopes),
        )
        return issued

    async def get(self, credential_id: str) -> Credential:
        credential = await self._store.get(credential_id)
        if credential is None:
            raise CredentialNotFound(f"no credential with id {credential_id}")
        return credential

    async def list(self, *, actor_id: str | None = None) -> builtins.list[Credential]:
        return await self._store.list(actor_id=actor_id)

    async def revoke(self, credential_id: str, *, when: datetime | None = None) -> Credential:
        """Withdraw a credential. Takes effect on the next request, not on restart.

        Authentication reads the row every time, so there is no cache to
        invalidate and no window in which a revoked credential still works.
        """
        moment = when or datetime.now(UTC)
        updated = await self._store.revoke(credential_id, when=moment)
        if updated is None:
            raise CredentialNotFound(f"no credential with id {credential_id}")
        await self._record(EventType.CREDENTIAL_REVOKED, updated, revoked_at=moment.isoformat())
        logger.info("credential_revoked", credential_id=credential_id)
        return updated

    async def rotate(
        self,
        credential_id: str,
        *,
        revoke_previous: bool = False,
        expires_at: datetime | None = None,
        when: datetime | None = None,
    ) -> RotationResult:
        """Issue a replacement for the same actor and scopes.

        The default leaves the original valid. That is the whole point: a
        deployment updates its clients against the new token, confirms they
        work, and only then revokes the old one. Rotating by deleting first
        guarantees an outage of exactly the length of the operator's reaction
        time, which is why ``revoke_previous`` is opt-in.

        The insert and the optional revoke share one transaction, so the pair
        cannot half-apply and strand an actor with no working credential.
        """
        moment = when or datetime.now(UTC)
        existing = await self.get(credential_id)

        issued = issue_credential(
            actor_id=existing.actor_id,
            actor_type=existing.actor_type,
            scopes=existing.scopes,
            pepper=self._pepper,
            display_name=existing.display_name,
            expires_at=expires_at,
            metadata={"created_by": self._actor.id, "rotated_from": credential_id},
        )

        previous = await self._store.rotate(
            credential_id,
            issued.credential,
            revoke_old_at=moment if revoke_previous else None,
        )
        if previous is None:  # pragma: no cover - get() above already proved it exists
            raise CredentialNotFound(f"no credential with id {credential_id}")

        await self._record(
            EventType.CREDENTIAL_ROTATED,
            issued.credential,
            rotated_from=credential_id,
            previous_revoked=revoke_previous,
        )
        if revoke_previous:
            await self._record(
                EventType.CREDENTIAL_REVOKED,
                previous,
                revoked_at=moment.isoformat(),
                reason="rotation",
            )
        logger.info(
            "credential_rotated",
            credential_id=issued.credential.credential_id,
            rotated_from=credential_id,
            previous_revoked=revoke_previous,
        )
        return RotationResult(
            issued=issued, previous=previous, previous_revoked=revoke_previous
        )

    async def prune(
        self, *, older_than: datetime, now: datetime | None = None
    ) -> builtins.list[str]:
        """Delete revoked or expired credentials last relevant before ``older_than``.

        Retention rule, stated so it can be argued with: a credential is
        eligible only if it is *not* currently usable and the moment it stopped
        being usable is older than the cutoff. Active credentials are never
        touched regardless of age, because "old" is not "unwanted".

        This is the one operation that loses history. The audit events for the
        credential's creation and revocation remain - only the credential row
        goes - so the trail still explains what happened.
        """
        moment = now or datetime.now(UTC)
        doomed: builtins.list[Credential] = []
        for credential in await self._store.list():
            status = credential.status_at(moment)
            if status is CredentialStatus.ACTIVE:
                continue
            retired_at = credential.revoked_at or credential.expires_at
            if retired_at is not None and retired_at < older_than:
                doomed.append(credential)

        if not doomed:
            return []

        # Ask the store whether it can delete rather than testing for one
        # concrete class. The isinstance check this replaces meant any store
        # that was not SQLite skipped the deletion, still wrote
        # ``credential.pruned`` audit events, and still returned the ids - so
        # the operator was told records were gone while they were all still
        # there. Refusing outright is the honest failure.
        if not isinstance(self._store, SupportsDeletion):
            raise CredentialError(
                f"{type(self._store).__name__} cannot delete credentials, so there is "
                "nothing to prune. Revoked credentials remain valid audit history; "
                "no records were removed."
            )
        await self._store.delete_many([c.credential_id for c in doomed])
        for credential in doomed:
            await self._record(EventType.CREDENTIAL_PRUNED, credential)
        logger.info("credentials_pruned", count=len(doomed))
        return [credential.credential_id for credential in doomed]


__all__ = ["CredentialNotFound", "CredentialService", "RotationResult"]
