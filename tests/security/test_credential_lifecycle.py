"""Credential persistence and the administrative operations over it.

The store and the service are tested together because the properties worth
proving are joint ones: that a rotation cannot half-apply, that revocation is
recorded as well as applied, and that the only destructive command refuses to
touch anything still usable.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

from scrappy_os.core.enums import EventType
from scrappy_os.core.identity import Actor, ActorType, AuthMethod, Scope, local_cli_actor
from scrappy_os.memory.store import Store
from scrappy_os.security.audit import AuditLog
from scrappy_os.security.credential_service import (
    CredentialNotFound,
    CredentialService,
)
from scrappy_os.security.credential_store import (
    CredentialStore,
    SqliteCredentialStore,
    SupportsDeletion,
)
from scrappy_os.security.credentials import (
    Credential,
    CredentialError,
    CredentialStatus,
    parse_token,
    verify_secret,
)

PEPPER = "lifecycle-pepper-long-enough"
NOW = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)


@pytest.fixture
def credential_store(store: Store) -> SqliteCredentialStore:
    return SqliteCredentialStore(store)


@pytest_asyncio.fixture
async def service(
    credential_store: SqliteCredentialStore, store: Store
) -> CredentialService:
    return CredentialService(
        credential_store, AuditLog(store), pepper=PEPPER, actor=local_cli_actor()
    )


async def _audit_types(store: Store) -> list[str]:
    rows = await store.fetch_all("SELECT event_type FROM audit_events ORDER BY id")
    return [row["event_type"] for row in rows]


class TestCreate:
    async def test_created_credential_is_readable_back(
        self, service: CredentialService
    ) -> None:
        issued = await service.create(
            actor_id="svc-ci",
            actor_type=ActorType.SERVICE,
            scopes=frozenset({Scope.TASK_CREATE}),
        )
        stored = await service.get(issued.credential.credential_id)
        assert stored.actor_id == "svc-ci"
        assert stored.scopes == frozenset({Scope.TASK_CREATE})

    async def test_the_raw_token_is_never_persisted(
        self, service: CredentialService, store: Store
    ) -> None:
        """The property the whole design exists for."""
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        rows = await store.fetch_all("SELECT * FROM credentials")
        assert issued.token not in str([dict(row) for row in rows])

        _, secret = parse_token(issued.token)
        assert secret not in str([dict(row) for row in rows])

    async def test_creation_is_audited_with_the_administrator(
        self, service: CredentialService, store: Store
    ) -> None:
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        assert str(EventType.CREDENTIAL_CREATED) in await _audit_types(store)

        row = await store.fetch_one(
            "SELECT * FROM audit_events WHERE event_type = ?",
            (str(EventType.CREDENTIAL_CREATED),),
        )
        assert row is not None
        assert issued.credential.credential_id in row["payload"]
        assert issued.token not in str(dict(row))

    async def test_scopes_survive_a_round_trip_through_sqlite(
        self, service: CredentialService
    ) -> None:
        granted = frozenset({Scope.TASK_READ, Scope.AUDIT_READ, Scope.SYSTEM_READ})
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=granted
        )
        assert (await service.get(issued.credential.credential_id)).scopes == granted

    async def test_a_credential_records_who_created_it(
        self, service: CredentialService
    ) -> None:
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        assert issued.credential.metadata["created_by"] == local_cli_actor().id


class TestListing:
    async def test_listing_can_be_narrowed_to_one_actor(
        self, service: CredentialService
    ) -> None:
        await service.create(
            actor_id="alice", actor_type=ActorType.HUMAN, scopes=frozenset()
        )
        await service.create(
            actor_id="bob", actor_type=ActorType.HUMAN, scopes=frozenset()
        )
        assert len(await service.list()) == 2
        assert len(await service.list(actor_id="alice")) == 1

    async def test_missing_credential_raises_rather_than_returning_none(
        self, service: CredentialService
    ) -> None:
        with pytest.raises(CredentialNotFound):
            await service.get("cred_ffffffffffff")


class TestRevocation:
    async def test_revoked_credential_stops_being_usable(
        self, service: CredentialService
    ) -> None:
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        await service.revoke(issued.credential.credential_id)
        stored = await service.get(issued.credential.credential_id)
        assert stored.status_at(datetime.now(UTC)) is CredentialStatus.REVOKED
        assert not stored.is_usable_at(datetime.now(UTC))

    async def test_revocation_keeps_the_row_for_the_audit_trail(
        self, service: CredentialService
    ) -> None:
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        await service.revoke(issued.credential.credential_id)
        assert await service.get(issued.credential.credential_id) is not None

    async def test_revocation_is_idempotent_and_keeps_the_first_moment(
        self, service: CredentialService
    ) -> None:
        """When authority was withdrawn is a fact; a second command must not rewrite it."""
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        first = await service.revoke(issued.credential.credential_id, when=NOW)
        second = await service.revoke(
            issued.credential.credential_id, when=NOW + timedelta(days=1)
        )
        assert first.revoked_at == second.revoked_at == NOW

    async def test_revoking_an_unknown_credential_raises(
        self, service: CredentialService
    ) -> None:
        with pytest.raises(CredentialNotFound):
            await service.revoke("cred_ffffffffffff")

    async def test_revocation_is_audited(
        self, service: CredentialService, store: Store
    ) -> None:
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        await service.revoke(issued.credential.credential_id)
        assert str(EventType.CREDENTIAL_REVOKED) in await _audit_types(store)


class TestRotation:
    async def test_rotation_leaves_the_original_valid_by_default(
        self, service: CredentialService
    ) -> None:
        """Overlap is the point: clients move over before the old key dies."""
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        result = await service.rotate(issued.credential.credential_id)

        old = await service.get(issued.credential.credential_id)
        assert old.is_usable_at(datetime.now(UTC))
        assert result.issued.credential.credential_id != issued.credential.credential_id
        assert not result.previous_revoked

    async def test_rotation_can_revoke_the_original_immediately(
        self, service: CredentialService
    ) -> None:
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        await service.rotate(issued.credential.credential_id, revoke_previous=True)
        old = await service.get(issued.credential.credential_id)
        assert not old.is_usable_at(datetime.now(UTC))

    async def test_rotation_preserves_actor_and_scopes(
        self, service: CredentialService
    ) -> None:
        granted = frozenset({Scope.TASK_CREATE, Scope.TASK_READ})
        issued = await service.create(
            actor_id="svc-ci",
            actor_type=ActorType.SERVICE,
            scopes=granted,
            display_name="CI",
        )
        result = await service.rotate(issued.credential.credential_id)
        assert result.issued.credential.actor_id == "svc-ci"
        assert result.issued.credential.scopes == granted
        assert result.issued.credential.display_name == "CI"

    async def test_rotation_does_not_widen_scopes(
        self, service: CredentialService
    ) -> None:
        """Rotation replaces a key; it is not a route to more authority."""
        issued = await service.create(
            actor_id="svc",
            actor_type=ActorType.SERVICE,
            scopes=frozenset({Scope.TASK_READ}),
        )
        result = await service.rotate(issued.credential.credential_id)
        assert result.issued.credential.scopes == frozenset({Scope.TASK_READ})

    async def test_the_replacement_token_is_new_and_works(
        self, service: CredentialService
    ) -> None:
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        result = await service.rotate(issued.credential.credential_id)
        assert result.issued.token != issued.token
        _, secret = parse_token(result.issued.token)
        assert verify_secret(secret, result.issued.credential.verifier, pepper=PEPPER)

    async def test_rotation_records_what_it_replaced(
        self, service: CredentialService
    ) -> None:
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        result = await service.rotate(issued.credential.credential_id)
        assert (
            result.issued.credential.metadata["rotated_from"]
            == issued.credential.credential_id
        )

    async def test_rotating_an_unknown_credential_raises(
        self, service: CredentialService
    ) -> None:
        with pytest.raises(CredentialNotFound):
            await service.rotate("cred_ffffffffffff")

    async def test_rotation_with_revoke_audits_both_events(
        self, service: CredentialService, store: Store
    ) -> None:
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        await service.rotate(issued.credential.credential_id, revoke_previous=True)
        types = await _audit_types(store)
        assert str(EventType.CREDENTIAL_ROTATED) in types
        assert str(EventType.CREDENTIAL_REVOKED) in types


class TestRotationAtomicity:
    async def test_a_failed_insert_leaves_the_original_untouched(
        self, credential_store: SqliteCredentialStore, service: CredentialService
    ) -> None:
        """The expensive failure: old revoked, new missing, actor locked out.

        The insert is made to fail by reusing an id that already exists. Both
        statements share a transaction, so the revoke must roll back with it.
        """
        first = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        second = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )

        # A replacement carrying an id that is already taken.
        clashing = second.credential.model_copy(
            update={"credential_id": first.credential.credential_id}
        )

        with pytest.raises(Exception):  # noqa: B017 - any failure must roll back
            await credential_store.rotate(
                second.credential.credential_id, clashing, revoke_old_at=NOW
            )

        survivor = await credential_store.get(second.credential.credential_id)
        assert survivor is not None
        assert survivor.revoked_at is None, "revoke applied although the insert failed"
        assert survivor.is_usable_at(datetime.now(UTC))


class TestPrune:
    async def test_active_credentials_are_never_pruned(
        self, service: CredentialService
    ) -> None:
        """Old is not unwanted."""
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        removed = await service.prune(older_than=datetime.now(UTC) + timedelta(days=365))
        assert removed == []
        assert await service.get(issued.credential.credential_id) is not None

    async def test_revoked_credentials_past_the_cutoff_are_removed(
        self, service: CredentialService
    ) -> None:
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        await service.revoke(issued.credential.credential_id, when=NOW - timedelta(days=200))
        removed = await service.prune(older_than=NOW - timedelta(days=90), now=NOW)
        assert removed == [issued.credential.credential_id]
        with pytest.raises(CredentialNotFound):
            await service.get(issued.credential.credential_id)

    async def test_recently_revoked_credentials_are_kept(
        self, service: CredentialService
    ) -> None:
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        await service.revoke(issued.credential.credential_id, when=NOW - timedelta(days=5))
        assert await service.prune(older_than=NOW - timedelta(days=90), now=NOW) == []
        assert await service.get(issued.credential.credential_id) is not None

    async def test_pruning_keeps_the_audit_history(
        self, service: CredentialService, store: Store
    ) -> None:
        """The row goes; the story of it does not."""
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        await service.revoke(issued.credential.credential_id, when=NOW - timedelta(days=200))
        await service.prune(older_than=NOW - timedelta(days=90), now=NOW)

        types = await _audit_types(store)
        assert str(EventType.CREDENTIAL_CREATED) in types
        assert str(EventType.CREDENTIAL_REVOKED) in types
        assert str(EventType.CREDENTIAL_PRUNED) in types

    async def test_a_store_that_cannot_delete_refuses_loudly(
        self, store: Store
    ) -> None:
        """Reporting rows removed that are still there is the failure to avoid."""
        service = CredentialService(
            _UndeletableStore(SqliteCredentialStore(store)),
            AuditLog(store),
            pepper=PEPPER,
            actor=local_cli_actor(),
        )
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        await service.revoke(issued.credential.credential_id, when=NOW - timedelta(days=200))

        with pytest.raises(CredentialError, match="cannot delete"):
            await service.prune(older_than=NOW - timedelta(days=90), now=NOW)


class _UndeletableStore:
    """A credential store with no deletion support, delegating everything else."""

    def __init__(self, inner: SqliteCredentialStore) -> None:
        self._inner = inner

    async def create(self, credential: Credential) -> None:
        await self._inner.create(credential)

    async def get(self, credential_id: str) -> Credential | None:
        return await self._inner.get(credential_id)

    async def list(self, *, actor_id: str | None = None) -> list[Credential]:
        return await self._inner.list(actor_id=actor_id)

    async def revoke(self, credential_id: str, *, when: datetime) -> Credential | None:
        return await self._inner.revoke(credential_id, when=when)

    async def update_last_used(self, credential_id: str, *, when: datetime) -> None:
        await self._inner.update_last_used(credential_id, when=when)

    async def rotate(
        self,
        credential_id: str,
        replacement: Credential,
        *,
        revoke_old_at: datetime | None,
    ) -> Credential | None:
        return await self._inner.rotate(
            credential_id, replacement, revoke_old_at=revoke_old_at
        )


class TestStoreProtocols:
    def test_the_sqlite_store_satisfies_both_protocols(self, store: Store) -> None:
        instance = SqliteCredentialStore(store)
        assert isinstance(instance, CredentialStore)
        assert isinstance(instance, SupportsDeletion)

    def test_a_store_without_deletion_is_still_a_credential_store(
        self, store: Store
    ) -> None:
        """The seam that lets an append-only store be a legitimate implementation."""
        instance = _UndeletableStore(SqliteCredentialStore(store))
        assert isinstance(instance, CredentialStore)
        assert not isinstance(instance, SupportsDeletion)


class TestLastUsed:
    async def test_last_used_starts_empty_and_is_recorded(
        self, credential_store: SqliteCredentialStore, service: CredentialService
    ) -> None:
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        assert issued.credential.last_used_at is None

        await credential_store.update_last_used(
            issued.credential.credential_id, when=NOW
        )
        stored = await credential_store.get(issued.credential.credential_id)
        assert stored is not None
        assert stored.last_used_at == NOW


class TestUnknownScopeHandling:
    async def test_an_unrecognised_stored_scope_is_dropped_not_granted(
        self, credential_store: SqliteCredentialStore, service: CredentialService, store: Store
    ) -> None:
        """A scope this build does not know cannot be a grant.

        Dropping it yields "does not have that capability", which is the safe
        reading. Refusing to load the row would instead make the credential
        unrevokable at exactly the wrong moment.
        """
        issued = await service.create(
            actor_id="svc",
            actor_type=ActorType.SERVICE,
            scopes=frozenset({Scope.TASK_READ}),
        )
        await store.execute(
            "UPDATE credentials SET scopes = ? WHERE credential_id = ?",
            ('["task:read", "galaxy:destroy"]', issued.credential.credential_id),
        )
        reloaded = await credential_store.get(issued.credential.credential_id)
        assert reloaded is not None
        assert reloaded.scopes == frozenset({Scope.TASK_READ})


class TestAdministratorAttribution:
    async def test_audit_names_the_administrator_not_only_the_subject(
        self, store: Store
    ) -> None:
        """'A credential was issued' is not enough; who issued it matters."""
        admin = Actor(
            id="ops-alice",
            actor_type=ActorType.HUMAN,
            display_name="Alice",
            scopes=frozenset(Scope),
            auth_method=AuthMethod.LOCAL_PROCESS,
        )
        service = CredentialService(
            SqliteCredentialStore(store), AuditLog(store), pepper=PEPPER, actor=admin
        )
        await service.create(
            actor_id="svc-new", actor_type=ActorType.SERVICE, scopes=frozenset()
        )

        row = await store.fetch_one(
            "SELECT * FROM audit_events WHERE event_type = ?",
            (str(EventType.CREDENTIAL_CREATED),),
        )
        assert row is not None
        assert row["actor_id"] == "ops-alice"
        assert "ops-alice" in row["payload"]
        # and the credential the event is *about* is the subject, not the admin
        assert "svc-new" in row["payload"]
