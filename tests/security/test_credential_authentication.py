"""Authenticating a stored credential, and every way that must fail.

The rule under test throughout: a client learns only that its credential was not
accepted. Unparseable, no such id, wrong secret, revoked and expired are five
genuinely different events for an operator, and exactly one answer for a caller.
Distinguishing them over the wire is a credential-enumeration oracle, and
distinguishing "revoked" would tell a thief when they were noticed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from pydantic import SecretStr

from scrappy_os.core.identity import ActorType, AuthMethod, Scope, local_cli_actor
from scrappy_os.memory.store import Store
from scrappy_os.security.audit import AuditLog
from scrappy_os.security.authn import (
    AuthenticationFailed,
    AuthFailureReason,
    CredentialAuthenticator,
    build_authenticator,
)
from scrappy_os.security.credential_service import CredentialService
from scrappy_os.security.credential_store import SqliteCredentialStore
from scrappy_os.security.credentials import Credential

PEPPER = "authentication-pepper-long-enough"


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


@pytest.fixture
def authenticator(credential_store: SqliteCredentialStore) -> CredentialAuthenticator:
    return CredentialAuthenticator(credential_store, pepper=PEPPER)


def bearer(token: str) -> str:
    return f"Bearer {token}"


class TestAcceptance:
    async def test_a_valid_token_authenticates_to_its_actor(
        self, service: CredentialService, authenticator: CredentialAuthenticator
    ) -> None:
        issued = await service.create(
            actor_id="svc-ci",
            actor_type=ActorType.SERVICE,
            scopes=frozenset({Scope.TASK_CREATE, Scope.TASK_READ}),
            display_name="CI runner",
        )
        actor = await authenticator.authenticate(bearer(issued.token))

        assert actor.id == "svc-ci"
        assert actor.actor_type is ActorType.SERVICE
        assert actor.display_name == "CI runner"
        assert actor.scopes == frozenset({Scope.TASK_CREATE, Scope.TASK_READ})
        assert actor.auth_method is AuthMethod.BEARER_TOKEN

    async def test_the_actor_carries_the_credential_that_proved_it(
        self, service: CredentialService, authenticator: CredentialAuthenticator
    ) -> None:
        """So an audit row can name the key, not just the principal."""
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        actor = await authenticator.authenticate(bearer(issued.token))
        assert actor.credential_id == issued.credential.credential_id

    async def test_display_name_is_optional(
        self, service: CredentialService, authenticator: CredentialAuthenticator
    ) -> None:
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        actor = await authenticator.authenticate(bearer(issued.token))
        assert actor.display_name is None


class TestLegacyAcceptance:
    async def test_legacy_token_authenticates_to_configured_identity(self) -> None:
        authenticator = build_authenticator(
            SecretStr("legacy-token-with-enough-entropy"),
            actor_id="legacy-service",
            scopes=frozenset({Scope.SYSTEM_READ}),
        )
        actor = await authenticator.authenticate("Bearer legacy-token-with-enough-entropy")
        assert actor.id == "legacy-service"
        assert actor.scopes == frozenset({Scope.SYSTEM_READ})
        assert actor.auth_method is AuthMethod.BEARER_TOKEN


class TestRejection:
    async def test_missing_authorization_is_refused(
        self, authenticator: CredentialAuthenticator
    ) -> None:
        with pytest.raises(AuthenticationFailed) as caught:
            await authenticator.authenticate(None)
        assert caught.value.reason is AuthFailureReason.MISSING

    async def test_non_bearer_authorization_is_refused(
        self, authenticator: CredentialAuthenticator
    ) -> None:
        with pytest.raises(AuthenticationFailed) as caught:
            await authenticator.authenticate("Basic abc")
        assert caught.value.reason is AuthFailureReason.MALFORMED

    async def test_empty_bearer_is_refused(self, authenticator: CredentialAuthenticator) -> None:
        with pytest.raises(AuthenticationFailed) as caught:
            await authenticator.authenticate("Bearer ")
        assert caught.value.reason is AuthFailureReason.MALFORMED

    async def test_a_malformed_credential_is_refused(
        self, authenticator: CredentialAuthenticator
    ) -> None:
        with pytest.raises(AuthenticationFailed) as caught:
            await authenticator.authenticate(bearer("not-a-scrappy-credential"))
        assert caught.value.reason is AuthFailureReason.MALFORMED

    async def test_an_unknown_credential_id_is_refused(
        self, authenticator: CredentialAuthenticator
    ) -> None:
        with pytest.raises(AuthenticationFailed) as caught:
            await authenticator.authenticate(bearer("scrp_a8f13e9c2b41_nosuchsecret"))
        assert caught.value.reason is AuthFailureReason.UNKNOWN_CREDENTIAL

    async def test_a_real_id_with_the_wrong_secret_is_refused(
        self, service: CredentialService, authenticator: CredentialAuthenticator
    ) -> None:
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        id_hex = issued.credential.credential_id.split("_", 1)[1]
        with pytest.raises(AuthenticationFailed) as caught:
            await authenticator.authenticate(bearer(f"scrp_{id_hex}_wrongsecret"))
        assert caught.value.reason is AuthFailureReason.UNKNOWN_CREDENTIAL

    async def test_a_revoked_credential_is_refused(
        self, service: CredentialService, authenticator: CredentialAuthenticator
    ) -> None:
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        await service.revoke(issued.credential.credential_id)
        with pytest.raises(AuthenticationFailed) as caught:
            await authenticator.authenticate(bearer(issued.token))
        assert caught.value.reason is AuthFailureReason.UNKNOWN_CREDENTIAL

    async def test_revocation_takes_effect_without_a_restart(
        self, service: CredentialService, authenticator: CredentialAuthenticator
    ) -> None:
        """No cache to invalidate: the row is read on every request."""
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        assert await authenticator.authenticate(bearer(issued.token))
        await service.revoke(issued.credential.credential_id)
        with pytest.raises(AuthenticationFailed):
            await authenticator.authenticate(bearer(issued.token))

    async def test_an_expired_credential_is_refused(
        self, credential_store: SqliteCredentialStore, service: CredentialService
    ) -> None:
        # Anchor expiry relative to the test run rather than a calendar date.
        # Production still validates that a credential cannot be born expired;
        # the injected authenticator clock below is the only thing that moves.
        now = datetime.now(UTC)
        issued = await service.create(
            actor_id="svc",
            actor_type=ActorType.SERVICE,
            scopes=frozenset(),
            expires_at=now + timedelta(hours=1),
        )
        late = CredentialAuthenticator(
            credential_store, pepper=PEPPER, now=lambda: now + timedelta(days=1)
        )
        with pytest.raises(AuthenticationFailed) as caught:
            await late.authenticate(bearer(issued.token))
        assert caught.value.reason is AuthFailureReason.UNKNOWN_CREDENTIAL

    async def test_a_credential_issued_under_another_pepper_is_refused(
        self, service: CredentialService, credential_store: SqliteCredentialStore
    ) -> None:
        """Rotating the pepper invalidates everything, as documented."""
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        other = CredentialAuthenticator(credential_store, pepper="a-completely-different-pepper")
        with pytest.raises(AuthenticationFailed):
            await other.authenticate(bearer(issued.token))

    async def test_failures_never_echo_the_presented_credential(
        self, authenticator: CredentialAuthenticator
    ) -> None:
        """A traceback, log line or audit row derived from this must not leak."""
        secret = "scrp_a8f13e9c2b41_supersecretvalue"
        with pytest.raises(AuthenticationFailed) as caught:
            await authenticator.authenticate(bearer(secret))
        rendered = f"{caught.value} {caught.value.args!r} {caught.value.__dict__!r}"
        assert "supersecretvalue" not in rendered
        assert secret not in rendered


class TestFailClosed:
    async def test_an_empty_store_accepts_nothing(
        self, authenticator: CredentialAuthenticator
    ) -> None:
        """No credentials is zero valid keys, not an open door."""
        with pytest.raises(AuthenticationFailed):
            await authenticator.authenticate(bearer("scrp_a8f13e9c2b41_anything"))

    async def test_the_null_authenticator_refuses_everything(self) -> None:
        null = build_authenticator(None)
        assert not null.configured
        with pytest.raises(AuthenticationFailed) as caught:
            await null.authenticate(bearer("anything"))
        assert caught.value.reason is AuthFailureReason.NO_CREDENTIALS_CONFIGURED

    async def test_a_whitespace_only_token_is_treated_as_unconfigured(self) -> None:
        """It would otherwise report configured while refusing every caller."""
        assert not build_authenticator(SecretStr("   ")).configured

    async def test_a_credential_store_reports_itself_configured_when_empty(
        self, authenticator: CredentialAuthenticator
    ) -> None:
        """Empty is not broken; doctor counts credentials, this reports capability."""
        assert authenticator.configured


class TestLegacyToken:
    async def test_a_legacy_token_still_works_alongside_credentials(
        self, credential_store: SqliteCredentialStore
    ) -> None:
        """Upgrading must not lock out a deployment mid-migration."""
        legacy = build_authenticator(SecretStr("legacy-token-value-1234567890"))
        combined = CredentialAuthenticator(
            credential_store, pepper=PEPPER, legacy=legacy
        )
        actor = await combined.authenticate(bearer("legacy-token-value-1234567890"))
        assert actor.auth_method is AuthMethod.BEARER_TOKEN

    async def test_a_stored_credential_is_preferred_over_the_legacy_token(
        self, credential_store: SqliteCredentialStore, service: CredentialService
    ) -> None:
        legacy = build_authenticator(SecretStr("legacy-token-value-1234567890"))
        combined = CredentialAuthenticator(
            credential_store, pepper=PEPPER, legacy=legacy
        )
        issued = await service.create(
            actor_id="svc-stored", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        assert (await combined.authenticate(bearer(issued.token))).id == "svc-stored"

    async def test_without_a_legacy_token_a_foreign_format_is_refused(
        self, authenticator: CredentialAuthenticator
    ) -> None:
        with pytest.raises(AuthenticationFailed):
            await authenticator.authenticate(bearer("some-other-systems-token"))


class TestLastUsedTracking:
    async def test_a_successful_authentication_can_be_recorded(
        self, credential_store: SqliteCredentialStore, service: CredentialService
    ) -> None:
        seen: list[Credential] = []

        async def remember(credential: Credential) -> None:
            seen.append(credential)

        authenticator = CredentialAuthenticator(
            credential_store, pepper=PEPPER, on_authenticated=remember
        )
        issued = await service.create(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset()
        )
        await authenticator.authenticate(bearer(issued.token))
        assert [c.credential_id for c in seen] == [issued.credential.credential_id]

    async def test_a_failed_authentication_records_nothing(
        self, credential_store: SqliteCredentialStore
    ) -> None:
        seen: list[Credential] = []

        async def remember(credential: Credential) -> None:  # pragma: no cover
            seen.append(credential)

        authenticator = CredentialAuthenticator(
            credential_store, pepper=PEPPER, on_authenticated=remember
        )
        with pytest.raises(AuthenticationFailed):
            await authenticator.authenticate(bearer("scrp_a8f13e9c2b41_wrong"))
        assert seen == []
