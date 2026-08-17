"""The credential primitives: token format, verifiers and lifecycle state.

These are the pieces every other credential test stands on, so they are tested
directly rather than through the store or the API. A bug in ``parse_token`` or
``status_at`` would show up higher as something vague ("authentication fails
sometimes"); here it shows up as the specific thing that broke.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from scrappy_os.core.identity import ActorType, AuthMethod, Scope
from scrappy_os.security.credentials import (
    MAX_TOKEN_LENGTH,
    SECRET_ENTROPY_BYTES,
    TOKEN_PREFIX,
    Credential,
    CredentialError,
    CredentialStatus,
    IssuedCredential,
    compute_verifier,
    format_token,
    generate_secret,
    issue_credential,
    new_credential_id,
    parse_token,
    verify_secret,
)

PEPPER = "test-pepper-value-long-enough"
NOW = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)


def _credential(**overrides: object) -> Credential:
    defaults: dict[str, object] = {
        "credential_id": new_credential_id(),
        "actor_id": "svc-deploy",
        "actor_type": ActorType.SERVICE,
        "scopes": frozenset({Scope.TASK_READ}),
        "verifier": compute_verifier("secret", pepper=PEPPER),
        "created_at": NOW,
    }
    return Credential(**{**defaults, **overrides})  # type: ignore[arg-type]


class TestTokenFormat:
    def test_generated_ids_are_well_formed_and_unique(self) -> None:
        ids = {new_credential_id() for _ in range(50)}
        assert len(ids) == 50, "credential ids collided"
        assert all(value.startswith("cred_") for value in ids)

    def test_secret_carries_the_advertised_entropy(self) -> None:
        # token_urlsafe emits ~4/3 characters per byte; the point is that the
        # secret is not truncated to something guessable.
        assert len(generate_secret()) >= SECRET_ENTROPY_BYTES

    def test_round_trip_recovers_id_and_secret(self) -> None:
        credential_id = new_credential_id()
        secret = generate_secret()
        recovered_id, recovered_secret = parse_token(format_token(credential_id, secret))
        assert recovered_id == credential_id
        assert recovered_secret == secret

    def test_secret_containing_underscores_survives(self) -> None:
        """The regression that a naive ``split("_")`` would cause.

        ``token_urlsafe`` uses the base64url alphabet, which includes ``_``, so
        a real secret regularly contains one. Splitting without ``maxsplit``
        truncates it and authentication fails for one token in a handful.
        """
        credential_id = new_credential_id()
        secret = "abc_def_ghi_jkl"
        recovered_id, recovered_secret = parse_token(format_token(credential_id, secret))
        assert recovered_id == credential_id
        assert recovered_secret == secret

    def test_issued_tokens_are_greppable(self) -> None:
        issued = issue_credential(
            actor_id="a", actor_type=ActorType.SERVICE, scopes=frozenset(), pepper=PEPPER
        )
        assert issued.token.startswith(f"{TOKEN_PREFIX}_")

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "nonsense",
            "scrp_short",
            "wrong_a8f13e9c2b41_secret",
            "scrp_ZZZZZZZZZZZZ_secret",
            "scrp_a8f13e9c2b41_",
            "scrp__secret",
        ],
        ids=[
            "empty",
            "no-separators",
            "two-parts-only",
            "wrong-prefix",
            "non-hex-id",
            "empty-secret",
            "missing-id",
        ],
    )
    def test_malformed_tokens_are_refused(self, raw: str) -> None:
        with pytest.raises(CredentialError):
            parse_token(raw)

    def test_absurdly_long_token_is_refused_before_parsing(self) -> None:
        """Bounded work on unauthenticated input."""
        with pytest.raises(CredentialError):
            parse_token("scrp_a8f13e9c2b41_" + "x" * MAX_TOKEN_LENGTH)

    def test_format_token_rejects_a_malformed_id(self) -> None:
        with pytest.raises(CredentialError):
            format_token("not-a-credential-id", "secret")


class TestVerifier:
    def test_verifier_matches_its_own_secret(self) -> None:
        verifier = compute_verifier("s3cret", pepper=PEPPER)
        assert verify_secret("s3cret", verifier, pepper=PEPPER)

    def test_wrong_secret_does_not_verify(self) -> None:
        verifier = compute_verifier("s3cret", pepper=PEPPER)
        assert not verify_secret("other", verifier, pepper=PEPPER)

    def test_a_different_pepper_invalidates_the_verifier(self) -> None:
        """The property that makes a stolen database insufficient."""
        verifier = compute_verifier("s3cret", pepper=PEPPER)
        assert not verify_secret("s3cret", verifier, pepper="a-different-pepper")

    def test_verifier_is_not_the_secret(self) -> None:
        verifier = compute_verifier("s3cret", pepper=PEPPER)
        assert "s3cret" not in verifier
        assert len(verifier) == 64  # hex sha256

    def test_refuses_to_compute_without_a_pepper(self) -> None:
        with pytest.raises(CredentialError):
            compute_verifier("s3cret", pepper="")

    def test_verify_is_false_rather_than_raising_without_a_pepper(self) -> None:
        """Authentication must fail closed, not explode into a 500."""
        assert not verify_secret("s3cret", "0" * 64, pepper="")


class TestLifecycleState:
    def test_a_fresh_credential_is_active(self) -> None:
        assert _credential().status_at(NOW) is CredentialStatus.ACTIVE

    def test_expiry_is_derived_from_the_clock(self) -> None:
        credential = _credential(expires_at=NOW + timedelta(hours=1))
        assert credential.status_at(NOW) is CredentialStatus.ACTIVE
        assert credential.status_at(NOW + timedelta(hours=2)) is CredentialStatus.EXPIRED

    def test_expiry_boundary_is_exclusive_of_the_instant_itself(self) -> None:
        credential = _credential(expires_at=NOW)
        assert credential.status_at(NOW) is CredentialStatus.EXPIRED

    def test_revocation_outranks_expiry(self) -> None:
        """Two true stories; the audit trail should tell the deliberate one."""
        credential = _credential(
            expires_at=NOW + timedelta(hours=1), revoked_at=NOW + timedelta(minutes=1)
        )
        assert credential.status_at(NOW + timedelta(days=7)) is CredentialStatus.REVOKED

    def test_only_active_credentials_are_usable(self) -> None:
        assert _credential().is_usable_at(NOW)
        assert not _credential(revoked_at=NOW).is_usable_at(NOW)
        assert not _credential(expires_at=NOW - timedelta(seconds=1)).is_usable_at(NOW)


class TestCredentialModel:
    def test_naive_timestamps_are_rejected(self) -> None:
        """Expiry is a security boundary; a naive datetime makes it ambiguous."""
        with pytest.raises(ValidationError):
            _credential(created_at=datetime(2026, 8, 17, 12, 0))

    def test_timestamps_are_normalised_to_utc(self) -> None:
        """Stored in UTC regardless of the operator's timezone."""
        kolkata = timezone(timedelta(hours=5, minutes=30))
        elsewhere = datetime(2026, 8, 17, 17, 30, tzinfo=kolkata)
        stored = _credential(created_at=elsewhere).created_at
        assert stored.tzinfo is UTC
        assert stored == datetime(2026, 8, 17, 12, 0, tzinfo=UTC)

    def test_malformed_credential_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _credential(credential_id="cred_nothex")

    def test_credential_is_frozen(self) -> None:
        """Scopes must not be grantable by assignment."""
        credential = _credential()
        with pytest.raises(ValidationError):
            credential.scopes = frozenset(Scope)  # type: ignore[misc]

    def test_unknown_fields_are_refused(self) -> None:
        with pytest.raises(ValidationError):
            _credential(is_admin=True)

    def test_verifier_is_absent_from_repr(self) -> None:
        """A credential landing in a traceback must not carry the verifier."""
        credential = _credential(verifier=compute_verifier("topsecret", pepper=PEPPER))
        assert credential.verifier not in repr(credential)

    def test_revocation_returns_a_copy(self) -> None:
        original = _credential()
        revoked = original.with_revoked_at(NOW)
        assert original.revoked_at is None
        assert revoked.revoked_at == NOW


class TestActorDerivation:
    def test_actor_is_built_only_from_stored_fields(self) -> None:
        credential = _credential(
            actor_id="svc-ci",
            actor_type=ActorType.SERVICE,
            display_name="CI runner",
            scopes=frozenset({Scope.TASK_CREATE, Scope.TASK_READ}),
        )
        actor = credential.to_actor()
        assert actor.id == "svc-ci"
        assert actor.actor_type is ActorType.SERVICE
        assert actor.display_name == "CI runner"
        assert actor.scopes == frozenset({Scope.TASK_CREATE, Scope.TASK_READ})
        assert actor.auth_method is AuthMethod.BEARER_TOKEN

    def test_actor_records_which_credential_proved_it(self) -> None:
        credential = _credential()
        assert credential.to_actor().metadata["credential_id"] == credential.credential_id


class TestRedaction:
    def test_redacted_view_excludes_the_verifier(self) -> None:
        credential = _credential(verifier=compute_verifier("topsecret", pepper=PEPPER))
        rendered = credential.redacted()
        assert "verifier" not in rendered
        assert credential.verifier not in str(rendered)

    def test_audit_fields_are_identifiers_only(self) -> None:
        assert set(_credential().audit_fields()) == {
            "credential_id",
            "actor_id",
            "actor_type",
        }


class TestIssuing:
    def test_issuing_returns_a_token_that_verifies(self) -> None:
        issued = issue_credential(
            actor_id="svc",
            actor_type=ActorType.SERVICE,
            scopes=frozenset({Scope.TASK_READ}),
            pepper=PEPPER,
        )
        _, secret = parse_token(issued.token)
        assert verify_secret(secret, issued.credential.verifier, pepper=PEPPER)

    def test_the_raw_token_is_never_on_the_stored_credential(self) -> None:
        issued = issue_credential(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset(), pepper=PEPPER
        )
        assert issued.token not in issued.credential.model_dump_json()

    def test_issued_credential_str_hides_the_token(self) -> None:
        issued = issue_credential(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset(), pepper=PEPPER
        )
        assert issued.token not in str(issued)
        assert issued.token not in repr(issued)

    def test_two_issues_never_share_a_token(self) -> None:
        tokens = {
            issue_credential(
                actor_id="svc",
                actor_type=ActorType.SERVICE,
                scopes=frozenset(),
                pepper=PEPPER,
            ).token
            for _ in range(25)
        }
        assert len(tokens) == 25

    def test_a_credential_cannot_be_born_expired(self) -> None:
        with pytest.raises(CredentialError):
            issue_credential(
                actor_id="svc",
                actor_type=ActorType.SERVICE,
                scopes=frozenset(),
                pepper=PEPPER,
                created_at=NOW,
                expires_at=NOW - timedelta(seconds=1),
            )

    def test_issued_credential_is_frozen(self) -> None:
        issued = issue_credential(
            actor_id="svc", actor_type=ActorType.SERVICE, scopes=frozenset(), pepper=PEPPER
        )
        with pytest.raises(ValidationError):
            issued.token = "scrp_deadbeefcafe_stolen"  # type: ignore[misc]

    def test_issued_credential_holds_what_was_asked_for(self) -> None:
        issued: IssuedCredential = issue_credential(
            actor_id="node-7",
            actor_type=ActorType.NODE,
            scopes=frozenset({Scope.SYSTEM_READ}),
            pepper=PEPPER,
            display_name="edge node 7",
            created_at=NOW,
        )
        assert issued.credential.actor_type is ActorType.NODE
        assert issued.credential.scopes == frozenset({Scope.SYSTEM_READ})
        assert issued.credential.display_name == "edge node 7"
        assert issued.credential.created_at == NOW
