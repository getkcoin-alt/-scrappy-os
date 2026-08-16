"""Authentication: turning a presented credential into an :class:`Actor`.

The contract every implementation honours:

* A credential is compared in constant time, against every configured
  credential, with no early exit. Comparison is over SHA-256 digests so that
  neither the length nor a shared prefix of the real token is observable.
* A failure says *why* in a category (missing, malformed, unknown) and never
  echoes what was presented. The reason is safe to audit; the credential is not,
  and is never carried on the exception.
* No configured credential means no valid credential. The API stays up and
  refuses every authenticated request rather than falling open.

That last rule is the one that replaces "safe because it is on localhost".
Booting without a token is not an unauthenticated mode - it is a deployment with
zero valid keys, which is a very different thing from a deployment that stopped
checking.

:class:`Authenticator` is a Protocol so mTLS, OIDC and node identities can be
added as siblings rather than as branches inside a token checker.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import SecretStr

from scrappy_os.core.errors import ScrappyError
from scrappy_os.core.identity import Actor, ActorType, AuthMethod, Scope, all_scopes

#: RFC 6750 names this scheme; the comparison against it is case-insensitive.
BEARER_SCHEME = "bearer"

#: Shortest token accepted from configuration. Not a strength guarantee - it is
#: a floor that rejects the obviously-a-placeholder case ("changeme", "test").
MIN_TOKEN_LENGTH = 16


class AuthFailureReason(StrEnum):
    """Why authentication failed.

    Categories, not messages: they are safe to audit, safe to count, and
    deliberately coarse. A client learns only that its credential was not
    accepted, never which of several tokens it nearly matched.
    """

    MISSING_CREDENTIAL = "missing_credential"
    """No Authorization header at all."""

    MALFORMED_CREDENTIAL = "malformed_credential"
    """Header present but not a well-formed ``Bearer <token>``."""

    UNKNOWN_CREDENTIAL = "unknown_credential"
    """Well-formed, but matched no configured credential."""

    NO_CREDENTIALS_CONFIGURED = "no_credentials_configured"
    """The deployment has no token set, so nothing can authenticate."""


class AuthenticationFailed(ScrappyError):
    """A credential was absent, malformed or unrecognised.

    Carries the reason category and nothing else. In particular it never carries
    the presented value, so a traceback, a log line or an audit row derived from
    this exception cannot leak a credential.
    """

    def __init__(self, reason: AuthFailureReason, message: str) -> None:
        super().__init__(message, reason=str(reason))
        self.reason = reason


@dataclass(frozen=True, slots=True)
class TokenCredential:
    """One configured token and the identity it grants.

    A list of these is what makes multiple tokens and rotation additive later:
    issue the new one, keep both accepted, retire the old. v0.2 configures a
    single entry, but nothing in the checker assumes that.
    """

    token: SecretStr
    actor_id: str
    actor_type: ActorType = ActorType.SERVICE
    scopes: frozenset[Scope] = frozenset()
    display_name: str | None = None

    def digest(self) -> bytes:
        """SHA-256 of the secret, which is what comparison actually uses."""
        return hashlib.sha256(self.token.get_secret_value().encode("utf-8")).digest()

    def to_actor(self) -> Actor:
        """The identity this credential proves."""
        return Actor(
            id=self.actor_id,
            actor_type=self.actor_type,
            display_name=self.display_name,
            scopes=self.scopes,
            auth_method=AuthMethod.BEARER_TOKEN,
        )


@runtime_checkable
class Authenticator(Protocol):
    """Turns a raw ``Authorization`` header into an actor, or fails.

    Implementations must not log, echo or re-raise the header value.
    """

    def authenticate(self, authorization_header: str | None) -> Actor:
        """Return the authenticated actor or raise :class:`AuthenticationFailed`."""
        ...

    @property
    def configured(self) -> bool:
        """Whether this authenticator can accept anything at all."""
        ...


def parse_bearer(authorization_header: str | None) -> str:
    """Extract the token from an ``Authorization`` header.

    Strict by construction: exactly two whitespace-separated parts, the first
    equal to ``Bearer`` case-insensitively, the second non-empty. ``Basic``,
    a bare token with no scheme, and ``Bearer`` with nothing after it are all
    malformed - accepting any of them would mean accepting a credential the
    client did not intend as one.
    """
    if authorization_header is None or not authorization_header.strip():
        raise AuthenticationFailed(
            AuthFailureReason.MISSING_CREDENTIAL,
            "authentication required: send 'Authorization: Bearer <token>'",
        )

    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != BEARER_SCHEME or not parts[1]:
        raise AuthenticationFailed(
            AuthFailureReason.MALFORMED_CREDENTIAL,
            "malformed Authorization header: expected 'Bearer <token>'",
        )
    return parts[1]


class StaticTokenAuthenticator:
    """Verifies bearer tokens against a fixed set loaded from configuration.

    Every configured credential is compared on every attempt, and the result is
    accumulated rather than returned early, so the time taken does not reveal
    how many credentials exist or which one nearly matched.
    """

    def __init__(self, credentials: Sequence[TokenCredential] = ()) -> None:
        self._credentials = tuple(credentials)
        # Precomputed so the hot path hashes the presented value only.
        self._digests = tuple(credential.digest() for credential in self._credentials)

    @property
    def configured(self) -> bool:
        return bool(self._credentials)

    @property
    def credential_count(self) -> int:
        """How many credentials are accepted. Never which, and never their values."""
        return len(self._credentials)

    def authenticate(self, authorization_header: str | None) -> Actor:
        """Verify the header and return the actor it proves."""
        presented = parse_bearer(authorization_header)

        if not self._credentials:
            # Checked after parsing so that a malformed header is still reported
            # as malformed: an operator debugging a client deserves the accurate
            # reason, and neither answer reveals anything to the client.
            raise AuthenticationFailed(
                AuthFailureReason.NO_CREDENTIALS_CONFIGURED,
                "no API credentials are configured; set SCRAPPY_API_TOKEN to enable API access",
            )

        digest = hashlib.sha256(presented.encode("utf-8")).digest()
        matched: TokenCredential | None = None
        for credential, expected in zip(self._credentials, self._digests, strict=True):
            # compare_digest on every entry, no break: the loop's cost must not
            # depend on which credential matched, or whether one did.
            if hmac.compare_digest(digest, expected):
                matched = credential

        if matched is None:
            raise AuthenticationFailed(
                AuthFailureReason.UNKNOWN_CREDENTIAL,
                "the presented credential is not recognised",
            )
        return matched.to_actor()


class NullAuthenticator:
    """Accepts nothing. The authenticator for a deployment with no token set.

    Exists so "unconfigured" is a real object with the same shape as a working
    one, rather than a ``None`` that every call site has to remember to check -
    the check that gets forgotten is the one that fails open.
    """

    @property
    def configured(self) -> bool:
        return False

    @property
    def credential_count(self) -> int:
        return 0

    def authenticate(self, authorization_header: str | None) -> Actor:
        # Parse first, for the same reason as above: accurate diagnostics for the
        # operator, no additional information for the client.
        parse_bearer(authorization_header)
        raise AuthenticationFailed(
            AuthFailureReason.NO_CREDENTIALS_CONFIGURED,
            "no API credentials are configured; set SCRAPPY_API_TOKEN to enable API access",
        )


def generate_token(*, entropy_bytes: int = 32) -> str:
    """A fresh API token for an operator to paste into their configuration.

    Not called automatically anywhere. Scrappy OS never invents a credential on
    an operator's behalf and never writes one to disk or to a log; this exists so
    ``scrappy token new`` can print one to a terminal on request.
    """
    return secrets.token_urlsafe(entropy_bytes)


def build_authenticator(
    token: SecretStr | None,
    *,
    actor_id: str = "api-token",
    scopes: frozenset[Scope] | None = None,
) -> StaticTokenAuthenticator | NullAuthenticator:
    """Construct the authenticator implied by configuration.

    A deployment with no token gets a :class:`NullAuthenticator`, which refuses
    everything. It does not get an open door.
    """
    # `.strip()` matters as much as the None check. A token that is only
    # whitespace is truthy, so it would build a real authenticator holding a
    # credential no client can ever present: `parse_bearer` splits the header on
    # whitespace and demands exactly two parts, so `Authorization: Bearer    `
    # is malformed by construction. The result is a deployment that reports
    # itself configured and refuses everyone. Treating it as unconfigured is
    # both accurate and the safer of the two failures.
    if token is None or not token.get_secret_value().strip():
        return NullAuthenticator()
    return StaticTokenAuthenticator(
        [
            TokenCredential(
                token=token,
                actor_id=actor_id,
                actor_type=ActorType.SERVICE,
                scopes=all_scopes() if scopes is None else scopes,
                display_name="configured API token",
            )
        ]
    )


__all__ = [
    "BEARER_SCHEME",
    "MIN_TOKEN_LENGTH",
    "AuthFailureReason",
    "AuthenticationFailed",
    "Authenticator",
    "NullAuthenticator",
    "StaticTokenAuthenticator",
    "TokenCredential",
    "build_authenticator",
    "generate_token",
    "parse_bearer",
]
