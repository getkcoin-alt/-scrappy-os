"""Credentials: the things that prove an :class:`~scrappy_os.core.identity.Actor`.

An actor is *who*. A credential is *one way of proving it*. Keeping them apart is
the whole point of this module: a person may hold a laptop token and a CI token,
lose one, rotate it, and remain the same principal in the audit trail. Collapsing
the two - making the credential the identity - is what forces "revoke the token"
and "delete the user" to be the same operation, and it is the mistake this design
exists to avoid.

What is stored, and what is not
-------------------------------

The raw token is never persisted. What lands in the database is an HMAC-SHA256
verifier keyed by a server-side pepper, plus the non-secret identifiers needed to
find it. An operator who steals the database file gets verifiers, not tokens, and
cannot use them against the API.

Why HMAC and not Argon2id or scrypt
-----------------------------------

Slow KDFs exist to make *guessing* expensive, and guessing is only a threat when
the secret is guessable. These secrets are 256 bits from :mod:`secrets`; brute
force is not on the table at any cost factor, so a memory-hard KDF would buy
nothing and would add a dependency plus per-request latency on the authentication
hot path. The real threat to a high-entropy token is theft of the stored value,
and that is what the pepper addresses: a verifier is useless without a key the
database does not contain.

The honest limitation: if an attacker takes the pepper *and* the database, they
can confirm a guessed token offline. They still cannot reverse a verifier into a
token. See ``docs/CREDENTIALS.md`` for where the pepper should live.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

from scrappy_os.core.errors import ScrappyError
from scrappy_os.core.identity import Actor, ActorType, AuthMethod, Scope

#: Prefix on every token this system issues. Makes a leaked token greppable in
#: logs and CI output, and lets secret scanners recognise one on sight.
TOKEN_PREFIX: Final = "scrp"  # noqa: S105 - a format marker, not a secret

#: Prefix on the non-secret credential identifier.
CREDENTIAL_ID_PREFIX: Final = "cred"

#: Hex characters in the lookup part of a credential id. 12 hex = 48 bits, which
#: is not a secret and does not need to be - it only has to not collide.
ID_HEX_LENGTH: Final = 12

#: Bytes of randomness in the secret half. 32 bytes = 256 bits, well past the
#: 128-bit floor the milestone asks for.
SECRET_ENTROPY_BYTES: Final = 32

#: Rejects a credential id that did not come from :func:`new_credential_id`.
_CREDENTIAL_ID_RE: Final = re.compile(rf"^{CREDENTIAL_ID_PREFIX}_[0-9a-f]{{{ID_HEX_LENGTH}}}$")

#: An Authorization header value longer than this is refused before any parsing
#: or hashing happens. A legitimate token is ~60 characters; the limit exists so
#: an attacker cannot make the server do unbounded work by sending megabytes.
MAX_TOKEN_LENGTH: Final = 512


class CredentialError(ScrappyError):
    """A credential could not be created, parsed or verified."""


class CredentialStatus(StrEnum):
    """The lifecycle state of a credential.

    Derived from timestamps rather than stored as a flag, so "expired" cannot
    drift from ``expires_at``. There is no sweeper job to forget to run, and no
    window where a row says ACTIVE while the clock disagrees.
    """

    ACTIVE = "active"
    """Usable right now."""

    EXPIRED = "expired"
    """Past ``expires_at``. Fails authentication; kept for the audit trail."""

    REVOKED = "revoked"
    """Withdrawn by an operator. Terminal - a revoked credential never returns."""


def new_credential_id() -> str:
    """A fresh non-secret credential identifier, e.g. ``cred_a8f13e9c2b41``."""
    return f"{CREDENTIAL_ID_PREFIX}_{secrets.token_hex(ID_HEX_LENGTH // 2)}"


def generate_secret() -> str:
    """A fresh token secret: 256 bits, URL-safe, from the OS CSPRNG."""
    return secrets.token_urlsafe(SECRET_ENTROPY_BYTES)


def format_token(credential_id: str, secret: str) -> str:
    """Assemble the raw token a client will present.

    ``scrp_<id-hex>_<secret>``. The id half is not secret: it lets
    authentication find one row instead of hashing the presented value against
    every credential in the table. The secret half is the only part that proves
    anything.
    """
    if not _CREDENTIAL_ID_RE.match(credential_id):
        raise CredentialError(f"not a well-formed credential id: {credential_id!r}")
    id_hex = credential_id.split("_", 1)[1]
    return f"{TOKEN_PREFIX}_{id_hex}_{secret}"


def parse_token(raw: str) -> tuple[str, str]:
    """Split a presented token into ``(credential_id, secret)``.

    Raises :class:`CredentialError` for anything that is not exactly this
    format. Callers translate that into 401 without distinguishing *which* part
    was wrong, because telling a client whether the id existed is how credential
    enumeration starts.

    ``maxsplit=2`` matters: :func:`secrets.token_urlsafe` emits the base64url
    alphabet, which includes ``_``, so the secret regularly contains underscores
    and a naive split would corrupt it.
    """
    if not raw or len(raw) > MAX_TOKEN_LENGTH:
        raise CredentialError("token is empty or implausibly long")

    parts = raw.split("_", 2)
    if len(parts) != 3:
        raise CredentialError("token does not have the expected three parts")

    prefix, id_hex, secret = parts
    if prefix != TOKEN_PREFIX or not secret:
        raise CredentialError("token prefix or secret is missing")

    credential_id = f"{CREDENTIAL_ID_PREFIX}_{id_hex}"
    if not _CREDENTIAL_ID_RE.match(credential_id):
        raise CredentialError("token does not carry a well-formed credential id")
    return credential_id, secret


def compute_verifier(secret: str, *, pepper: str) -> str:
    """The value stored for ``secret``: ``HMAC-SHA256(pepper, secret)`` as hex.

    Keyed rather than plain: a bare SHA-256 of the secret would let anyone
    holding the database confirm a guess without knowing anything else, and
    would make a precomputed table meaningful if a token were ever low-entropy.
    """
    if not pepper:
        raise CredentialError("refusing to compute a verifier without a pepper")
    return hmac.new(
        pepper.encode("utf-8"), secret.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify_secret(secret: str, expected_verifier: str, *, pepper: str) -> bool:
    """Whether ``secret`` matches ``expected_verifier``, in constant time.

    :func:`hmac.compare_digest` because a byte-by-byte ``==`` leaks how much of
    a guess was right through timing. The HMAC itself is constant-time in the
    secret, so the whole path is.
    """
    try:
        candidate = compute_verifier(secret, pepper=pepper)
    except CredentialError:
        return False
    return hmac.compare_digest(candidate, expected_verifier)


class Credential(BaseModel):
    """One stored proof of an actor's identity. Never holds the raw token.

    Frozen for the same reason :class:`Actor` is: this is a record of something
    that was decided, and code that could edit it in place could grant itself
    scopes or un-revoke a credential by assignment.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    credential_id: str = Field(min_length=1, max_length=64)
    actor_id: str = Field(min_length=1, max_length=128)
    actor_type: ActorType
    display_name: str | None = Field(default=None, max_length=128)
    scopes: frozenset[Scope] = Field(default_factory=frozenset)
    verifier: str = Field(min_length=1, max_length=128, repr=False)
    created_at: datetime
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None
    auth_method: AuthMethod = AuthMethod.BEARER_TOKEN
    #: Non-secret provenance: who created it, what it replaced. Never a secret.
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("credential_id")
    @classmethod
    def _well_formed_id(cls, value: str) -> str:
        if not _CREDENTIAL_ID_RE.match(value):
            raise ValueError(f"not a well-formed credential id: {value!r}")
        return value

    @field_validator("created_at", "expires_at", "revoked_at", "last_used_at")
    @classmethod
    def _must_be_timezone_aware(cls, value: datetime | None) -> datetime | None:
        """Naive datetimes are a bug here specifically.

        Expiry is a security boundary. A naive timestamp compared against an
        aware one raises, and a naive one compared against a naive local clock
        silently means something different depending on the host's timezone -
        either way the boundary stops being trustworthy. Everything is stored
        and compared in UTC.
        """
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("credential timestamps must be timezone-aware")
        return value.astimezone(UTC)

    def status_at(self, now: datetime) -> CredentialStatus:
        """This credential's state at ``now``.

        Revocation wins over expiry: a credential an operator withdrew should
        read REVOKED in the audit trail even if it would also have aged out,
        because those are different stories about what happened.
        """
        if self.revoked_at is not None:
            return CredentialStatus.REVOKED
        if self.expires_at is not None and now >= self.expires_at:
            return CredentialStatus.EXPIRED
        return CredentialStatus.ACTIVE

    def is_usable_at(self, now: datetime) -> bool:
        """Whether authentication may proceed. Anything not ACTIVE is a no."""
        return self.status_at(now) is CredentialStatus.ACTIVE

    def to_actor(self) -> Actor:
        """The identity this credential proves.

        Built entirely from stored fields. Nothing a client sent contributes, so
        a caller cannot influence who they are by decorating the request.
        """
        return Actor(
            id=self.actor_id,
            actor_type=self.actor_type,
            display_name=self.display_name,
            scopes=self.scopes,
            auth_method=self.auth_method,
            metadata={"credential_id": self.credential_id},
        )

    def redacted(self) -> dict[str, Any]:
        """Everything safe to show a human. Deliberately excludes the verifier."""
        return {
            "credential_id": self.credential_id,
            "actor_id": self.actor_id,
            "actor_type": str(self.actor_type),
            "display_name": self.display_name,
            "scopes": sorted(str(scope) for scope in self.scopes),
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "auth_method": str(self.auth_method),
            "metadata": dict(self.metadata),
        }

    def audit_fields(self) -> dict[str, Any]:
        """Identity columns for an audit row about this credential."""
        return {
            "credential_id": self.credential_id,
            "actor_id": self.actor_id,
            "actor_type": str(self.actor_type),
        }

    def with_revoked_at(self, when: datetime) -> Self:
        return self.model_copy(update={"revoked_at": when})

    def with_last_used_at(self, when: datetime) -> Self:
        return self.model_copy(update={"last_used_at": when})


class IssuedCredential(BaseModel):
    """A newly created credential *plus* the one and only sight of its token.

    Separate from :class:`Credential` so the raw token cannot be returned by
    accident from a lookup: nothing that reads the database can construct one of
    these, because the token it needs is not there to read.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    credential: Credential
    token: str = Field(repr=False)

    def __str__(self) -> str:  # pragma: no cover - defensive
        return f"IssuedCredential({self.credential.credential_id}, token=<redacted>)"


def issue_credential(
    *,
    actor_id: str,
    actor_type: ActorType,
    scopes: frozenset[Scope],
    pepper: str,
    display_name: str | None = None,
    expires_at: datetime | None = None,
    created_at: datetime | None = None,
    metadata: dict[str, Any] | None = None,
) -> IssuedCredential:
    """Mint a credential and its token. The token is returned, never stored."""
    now = created_at or datetime.now(UTC)
    if expires_at is not None and expires_at <= now:
        raise CredentialError("expires_at is in the past; the credential would be born expired")

    credential_id = new_credential_id()
    secret = generate_secret()
    credential = Credential(
        credential_id=credential_id,
        actor_id=actor_id,
        actor_type=actor_type,
        display_name=display_name,
        scopes=scopes,
        verifier=compute_verifier(secret, pepper=pepper),
        created_at=now,
        expires_at=expires_at,
        metadata=metadata or {},
    )
    return IssuedCredential(credential=credential, token=format_token(credential_id, secret))


__all__ = [
    "CREDENTIAL_ID_PREFIX",
    "ID_HEX_LENGTH",
    "MAX_TOKEN_LENGTH",
    "SECRET_ENTROPY_BYTES",
    "TOKEN_PREFIX",
    "Credential",
    "CredentialError",
    "CredentialStatus",
    "IssuedCredential",
    "compute_verifier",
    "format_token",
    "generate_secret",
    "issue_credential",
    "new_credential_id",
    "parse_token",
    "verify_secret",
]
