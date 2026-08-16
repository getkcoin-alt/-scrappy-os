"""The server-side key that makes a stored verifier useless on its own.

Every credential verifier is ``HMAC-SHA256(pepper, secret)``. Without the pepper
the stored value cannot be checked against a guess, so an attacker who copies the
database still cannot test candidate tokens offline.

Where the pepper comes from decides how much that is worth:

``SCRAPPY_TOKEN_PEPPER`` in the environment
    The intended production source. The key lives in the service's environment
    file (root-owned, ``0640``) and never touches the data directory, so stealing
    the database is genuinely not enough.

A file in the data directory
    The first-run fallback. Generated once, ``0600``, and reused on every
    subsequent start. It makes the system work out of the box without an
    operator inventing a secret, and it is honestly weaker: the pepper sits next
    to the database it protects, so anything that can read one can usually read
    the other. ``doctor`` says so rather than reporting a clean bill.

The fallback is generated *once and persisted*, never per start. A pepper that
changed at startup would silently invalidate every credential in the database,
which reads to an operator as "all my tokens broke for no reason".
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from scrappy_os.core.errors import ConfigurationError
from scrappy_os.observability.logging import get_logger

logger = get_logger("security.pepper")

#: Filename used for the generated fallback, inside the data directory.
PEPPER_FILENAME = "token_pepper"

#: Bytes of randomness in a generated pepper.
PEPPER_ENTROPY_BYTES = 32

#: A configured pepper shorter than this is treated as a misconfiguration.
MIN_PEPPER_LENGTH = 16


class PepperSource(StrEnum):
    """Where the active pepper came from. Reported by ``doctor``, never its value."""

    ENVIRONMENT = "environment"
    """From SCRAPPY_TOKEN_PEPPER. The production answer."""

    DATA_DIRECTORY = "data_directory"
    """Generated on first run and stored beside the database. Works; weaker."""


@dataclass(frozen=True, slots=True)
class ResolvedPepper:
    """The active pepper and its provenance.

    ``value`` is deliberately not in ``__repr__``-friendly form anywhere it gets
    logged: callers pass it to the verifier and nothing else.
    """

    value: str
    source: PepperSource

    @property
    def is_environment(self) -> bool:
        return self.source is PepperSource.ENVIRONMENT

    def describe(self) -> str:
        """A sentence for ``doctor``. Contains no part of the pepper."""
        if self.source is PepperSource.ENVIRONMENT:
            return "SCRAPPY_TOKEN_PEPPER (environment)"
        return f"generated, stored in the data directory as {PEPPER_FILENAME}"


def _read_or_create_file_pepper(data_dir: Path) -> str:
    path = data_dir / PEPPER_FILENAME
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
        # An empty file is a broken state, not a pepper. Regenerating would
        # invalidate existing credentials silently, so say so instead.
        raise ConfigurationError(
            f"{path} exists but is empty. Every credential was verified with the "
            "pepper that used to be there; restore it from backup, or set "
            "SCRAPPY_TOKEN_PEPPER, or delete the file and reissue all credentials."
        )

    value = secrets.token_urlsafe(PEPPER_ENTROPY_BYTES)
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Created 0600 by the opener rather than chmod'd afterwards: a write-then-
    # chmod leaves a window where the pepper is world-readable. "x" makes a
    # concurrent first start fail loudly instead of two processes racing to
    # write different peppers, one of which would win and invalidate the other's
    # credentials.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(value)
    logger.info(
        "token_pepper_generated",
        path=str(path),
        detail=(
            "generated a token pepper because SCRAPPY_TOKEN_PEPPER is unset. It is "
            "stored next to the credential database, which is weaker than an "
            "environment-supplied key"
        ),
    )
    return value


def resolve_pepper(*, configured: str | None, data_dir: Path) -> ResolvedPepper:
    """Decide which pepper to use, generating the fallback on first run only.

    A configured-but-trivial pepper is refused rather than accepted quietly: it
    would produce verifiers that look protected and are not, and the failure
    would be invisible until someone stole the database.
    """
    if configured is not None and configured.strip():
        value = configured.strip()
        if len(value) < MIN_PEPPER_LENGTH:
            raise ConfigurationError(
                f"SCRAPPY_TOKEN_PEPPER is only {len(value)} characters; use at least "
                f"{MIN_PEPPER_LENGTH}. Generate one with "
                '`python -c "import secrets; print(secrets.token_urlsafe(32))"`.'
            )
        return ResolvedPepper(value=value, source=PepperSource.ENVIRONMENT)

    return ResolvedPepper(
        value=_read_or_create_file_pepper(data_dir), source=PepperSource.DATA_DIRECTORY
    )


__all__ = [
    "MIN_PEPPER_LENGTH",
    "PEPPER_ENTROPY_BYTES",
    "PEPPER_FILENAME",
    "PepperSource",
    "ResolvedPepper",
    "resolve_pepper",
]
