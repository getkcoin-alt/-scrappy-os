"""``scrappy token`` - credential administration.

Local-only on purpose. There is no HTTP equivalent of these commands, and adding
one is a decision for a later milestone rather than an oversight: whoever can run
this can already read the database, the pepper and the environment file, so the
authority here is the host's file permissions and nothing else pretends
otherwise. An HTTP endpoint would be a genuinely new attack surface - a remote
caller minting themselves a credential - and it is not needed to make rotation
and revocation work.

The raw token appears exactly once, at creation and at rotation, on stdout.
Nothing stores it, and no command can print it again.
"""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import typer

from scrappy_os.core.config import ScrappySettings, load_settings
from scrappy_os.core.identity import ActorType, Scope, all_scopes, local_cli_actor
from scrappy_os.interface.formatting import (
    bold,
    dim,
    error,
    heading,
    key_value,
    render_table,
    warn,
)
from scrappy_os.memory.store import open_store
from scrappy_os.observability.logging import configure_logging
from scrappy_os.security.audit import AuditLog
from scrappy_os.security.credential_service import CredentialNotFound, CredentialService
from scrappy_os.security.credential_store import SqliteCredentialStore
from scrappy_os.security.credentials import Credential, CredentialError, CredentialStatus
from scrappy_os.security.pepper import resolve_pepper

token_app = typer.Typer(
    help="Create, inspect, rotate and revoke API credentials.", no_args_is_help=True
)

#: ``30d``, ``12h``, ``90m``. Accepted alongside a full ISO-8601 timestamp so an
#: operator can express the common case without looking up the date.
_DURATION_RE = re.compile(r"^(?P<count>\d+)(?P<unit>[smhdw])$")

_DURATION_UNITS: dict[str, str] = {
    "s": "seconds",
    "m": "minutes",
    "h": "hours",
    "d": "days",
    "w": "weeks",
}


def _parse_duration(text: str) -> timedelta | None:
    """``30d`` -> a timedelta; anything else -> None (it may be a timestamp)."""
    match = _DURATION_RE.match(text)
    if match is None:
        return None
    count = int(match.group("count"))
    if count <= 0:
        raise typer.BadParameter("a duration must be greater than zero")
    return timedelta(**{_DURATION_UNITS[match.group("unit")]: count})


def _parse_absolute(text: str, *, what: str) -> datetime:
    """An ISO-8601 timestamp that must carry a timezone."""
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise typer.BadParameter(
            f"{text!r} is neither a duration like '30d' nor an ISO-8601 timestamp"
        ) from exc

    if parsed.tzinfo is None:
        raise typer.BadParameter(
            f"an absolute {what} must carry a timezone, e.g. 2026-09-16T10:30:00Z. "
            "Naive timestamps mean different instants on different hosts."
        )
    return parsed.astimezone(UTC)


def parse_expiry(raw: str | None, *, now: datetime | None = None) -> datetime | None:
    """Turn ``--expires-in`` into an absolute UTC instant in the future.

    Accepts a duration (``30d``) or an ISO-8601 timestamp. A timestamp without a
    timezone is rejected rather than assumed to be local: expiry is a security
    boundary, and "which midnight did you mean" is not a question to answer by
    guessing the host's configuration.
    """
    if raw is None or not raw.strip():
        return None

    moment = now or datetime.now(UTC)
    text = raw.strip()

    duration = _parse_duration(text)
    if duration is not None:
        return moment + duration
    return _parse_absolute(text, what="expiry")


def parse_cutoff(raw: str | None, *, now: datetime | None = None) -> datetime | None:
    """Turn ``--older-than`` into the absolute UTC instant to retain back to.

    The mirror of :func:`parse_expiry`, and deliberately a separate function.
    ``--expires-in 90d`` means *ninety days from now*; ``--older-than 90d`` means
    *ninety days ago*. Deriving one from the other by reflecting an instant about
    the present - ``now - (parse_expiry(raw) - now)`` - is correct for a duration
    and badly wrong for a timestamp: ``--older-than 2026-01-01T00:00:00Z`` came
    back as a cutoff in 2027, which on the one command that deletes rows would
    have pruned every retired credential rather than those retired before
    January. An absolute cutoff is used exactly as written.
    """
    if raw is None or not raw.strip():
        return None

    moment = now or datetime.now(UTC)
    text = raw.strip()

    duration = _parse_duration(text)
    if duration is not None:
        return moment - duration
    return _parse_absolute(text, what="cutoff")


def parse_scope_list(raw: str | None) -> frozenset[Scope]:
    """Validate requested scopes against the one scope registry.

    An unknown name is refused outright. Silently dropping it would issue a
    credential weaker than the operator asked for, and they would find out when
    something broke in production rather than here.
    """
    if raw is None or not raw.strip():
        raise typer.BadParameter(
            "--scopes is required. Grant the narrowest set that works; "
            f"known scopes are {', '.join(sorted(str(s) for s in all_scopes()))}"
        )

    requested = [chunk.strip() for chunk in raw.split(",") if chunk.strip()]
    resolved: set[Scope] = set()
    unknown: list[str] = []
    for name in requested:
        try:
            resolved.add(Scope(name))
        except ValueError:
            unknown.append(name)

    if unknown:
        raise typer.BadParameter(
            f"unknown scope(s): {', '.join(unknown)}. "
            f"Known scopes are {', '.join(sorted(str(s) for s in all_scopes()))}"
        )
    if not resolved:
        raise typer.BadParameter("--scopes resolved to nothing")
    return frozenset(resolved)


def _settings() -> ScrappySettings:
    settings = load_settings()
    configure_logging(level="ERROR", fmt=settings.log_format)
    return settings


async def _with_service(settings: ScrappySettings, action: Any) -> Any:
    """Open the store, build the service, run ``action``, close cleanly."""
    pepper = resolve_pepper(
        configured=settings.token_pepper.get_secret_value() if settings.token_pepper else None,
        data_dir=settings.data_dir,
    )
    async with open_store(settings.db_path) as store:
        service = CredentialService(
            SqliteCredentialStore(store),
            AuditLog(store),
            pepper=pepper.value,
            actor=local_cli_actor(),
        )
        return await action(service)


def _status_label(credential: Credential, now: datetime) -> str:
    return str(credential.status_at(now)).upper()


def _expiry_label(credential: Credential) -> str:
    if credential.expires_at is None:
        return "never"
    return credential.expires_at.strftime("%Y-%m-%d")


@token_app.command("create")
def create(
    actor: Annotated[str, typer.Option("--actor", help="Principal this credential proves.")],
    scopes: Annotated[
        str, typer.Option("--scopes", help="Comma-separated scopes. Required; grant narrowly.")
    ],
    actor_type: Annotated[
        str, typer.Option("--type", help="human | service | node | system.")
    ] = "service",
    display_name: Annotated[
        str | None, typer.Option("--name", help="Human-readable label.")
    ] = None,
    expires_in: Annotated[
        str | None,
        typer.Option("--expires-in", help="Duration like 30d, or an ISO-8601 timestamp."),
    ] = None,
) -> None:
    """Issue a credential. The token is printed once and never stored."""
    settings = _settings()
    granted = parse_scope_list(scopes)
    expires_at = parse_expiry(expires_in)
    try:
        resolved_type = ActorType(actor_type)
    except ValueError as exc:
        known = ", ".join(str(t) for t in ActorType)
        raise typer.BadParameter(
            f"unknown actor type {actor_type!r}; known types are {known}"
        ) from exc

    async def run(service: CredentialService) -> Any:
        return await service.create(
            actor_id=actor,
            actor_type=resolved_type,
            scopes=granted,
            display_name=display_name,
            expires_at=expires_at,
        )

    try:
        issued = asyncio.run(_with_service(settings, run))
    except CredentialError as exc:
        typer.echo(error(str(exc)))
        raise typer.Exit(1) from exc

    credential = issued.credential
    heading("Credential created")
    key_value("Credential ID", credential.credential_id)
    key_value("Actor", credential.actor_id)
    key_value("Actor Type", str(credential.actor_type))
    if credential.display_name:
        key_value("Name", credential.display_name)
    typer.echo()
    typer.echo("  Scopes:")
    for scope in sorted(str(s) for s in credential.scopes):
        typer.echo(f"    {scope}")
    typer.echo()
    key_value("Expires", credential.expires_at.isoformat() if credential.expires_at else "never")
    typer.echo()
    typer.echo("  Token:")
    typer.echo()
    typer.echo(f"    {bold(issued.token)}")
    typer.echo()
    typer.echo(warn("This token will not be shown again. Store it securely."))
    typer.echo(dim("  Nothing recorded it: only a keyed verifier was written to the database."))


@token_app.command("list")
def list_credentials(
    actor: Annotated[
        str | None, typer.Option("--actor", help="Only credentials for this principal.")
    ] = None,
    show_all: Annotated[
        bool, typer.Option("--all", help="Include revoked and expired credentials.")
    ] = False,
) -> None:
    """List credentials. Never shows a token, a verifier or the pepper."""
    settings = _settings()

    async def run(service: CredentialService) -> Any:
        return await service.list(actor_id=actor)

    credentials = asyncio.run(_with_service(settings, run))
    now = datetime.now(UTC)
    if not show_all:
        credentials = [c for c in credentials if c.is_usable_at(now)]

    if not credentials:
        heading("Credentials")
        typer.echo(dim("  none" + ("" if show_all else " active - pass --all to include retired")))
        return

    heading(f"{len(credentials)} credential(s)")
    render_table(
        ["ID", "Actor", "Type", "Status", "Expires", "Last used"],
        [
            [
                c.credential_id,
                c.actor_id,
                str(c.actor_type),
                _status_label(c, now),
                _expiry_label(c),
                c.last_used_at.strftime("%Y-%m-%d %H:%M") if c.last_used_at else "never",
            ]
            for c in credentials
        ],
    )


@token_app.command("inspect")
def inspect(credential_id: Annotated[str, typer.Argument(help="e.g. cred_a8f13e9c2b41")]) -> None:
    """Show everything about one credential except the parts that are secret."""
    settings = _settings()

    async def run(service: CredentialService) -> Any:
        return await service.get(credential_id)

    try:
        credential = asyncio.run(_with_service(settings, run))
    except CredentialNotFound as exc:
        typer.echo(error(str(exc)))
        raise typer.Exit(1) from exc

    now = datetime.now(UTC)
    heading(f"Credential {credential.credential_id}")
    key_value("Actor", credential.actor_id)
    key_value("Actor Type", str(credential.actor_type))
    key_value("Name", credential.display_name or "-")
    key_value("Status", _status_label(credential, now))
    key_value("Auth method", str(credential.auth_method))
    key_value("Created", credential.created_at.isoformat())
    key_value("Expires", credential.expires_at.isoformat() if credential.expires_at else "never")
    key_value("Revoked", credential.revoked_at.isoformat() if credential.revoked_at else "-")
    last_used = credential.last_used_at
    key_value("Last used", last_used.isoformat() if last_used else "never")
    typer.echo()
    typer.echo("  Scopes:")
    for scope in sorted(str(s) for s in credential.scopes):
        typer.echo(f"    {scope}")
    if credential.metadata:
        typer.echo()
        typer.echo("  Metadata:")
        for key, value in sorted(credential.metadata.items()):
            typer.echo(f"    {key}: {value}")


@token_app.command("revoke")
def revoke(credential_id: Annotated[str, typer.Argument(help="Credential to withdraw.")]) -> None:
    """Withdraw a credential. Effective on the next request, no restart needed."""
    settings = _settings()

    async def run(service: CredentialService) -> Any:
        return await service.revoke(credential_id)

    try:
        credential = asyncio.run(_with_service(settings, run))
    except CredentialNotFound as exc:
        typer.echo(error(str(exc)))
        raise typer.Exit(1) from exc

    heading("Credential revoked")
    key_value("Credential ID", credential.credential_id)
    key_value("Actor", credential.actor_id)
    key_value("Revoked", credential.revoked_at.isoformat() if credential.revoked_at else "-")
    typer.echo()
    typer.echo(dim("  Authentication reads the row on every request, so this is already in force."))


@token_app.command("rotate")
def rotate(
    credential_id: Annotated[str, typer.Argument(help="Credential to replace.")],
    revoke_previous: Annotated[
        bool,
        typer.Option(
            "--revoke-previous",
            help="Revoke the old credential immediately instead of leaving an overlap.",
        ),
    ] = False,
    expires_in: Annotated[
        str | None, typer.Option("--expires-in", help="Expiry for the replacement.")
    ] = None,
) -> None:
    """Issue a replacement for the same actor and scopes.

    By default the old credential stays valid so clients can be moved over
    without an outage. Revoke it once they are.
    """
    settings = _settings()
    expires_at = parse_expiry(expires_in)

    async def run(service: CredentialService) -> Any:
        return await service.rotate(
            credential_id, revoke_previous=revoke_previous, expires_at=expires_at
        )

    try:
        result = asyncio.run(_with_service(settings, run))
    except CredentialNotFound as exc:
        typer.echo(error(str(exc)))
        raise typer.Exit(1) from exc

    credential = result.issued.credential
    heading("Credential rotated")
    key_value("New credential", credential.credential_id)
    key_value("Replaces", result.previous.credential_id)
    key_value("Actor", credential.actor_id)
    key_value("Expires", credential.expires_at.isoformat() if credential.expires_at else "never")
    typer.echo()
    typer.echo("  Token:")
    typer.echo()
    typer.echo(f"    {bold(result.issued.token)}")
    typer.echo()
    typer.echo(warn("This token will not be shown again. Store it securely."))
    typer.echo()
    if result.previous_revoked:
        typer.echo(
            f"  {result.previous.credential_id} is revoked and no longer authenticates."
        )
    else:
        typer.echo(f"  {result.previous.credential_id} is still valid. Move clients over, then:")
        typer.echo(f"    scrappy token revoke {result.previous.credential_id}")


@token_app.command("prune")
def prune(
    older_than: Annotated[
        str, typer.Option("--older-than", help="Duration like 90d. Retention cutoff.")
    ] = "90d",
    yes: Annotated[bool, typer.Option("--yes", help="Do not ask for confirmation.")] = False,
) -> None:
    """Delete revoked or expired credential records past the retention cutoff.

    Active credentials are never removed regardless of age. This is the only
    command that loses data; the audit events describing each credential's
    creation and revocation survive it.
    """
    settings = _settings()
    now = datetime.now(UTC)
    cutoff = parse_cutoff(older_than, now=now)
    if cutoff is None:  # pragma: no cover - the option has a default
        raise typer.BadParameter("--older-than is required")

    async def preview(service: CredentialService) -> Any:
        candidates = []
        for credential in await service.list():
            if credential.status_at(now) is CredentialStatus.ACTIVE:
                continue
            retired = credential.revoked_at or credential.expires_at
            if retired is not None and retired < cutoff:
                candidates.append(credential)
        return candidates

    doomed = asyncio.run(_with_service(settings, preview))
    if not doomed:
        typer.echo(dim(f"  Nothing retired before {cutoff.date()}. Nothing to prune."))
        return

    heading(f"{len(doomed)} credential(s) eligible for deletion")
    render_table(
        ["ID", "Actor", "Status"],
        [[c.credential_id, c.actor_id, _status_label(c, now)] for c in doomed],
    )
    if not yes:
        typer.echo()
        typer.confirm("Delete these credential records?", abort=True)

    async def run(service: CredentialService) -> Any:
        return await service.prune(older_than=cutoff, now=now)

    removed = asyncio.run(_with_service(settings, run))
    typer.echo()
    typer.echo(f"  Deleted {len(removed)} credential record(s).")


__all__ = ["parse_cutoff", "parse_expiry", "parse_scope_list", "token_app"]
