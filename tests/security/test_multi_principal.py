"""Several credentials, several principals, one API.

The milestone's headline claim is that authority is per-credential rather than
per-deployment: two tokens reaching the same server are two different principals
with different scopes and separately attributable audit trails. That claim is
only worth anything if it holds through the real HTTP stack, so these tests
drive the app rather than the authenticator.

Credentials are written through a *second* database connection, which is how
production works too: ``scrappy token create`` runs in its own process and the
server never learns about it except by reading the row. A test that reached into
the server's own store would prove something weaker.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.identity import ActorType, Scope
from scrappy_os.interface.api import create_app
from scrappy_os.memory.store import Store
from scrappy_os.security.credential_store import SqliteCredentialStore
from scrappy_os.security.credentials import issue_credential

pytestmark = pytest.mark.security

PEPPER = "multi-principal-test-pepper-long-enough"

OPERATOR_SCOPES = frozenset(
    {Scope.TASK_CREATE, Scope.TASK_READ, Scope.AUDIT_READ, Scope.SYSTEM_READ}
)
READER_SCOPES = frozenset({Scope.TASK_READ, Scope.SYSTEM_READ})


@pytest.fixture
def api(settings: ScrappySettings) -> Iterator[TestClient]:
    """A server whose only authentication is stored credentials.

    ``api_token`` is left unset on purpose: with a legacy token configured, a
    test could pass because of the wrong mechanism.
    """
    settings.ensure_directories()
    settings.token_pepper = SecretStr(PEPPER)
    settings.api_token = None
    with TestClient(create_app(settings, with_heartbeat=False)) as client:
        yield client


def issue(
    settings: ScrappySettings,
    actor_id: str,
    scopes: frozenset[Scope],
    *,
    actor_type: ActorType = ActorType.SERVICE,
    display_name: str | None = None,
    created_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> tuple[str, str]:
    """Mint a credential out-of-band. Returns ``(token, credential_id)``."""

    async def go() -> tuple[str, str]:
        store = Store(settings.db_path)
        await store.connect()
        try:
            issued = issue_credential(
                actor_id=actor_id,
                actor_type=actor_type,
                scopes=scopes,
                pepper=PEPPER,
                display_name=display_name,
                created_at=created_at,
                expires_at=expires_at,
            )
            await SqliteCredentialStore(store).create(issued.credential)
            return issued.token, issued.credential.credential_id
        finally:
            await store.close()

    return asyncio.run(go())


def revoke(settings: ScrappySettings, credential_id: str) -> None:
    async def go() -> None:
        store = Store(settings.db_path)
        await store.connect()
        try:
            await SqliteCredentialStore(store).revoke(
                credential_id, when=datetime.now(UTC)
            )
        finally:
            await store.close()

    asyncio.run(go())


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def audit_rows(settings: ScrappySettings, event_type: str) -> list[dict[str, Any]]:
    async def go() -> list[dict[str, Any]]:
        store = Store(settings.db_path)
        await store.connect()
        try:
            return await store.fetch_all(
                "SELECT * FROM audit_events WHERE event_type = ? ORDER BY rowid",
                (event_type,),
            )
        finally:
            await store.close()

    return asyncio.run(go())


# ---------------------------------------------------------------------------
# Two principals
# ---------------------------------------------------------------------------


def test_two_credentials_authenticate_as_two_actors(
    api: TestClient, settings: ScrappySettings
) -> None:
    """The smoke sequence from the milestone, as a test."""
    operator, _ = issue(settings, "smoke-operator", OPERATOR_SCOPES)
    reader, _ = issue(settings, "smoke-reader", READER_SCOPES)

    created = api.post("/tasks", json={"objective": "check disks"}, headers=auth(operator))
    assert created.status_code == 202
    assert created.json()["actor_id"] == "smoke-operator"

    refused = api.post("/tasks", json={"objective": "check disks"}, headers=auth(reader))
    assert refused.status_code == 403, "the reader must not be able to create work"

    assert api.get("/status", headers=auth(reader)).status_code == 200


def test_neither_credential_can_borrow_the_others_authority(
    api: TestClient, settings: ScrappySettings
) -> None:
    """Scopes travel with the credential, not with the deployment."""
    operator, _ = issue(settings, "smoke-operator", OPERATOR_SCOPES)
    reader, _ = issue(settings, "smoke-reader", READER_SCOPES)

    assert api.get("/audit", headers=auth(operator)).status_code == 200
    assert api.get("/audit", headers=auth(reader)).status_code == 403


def test_the_actor_cannot_be_chosen_by_the_client(
    api: TestClient, settings: ScrappySettings
) -> None:
    """Identity comes from the row, whatever the request says it is."""
    reader, _ = issue(settings, "smoke-reader", READER_SCOPES)

    response = api.post(
        "/tasks",
        json={"objective": "check disks", "actor": "smoke-operator"},
        headers=auth(reader),
    )
    # Either the field is refused outright or it is ignored; what must never
    # happen is a 202 attributed to the actor the caller named.
    assert response.status_code in {403, 422}
    if response.status_code == 202:  # pragma: no cover - documented impossibility
        assert response.json()["actor_id"] == "smoke-reader"


def test_audit_attributes_each_request_to_its_own_credential(
    api: TestClient, settings: ScrappySettings
) -> None:
    """Two principals, two trails. This is what per-credential identity buys."""
    operator, operator_id = issue(settings, "smoke-operator", OPERATOR_SCOPES)
    reader, reader_id = issue(settings, "smoke-reader", READER_SCOPES)

    api.get("/status", headers=auth(operator))
    api.get("/status", headers=auth(reader))

    rows = audit_rows(settings, "auth.succeeded")
    seen = {
        row["actor_id"]: json.loads(row["payload"])["credential_id"]
        for row in rows
        if row["actor_id"] in {"smoke-operator", "smoke-reader"}
    }
    assert seen == {"smoke-operator": operator_id, "smoke-reader": reader_id}


def test_a_denial_is_attributed_to_the_credential_that_was_denied(
    api: TestClient, settings: ScrappySettings
) -> None:
    reader, _ = issue(settings, "smoke-reader", READER_SCOPES)
    api.post("/tasks", json={"objective": "check disks"}, headers=auth(reader))

    denials = audit_rows(settings, "authz.denied")
    assert denials, "a 403 must leave a record"
    assert denials[-1]["actor_id"] == "smoke-reader"


# ---------------------------------------------------------------------------
# Rotation, revocation, expiry - over HTTP, with no restart
# ---------------------------------------------------------------------------


def test_rotation_overlaps_and_then_the_old_token_dies(
    api: TestClient, settings: ScrappySettings
) -> None:
    """The whole point of overlap: no window where nothing works."""
    old, old_id = issue(settings, "smoke-operator", OPERATOR_SCOPES)
    assert api.get("/status", headers=auth(old)).status_code == 200

    new, _ = issue(settings, "smoke-operator", OPERATOR_SCOPES)
    assert api.get("/status", headers=auth(old)).status_code == 200, "overlap"
    assert api.get("/status", headers=auth(new)).status_code == 200, "overlap"

    revoke(settings, old_id)
    assert api.get("/status", headers=auth(old)).status_code == 401
    assert api.get("/status", headers=auth(new)).status_code == 200


def test_revocation_takes_effect_on_the_next_request(
    api: TestClient, settings: ScrappySettings
) -> None:
    """No restart, no cache, no window."""
    token, credential_id = issue(settings, "smoke-operator", OPERATOR_SCOPES)
    assert api.get("/status", headers=auth(token)).status_code == 200

    revoke(settings, credential_id)
    assert api.get("/status", headers=auth(token)).status_code == 401


def test_an_expired_credential_is_refused(api: TestClient, settings: ScrappySettings) -> None:
    """Backdated rather than slept on, so the boundary is exact."""
    long_ago = datetime.now(UTC) - timedelta(days=30)
    token, _ = issue(
        settings,
        "smoke-operator",
        OPERATOR_SCOPES,
        created_at=long_ago,
        expires_at=long_ago + timedelta(hours=1),
    )
    assert api.get("/status", headers=auth(token)).status_code == 401


def test_a_credential_expiring_later_still_works(
    api: TestClient, settings: ScrappySettings
) -> None:
    token, _ = issue(
        settings,
        "smoke-operator",
        OPERATOR_SCOPES,
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )
    assert api.get("/status", headers=auth(token)).status_code == 200


# ---------------------------------------------------------------------------
# Abuse
# ---------------------------------------------------------------------------


def test_revoked_and_nonexistent_are_indistinguishable_to_the_caller(
    api: TestClient, settings: ScrappySettings
) -> None:
    """Telling a thief when they were noticed is a courtesy to the thief."""
    token, credential_id = issue(settings, "smoke-operator", OPERATOR_SCOPES)
    revoke(settings, credential_id)

    revoked = api.get("/status", headers=auth(token))
    unknown = api.get("/status", headers=auth("scrp_a8f13e9c2b41_nosuchsecretatall"))

    assert revoked.status_code == unknown.status_code == 401
    assert revoked.json() == unknown.json()
    assert revoked.headers.get("WWW-Authenticate") == unknown.headers.get("WWW-Authenticate")


def test_the_audit_distinguishes_what_the_caller_cannot(
    api: TestClient, settings: ScrappySettings
) -> None:
    """The operator-only half of the previous test.

    "A client nobody migrated is still presenting an expired token" and "someone
    is guessing credential ids" are the same 401 and completely different
    operational events. The trail has to separate them even though the wire
    cannot.
    """
    long_ago = datetime.now(UTC) - timedelta(days=30)
    expired, _ = issue(
        settings,
        "smoke-operator",
        OPERATOR_SCOPES,
        created_at=long_ago,
        expires_at=long_ago + timedelta(hours=1),
    )
    api.get("/status", headers=auth(expired))
    api.get("/status", headers=auth("scrp_a8f13e9c2b41_nosuchsecretatall"))

    details = [
        json.loads(row["payload"]).get("detail")
        for row in audit_rows(settings, "auth.failed")
    ]
    assert "credential_expired" in details
    assert "no_such_credential" in details


def test_an_oversized_authorization_header_is_refused(api: TestClient) -> None:
    """Bounded work on unauthenticated input."""
    response = api.get("/status", headers=auth("scrp_a8f13e9c2b41_" + "x" * 100_000))
    assert response.status_code == 401


def test_duplicate_authorization_headers_do_not_authenticate(
    api: TestClient, settings: ScrappySettings
) -> None:
    """Two headers is not "try both" - it is a malformed request.

    Regression. ``request.headers.get`` returns the *first* and silently drops
    the rest, so this pair authenticated as the valid token while nothing
    recorded that a second credential was presented. Behind a proxy that adds its
    own Authorization header, the proxy would enforce on one and this server
    would audit the other.

    Order is parametrised because "first wins" and "last wins" are both wrong in
    the same way.
    """
    token, _ = issue(settings, "smoke-operator", OPERATOR_SCOPES)
    valid = ("Authorization", f"Bearer {token}")
    junk = ("Authorization", "Bearer nonsense")

    assert api.get("/status", headers=[valid, junk]).status_code == 401
    assert api.get("/status", headers=[junk, valid]).status_code == 401
    assert api.get("/status", headers=[valid, valid]).status_code == 401
    assert api.get("/status", headers=[valid]).status_code == 200, "one is still fine"


@pytest.mark.parametrize(
    "template",
    [
        "Bearer  {token}",
        "Bearer\t{token}",
        " Bearer {token}",
        "Bearer {token} ",
        "Bearer {token}\t",
    ],
    ids=["double-space", "tab", "leading", "trailing", "trailing-tab"],
)
def test_whitespace_variations_around_a_valid_token(
    api: TestClient, settings: ScrappySettings, template: str
) -> None:
    """Whitespace is split on, not stripped into meaning.

    These are all *accepted*: ``split()`` collapses runs of whitespace, so each
    of these is exactly two parts and the token itself is untouched. The test
    pins that as deliberate - the failure to avoid is a variant that smuggles a
    different value past the parser, and there is none here.
    """
    token, _ = issue(settings, "smoke-operator", OPERATOR_SCOPES)
    header = {"Authorization": template.format(token=token)}
    assert api.get("/status", headers=header).status_code == 200


@pytest.mark.parametrize(
    "value",
    [
        "scrp_",
        "scrp_a8f13e9c2b41",
        "scrp_a8f13e9c2b41_",
        "cred_a8f13e9c2b41",
        "scrp__secret",
        "SCRP_A8F13E9C2B41_secret",
        "scrp_a8f13e9c2b41_secret_extra_underscores",
    ],
    ids=[
        "prefix-only",
        "id-without-secret",
        "empty-secret",
        "credential-id-as-token",
        "missing-id",
        "uppercased-prefix",
        "extra-underscores",
    ],
)
def test_token_prefix_confusion_is_refused(api: TestClient, value: str) -> None:
    """Anything token-shaped but not a token gets the same 401 as garbage."""
    assert api.get("/status", headers=auth(value)).status_code == 401


def test_a_credential_id_alone_does_not_authenticate(
    api: TestClient, settings: ScrappySettings
) -> None:
    """The id half is not secret; it must not be sufficient."""
    _, credential_id = issue(settings, "smoke-operator", OPERATOR_SCOPES)
    id_hex = credential_id.split("_", 1)[1]
    assert api.get("/status", headers=auth(f"scrp_{id_hex}_")).status_code == 401
    assert api.get("/status", headers=auth(credential_id)).status_code == 401


def test_a_hostile_display_name_does_not_forge_audit_rows(
    api: TestClient, settings: ScrappySettings
) -> None:
    """Names are operator-supplied, but they are still untrusted text.

    The payload here is shaped to break a line-oriented log reader: newlines, a
    fake log prefix, an ANSI escape and a NUL-adjacent control character. It must
    land in the record as one literal value and produce no extra rows.
    """
    hostile = "eve\n2026-01-01 auth.succeeded actor=root\x1b[31m\r admin"
    token, _ = issue(
        settings,
        "svc-eve",
        READER_SCOPES,
        display_name=hostile,
    )
    api.get("/status", headers=auth(token))

    rows = [row for row in audit_rows(settings, "auth.succeeded") if row["actor_id"] == "svc-eve"]
    assert len(rows) == 1, "one request must produce exactly one row"
    assert rows[0]["actor_id"] == "svc-eve"
    # display_name is commentary, and `Actor.audit_fields` excludes it. That is
    # what keeps this payload from being a place to write into: the hostile
    # string is not in the record at all, forged prefix and all.
    assert hostile not in json.dumps(json.loads(rows[0]["payload"]))
    assert not [row for row in audit_rows(settings, "auth.succeeded") if row["actor_id"] == "root"]


def test_a_unicode_actor_id_round_trips_intact(
    api: TestClient, settings: ScrappySettings
) -> None:
    """Non-ASCII identities are ordinary, not an attack. They must not corrupt."""
    actor_id = "kärnvir-ᚱ-服务-🔑"
    token, _ = issue(settings, actor_id, READER_SCOPES)
    assert api.get("/status", headers=auth(token)).status_code == 200

    rows = [row for row in audit_rows(settings, "auth.succeeded") if row["actor_id"] == actor_id]
    assert len(rows) == 1


def test_no_raw_token_reaches_the_audit_trail(
    api: TestClient, settings: ScrappySettings
) -> None:
    """The sweep, on the one database that outlives the process."""
    token, _ = issue(settings, "smoke-operator", OPERATOR_SCOPES)
    api.get("/status", headers=auth(token))
    api.get("/status", headers=auth(token + "-tampered"))

    _, secret = token.rsplit("_", 1)
    blob = settings.db_path.read_bytes()
    assert secret.encode() not in blob
    assert PEPPER.encode() not in blob
