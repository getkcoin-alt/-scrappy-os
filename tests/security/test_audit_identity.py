"""What the audit trail records about security events, and what it must not.

The taxonomy matters. An operator triaging an incident needs to tell these
apart at a glance, because they mean very different things:

* ``auth.failed``      - somebody could not prove who they are (possibly a scan)
* ``authz.denied``     - a known principal reached past its scopes
* ``security.denied``  - policy refused an operation inside an authorised task
* ``tool.failed``      - the operation was allowed and did not work

Collapsing any two of those into one event type would make "is this an attack
or a misconfigured client" unanswerable from the log.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.enums import EventType
from scrappy_os.core.identity import Scope
from scrappy_os.interface.api import create_app

pytestmark = pytest.mark.security

TOKEN = "audit-identity-token-audit-identity"
WRONG = "not-the-right-token-not-the-right-x"


@pytest.fixture
def client(settings: ScrappySettings) -> Iterator[TestClient]:
    settings.ensure_directories()
    settings.api_token = SecretStr(TOKEN)
    settings.api_token_actor_id = "auditor"
    app = create_app(settings, with_heartbeat=False)
    with TestClient(app) as test_client:
        yield test_client


def _events(client: TestClient, limit: int = 200) -> list[dict[str, object]]:
    response = client.get(
        "/audit", params={"limit": limit}, headers={"Authorization": f"Bearer {TOKEN}"}
    )
    events: list[dict[str, object]] = response.json()["events"]
    return events


# ---------------------------------------------------------------------------
# The taxonomy
# ---------------------------------------------------------------------------


def test_authentication_failure_is_audited(client: TestClient) -> None:
    client.get("/status", headers={"Authorization": f"Bearer {WRONG}"})
    types = [event["event_type"] for event in _events(client)]
    assert str(EventType.AUTH_FAILED) in types


def test_authentication_success_is_audited(client: TestClient) -> None:
    client.get("/status", headers={"Authorization": f"Bearer {TOKEN}"})
    events = _events(client)
    successes = [
        event for event in events if event["event_type"] == str(EventType.AUTH_SUCCEEDED)
    ]
    assert successes
    assert successes[0]["actor_id"] == "auditor"
    assert successes[0]["success"] is True


def test_authorization_failure_is_a_distinct_event(settings: ScrappySettings) -> None:
    """A known caller exceeding its scopes is not an authentication failure."""
    settings.ensure_directories()
    settings.api_token = SecretStr(TOKEN)
    settings.api_token_actor_id = "narrow"
    settings.api_token_scopes_raw = str(Scope.AUDIT_READ)
    with TestClient(create_app(settings, with_heartbeat=False)) as client:
        client.post(
            "/tasks",
            json={"objective": "restart nginx"},
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        events = _events(client)

    denials = [event for event in events if event["event_type"] == str(EventType.AUTHZ_DENIED)]
    assert denials, "an out-of-scope request must be recorded as an authorization denial"
    assert denials[0]["actor_id"] == "narrow"
    assert denials[0]["payload"]["scope"] == str(Scope.TASK_CREATE)
    assert denials[0]["payload"]["rule"] == "missing-scope"

    types = [event["event_type"] for event in events]
    assert str(EventType.AUTH_FAILED) not in types, "the caller authenticated fine"


def test_the_four_security_event_types_are_distinct() -> None:
    """Guards against a refactor collapsing the taxonomy."""
    distinct = {
        EventType.AUTH_FAILED,
        EventType.AUTHZ_DENIED,
        EventType.SECURITY_DENIED,
        EventType.TOOL_FAILED,
    }
    assert len({str(item) for item in distinct}) == 4


# ---------------------------------------------------------------------------
# What must never reach a durable record
# ---------------------------------------------------------------------------


def test_the_authorization_header_never_reaches_the_audit_log(client: TestClient) -> None:
    """Neither a valid credential nor a guessed one is stored.

    The failed case matters most: an attacker's guesses are attacker-controlled
    strings, and a log that stores them is a place to inject content that some
    later viewer will render.
    """
    client.get("/status", headers={"Authorization": f"Bearer {WRONG}"})
    client.get("/status", headers={"Authorization": f"Bearer {TOKEN}"})

    body = client.get(
        "/audit", params={"limit": 200}, headers={"Authorization": f"Bearer {TOKEN}"}
    ).text
    assert TOKEN not in body
    assert WRONG not in body
    assert "authorization" not in body.lower()


def test_a_failed_authentication_records_a_reason_not_a_credential(client: TestClient) -> None:
    client.get("/status", headers={"Authorization": f"Bearer {WRONG}"})
    failures = [
        event for event in _events(client) if event["event_type"] == str(EventType.AUTH_FAILED)
    ]
    assert failures
    payload = failures[0]["payload"]
    assert payload["reason"] == "unknown_credential"
    assert "token" not in payload
    assert "credential" not in {key for key in payload if key != "reason"}


def test_an_anonymous_failure_is_not_attributed_to_a_principal(client: TestClient) -> None:
    """A failed attempt must not appear to be an action by a real actor."""
    client.get("/status")
    failures = [
        event for event in _events(client) if event["event_type"] == str(EventType.AUTH_FAILED)
    ]
    assert failures
    assert failures[0]["actor_id"] == "anonymous"
    assert failures[0]["success"] is False


def test_request_provenance_is_recorded_without_headers(client: TestClient) -> None:
    """Enough to investigate, nothing that could carry a secret."""
    client.get("/status", headers={"Authorization": f"Bearer {WRONG}", "X-Secret": "hunter2"})
    failures = [
        event for event in _events(client) if event["event_type"] == str(EventType.AUTH_FAILED)
    ]
    payload = failures[0]["payload"]
    assert payload["method"] == "GET"
    assert payload["path"] == "/status"
    assert "hunter2" not in str(payload)
