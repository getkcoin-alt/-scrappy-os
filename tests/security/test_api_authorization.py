"""Scope enforcement: a known caller doing something it may not.

Authentication asks *who*; these tests ask *may they*. The distinction is
visible in the status code, and it is load-bearing: a 401 tells a client to
present a credential, a 403 tells it that the credential it already has is not
enough, and confusing the two sends integrators down the wrong path.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.identity import (
    ANONYMOUS_ACTOR,
    SYSTEM_ACTOR,
    Actor,
    ActorType,
    AuthMethod,
    Scope,
    all_scopes,
    local_cli_actor,
    read_only_scopes,
)
from scrappy_os.interface.api import create_app
from scrappy_os.security.authz import AUTHORIZER, AuthorizationDenied, is_known_scope, parse_scopes

pytestmark = pytest.mark.security

TOKEN = "scoped-token-scoped-token-scoped-token"


def _client(settings: ScrappySettings, scopes: frozenset[Scope]) -> TestClient:
    settings.ensure_directories()
    settings.api_token = SecretStr(TOKEN)
    settings.api_token_scopes_raw = ",".join(sorted(str(scope) for scope in scopes))
    app = create_app(settings, with_heartbeat=False)
    return TestClient(app, headers={"Authorization": f"Bearer {TOKEN}"})


@pytest.fixture
def read_only(settings: ScrappySettings) -> Iterator[TestClient]:
    """A credential that may observe but never act."""
    with _client(settings, read_only_scopes()) as client:
        yield client


@pytest.fixture
def creator_only(settings: ScrappySettings) -> Iterator[TestClient]:
    """A credential that may submit work and nothing else."""
    with _client(settings, frozenset({Scope.TASK_CREATE})) as client:
        yield client


# ---------------------------------------------------------------------------
# Insufficient scope is 403, not 401 and certainly not 200
# ---------------------------------------------------------------------------


def test_read_only_credential_cannot_create_a_task(read_only: TestClient) -> None:
    response = read_only.post("/tasks", json={"objective": "restart nginx"})
    assert response.status_code == 403
    assert "task:create" in response.text


def test_read_only_credential_cannot_grant_an_approval(read_only: TestClient) -> None:
    """The scope guarding the most dangerous verb in the API."""
    response = read_only.post("/approvals/any-id", json={"approved": True})
    assert response.status_code == 403
    assert "approval:grant" in response.text


def test_approval_denial_also_requires_the_grant_scope(read_only: TestClient) -> None:
    """Refusing is a decision too, and it is recorded as one."""
    assert read_only.post("/approvals/any-id", json={"approved": False}).status_code == 403


def test_read_only_credential_may_observe(read_only: TestClient) -> None:
    assert read_only.get("/status").status_code == 200
    assert read_only.get("/audit").status_code == 200
    assert read_only.get("/approvals").status_code == 200


def test_creator_credential_may_create_but_not_read_audit(creator_only: TestClient) -> None:
    assert creator_only.post("/tasks", json={"objective": "check disks"}).status_code == 202
    assert creator_only.get("/audit").status_code == 403
    assert creator_only.get("/status").status_code == 403


def test_creator_credential_cannot_read_its_own_task(creator_only: TestClient) -> None:
    """task:create does not imply task:read. Scopes do not cascade."""
    created = creator_only.post("/tasks", json={"objective": "check disks"})
    objective_id = created.json()["objective_id"]
    assert creator_only.get(f"/tasks/{objective_id}").status_code == 403


def test_insufficient_scope_is_403_not_404(creator_only: TestClient) -> None:
    """Authorization is decided before the resource is looked up.

    Otherwise the status code becomes an existence oracle: 404 for a task that
    is not there, 403 for one that is, and a caller without task:read learns
    which task ids are real.
    """
    assert creator_only.get("/tasks/definitely-not-a-real-task").status_code == 403


def test_event_stream_requires_task_read(creator_only: TestClient) -> None:
    created = creator_only.post("/tasks", json={"objective": "check disks"})
    objective_id = created.json()["objective_id"]
    assert creator_only.get(f"/tasks/{objective_id}/events").status_code == 403


# ---------------------------------------------------------------------------
# The authorizer itself
# ---------------------------------------------------------------------------


def test_unknown_scope_is_denied() -> None:
    """A capability this build does not define is never granted."""
    verdict = AUTHORIZER.evaluate(local_cli_actor(username="root"), "task:crate")
    assert verdict.allowed is False
    assert verdict.rule == "unknown-scope"


def test_unknown_scope_is_denied_even_for_an_actor_holding_everything() -> None:
    """Holding every *known* scope must not imply holding an unknown one."""
    omnipotent = Actor(
        id="everything",
        actor_type=ActorType.SYSTEM,
        auth_method=AuthMethod.INTERNAL,
        scopes=all_scopes(),
    )
    assert AUTHORIZER.evaluate(omnipotent, "system:destroy").allowed is False


def test_anonymous_actor_is_denied_every_scope() -> None:
    for scope in Scope:
        verdict = AUTHORIZER.evaluate(ANONYMOUS_ACTOR, scope)
        assert verdict.allowed is False
        assert verdict.rule == "unauthenticated"


def test_authorize_raises_on_denial() -> None:
    with pytest.raises(AuthorizationDenied):
        AUTHORIZER.authorize(ANONYMOUS_ACTOR, Scope.TASK_CREATE)


def test_authorize_returns_a_verdict_on_success() -> None:
    verdict = AUTHORIZER.authorize(local_cli_actor(username="root"), Scope.TASK_CREATE)
    assert verdict.allowed is True
    assert verdict.rule == "scope-granted"


def test_verdict_dict_is_audit_safe() -> None:
    """What lands in an audit row must be plain, bounded facts."""
    payload = AUTHORIZER.evaluate(ANONYMOUS_ACTOR, Scope.AUDIT_READ).to_dict()
    assert set(payload) == {"allowed", "actor_id", "scope", "reason", "rule"}


def test_is_known_scope_rejects_non_strings() -> None:
    assert is_known_scope(Scope.TASK_READ)
    assert is_known_scope("task:read")
    assert not is_known_scope("task:write")
    assert not is_known_scope(None)
    assert not is_known_scope(42)


# ---------------------------------------------------------------------------
# Scope parsing from configuration
# ---------------------------------------------------------------------------


def test_parse_scopes_reads_a_csv_list() -> None:
    assert parse_scopes("task:read, audit:read") == {Scope.TASK_READ, Scope.AUDIT_READ}


def test_parse_scopes_rejects_an_unknown_name_rather_than_dropping_it() -> None:
    """A typo must not silently issue a credential nobody reviewed."""
    with pytest.raises(AuthorizationDenied) as excinfo:
        parse_scopes("task:read,task:crate")
    assert "task:crate" in excinfo.value.message


def test_empty_scope_configuration_grants_everything(settings: ScrappySettings) -> None:
    """Documented behaviour: narrowing is the explicit act, not the default."""
    settings.api_token_scopes_raw = ""
    assert settings.api_token_scopes == all_scopes()


# ---------------------------------------------------------------------------
# Actor invariants
# ---------------------------------------------------------------------------


def test_an_unauthenticated_actor_cannot_hold_scopes() -> None:
    """Making the dangerous state unrepresentable, rather than auditing for it."""
    with pytest.raises(ValueError, match="cannot hold scopes"):
        Actor(
            id="sneaky",
            actor_type=ActorType.HUMAN,
            auth_method=AuthMethod.NONE,
            scopes=frozenset({Scope.APPROVAL_GRANT}),
        )


def test_actors_are_frozen() -> None:
    """A component that could edit an actor could escalate by assignment."""
    actor = local_cli_actor(username="root")
    with pytest.raises(ValidationError):
        actor.id = "someone-else"  # type: ignore[misc]


def test_with_scopes_can_only_attenuate() -> None:
    """Delegation must never widen. The seam capability tokens will use."""
    narrow = Actor(
        id="svc",
        actor_type=ActorType.SERVICE,
        auth_method=AuthMethod.BEARER_TOKEN,
        scopes=frozenset({Scope.TASK_READ}),
    )
    widened = narrow.with_scopes(all_scopes())
    assert widened.scopes == {Scope.TASK_READ}


def test_system_actor_holds_no_scopes() -> None:
    """The runtime's own label is not a key to anything."""
    assert SYSTEM_ACTOR.scopes == frozenset()
    assert AUTHORIZER.evaluate(SYSTEM_ACTOR, Scope.APPROVAL_GRANT).allowed is False
