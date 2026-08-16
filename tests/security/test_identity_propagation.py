"""Following one authenticated actor all the way through the system.

The claim v0.2 makes is that the audit trail can answer:

    WHO requested WHAT, through WHICH task, using WHICH agent and tool,
    under WHICH policy, with WHICH result.

A test per hop would let the chain break in the gaps between them, so the
central test here walks the whole path in one go - API request, task,
orchestration, policy decision, tool invocation, audit event - and asserts the
same principal is identifiable at every stage.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.identity import (
    Actor,
    ActorType,
    AuthMethod,
    Scope,
    agent_actor,
    all_scopes,
    local_cli_actor,
)
from scrappy_os.core.models import ApprovalDecision, Objective, ToolCall
from scrappy_os.interface.api import create_app

pytestmark = pytest.mark.security

TOKEN = "propagation-token-propagation-token"
ACTOR_ID = "alice-the-operator"


@pytest.fixture
def client(settings: ScrappySettings) -> Iterator[TestClient]:
    settings.ensure_directories()
    settings.api_token = SecretStr(TOKEN)
    settings.api_token_actor_id = ACTOR_ID
    app = create_app(settings, with_heartbeat=False)
    with TestClient(app, headers={"Authorization": f"Bearer {TOKEN}"}) as test_client:
        yield test_client


def _wait_for_task(client: TestClient, objective_id: str, *, attempts: int = 200) -> dict[str, Any]:
    for _ in range(attempts):
        payload = client.get(f"/tasks/{objective_id}").json()
        if payload.get("state") != "running":
            return payload
        time.sleep(0.02)
    raise AssertionError("task did not finish in time")


# ---------------------------------------------------------------------------
# The full chain
# ---------------------------------------------------------------------------


def test_an_authenticated_actor_is_traceable_from_request_to_audit(client: TestClient) -> None:
    """API request -> task -> orchestration -> policy -> tool -> audit."""
    created = client.post("/tasks", json={"objective": "Inspect disk usage"})
    assert created.status_code == 202
    # 1. The response attributes the work to the authenticated principal, not
    #    to anything the request body said.
    assert created.json()["actor_id"] == ACTOR_ID

    objective_id = created.json()["objective_id"]
    result = _wait_for_task(client, objective_id)
    assert result["succeeded"] is True
    task_id = result["task_id"]

    trail = client.get("/audit", params={"task_id": task_id}).json()
    events = trail["events"]
    calls = trail["calls"]

    # 2. The task was created by this principal.
    created_events = [event for event in events if event["event_type"] == "task.created"]
    assert created_events, "the run must record a task.created event"
    assert created_events[0]["actor_id"] == ACTOR_ID
    assert created_events[0]["actor_type"] == str(ActorType.SERVICE)
    assert created_events[0]["auth_method"] == str(AuthMethod.BEARER_TOKEN)

    # 3. Tool calls carry both the proximate agent and the accountable principal.
    assert calls, "the run must have invoked at least one tool"
    for call in calls:
        assert call["actor_id"] == ACTOR_ID, "every tool call traces to the principal"
        assert call["actor"].startswith("agent:"), "the proposing agent is recorded too"

    # 4. Each call records the policy decision that let it through.
    assert all(call["policy_decision"] for call in calls)
    assert all(call["policy_rule"] for call in calls)

    # 5. And the result.
    assert all(call["success"] is not None for call in calls)

    # 6. The authentication event itself is in the trail.
    recent = client.get("/audit", params={"limit": 200}).json()["events"]
    auth_events = [event for event in recent if event["event_type"] == "auth.succeeded"]
    assert auth_events, "successful authentication must be auditable"
    assert auth_events[0]["actor_id"] == ACTOR_ID


def test_the_audit_trail_answers_who_asked_for_what(client: TestClient) -> None:
    """The question the milestone is actually about, asked literally."""
    created = client.post("/tasks", json={"objective": "Inspect disk usage"})
    task_id = _wait_for_task(client, created.json()["objective_id"])["task_id"]

    trail = client.get("/audit", params={"task_id": task_id}).json()
    answer = {
        "who": {event["actor_id"] for event in trail["events"] if event["actor_id"]},
        "what": {call["tool_name"] for call in trail["calls"]},
        "under_which_policy": {call["policy_rule"] for call in trail["calls"]},
        "with_which_result": {bool(call["success"]) for call in trail["calls"]},
    }
    assert answer["who"] == {ACTOR_ID}
    assert answer["what"], "which tools ran"
    assert answer["under_which_policy"], "under which rule"
    assert answer["with_which_result"], "and how it turned out"


# ---------------------------------------------------------------------------
# The identity cannot be forged by the client
# ---------------------------------------------------------------------------


def test_a_client_cannot_name_itself_in_the_task_body(client: TestClient) -> None:
    """The v0.1 hole, closed and asserted.

    ``extra="forbid"`` turns the old field into an explicit 422 rather than a
    silent ignore, so a v0.1 client learns its actor claim is no longer honoured
    instead of believing it still works.
    """
    response = client.post(
        "/tasks", json={"objective": "check disks", "actor": "root"}
    )
    assert response.status_code == 422


def test_a_client_cannot_name_its_own_approver(client: TestClient) -> None:
    response = client.post(
        "/approvals/some-id", json={"approved": True, "decided_by": "the-cto"}
    )
    assert response.status_code == 422


def test_the_actor_label_follows_the_verified_identity() -> None:
    """A supplied label is overwritten by the authenticated one, never merged."""
    actor = Actor(
        id="real-principal",
        actor_type=ActorType.HUMAN,
        auth_method=AuthMethod.BEARER_TOKEN,
        scopes=all_scopes(),
    )
    objective = Objective(text="do a thing", actor="i-am-root", identity=actor)
    assert objective.actor == actor.label
    assert "i-am-root" not in objective.actor


def test_an_approval_decision_label_follows_the_verified_identity() -> None:
    decision = ApprovalDecision(
        request_id="abc",
        approved=True,
        decided_by="somebody-else",
        identity=local_cli_actor(username="root"),
    )
    assert decision.decided_by == "human:root"


# ---------------------------------------------------------------------------
# Agents act under a principal, never as one
# ---------------------------------------------------------------------------


def test_an_agent_actor_holds_no_scopes() -> None:
    """A model deciding to do something does not authorize it."""
    agent = agent_actor("brahma", on_behalf_of=local_cli_actor(username="root"))
    assert agent.scopes == frozenset()
    assert not agent.has_scope(Scope.APPROVAL_GRANT)


def test_an_agent_actor_records_who_it_acts_for() -> None:
    agent = agent_actor("brahma", on_behalf_of=local_cli_actor(username="root"))
    assert agent.metadata["on_behalf_of"] == "root"


def test_a_tool_call_keeps_the_agent_and_the_principal_apart() -> None:
    """Two different questions: who proposed this, and who answers for it."""
    principal = local_cli_actor(username="root")
    call = ToolCall(
        task_id="t1",
        tool_name="system.disk",
        actor="agent:brahma",
        identity=principal,
    )
    assert call.actor == "agent:brahma"
    assert call.identity is not None
    assert call.identity.id == "root"


# ---------------------------------------------------------------------------
# The CLI's identity is distinguishable from an API caller's
# ---------------------------------------------------------------------------


def test_the_cli_actor_is_marked_as_a_local_process() -> None:
    """An operator must be able to tell shell access from a stolen token."""
    actor = local_cli_actor(username="root")
    assert actor.auth_method is AuthMethod.LOCAL_PROCESS
    assert actor.actor_type is ActorType.HUMAN
    assert actor.scopes == all_scopes()


def test_cli_and_api_actors_are_distinguishable_in_audit_fields() -> None:
    cli = local_cli_actor(username="root").audit_fields()
    api = Actor(
        id="ci",
        actor_type=ActorType.SERVICE,
        auth_method=AuthMethod.BEARER_TOKEN,
        scopes=all_scopes(),
    ).audit_fields()
    assert cli["auth_method"] != api["auth_method"]
    assert cli["actor_type"] != api["actor_type"]
