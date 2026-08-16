"""The local HTTP API.

Uses FastAPI's TestClient, which drives the real lifespan - so the runtime
actually starts, the store is real, and the assertions are about the shipped
behaviour rather than a mock of it.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from scrappy_os.core.config import ScrappySettings
from scrappy_os.interface.api import create_app

pytestmark = pytest.mark.integration


@pytest.fixture
def client(settings: ScrappySettings) -> Iterator[TestClient]:
    settings.ensure_directories()
    with TestClient(create_app(settings, with_heartbeat=False)) as test_client:
        yield test_client


def _wait_for_task(client: TestClient, objective_id: str, *, attempts: int = 200) -> dict:
    """Poll until the task leaves the running state."""
    import time

    for _ in range(attempts):
        payload = client.get(f"/tasks/{objective_id}").json()
        if payload.get("state") != "running":
            return payload
        time.sleep(0.02)
    raise AssertionError("task did not finish in time")


def test_health_reports_component_status(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200

    body = response.json()
    assert body["healthy"] is True
    assert body["version"]
    names = {component["name"] for component in body["components"]}
    assert {"store", "model_provider", "tools"} <= names


def test_status_reports_the_development_provider_honestly(client: TestClient) -> None:
    """An operator must never mistake the rule table for a model."""
    body = client.get("/status").json()
    assert body["development_provider"] is True
    assert body["provider"] == "mock"
    assert "system.disk" in body["tools"]


def test_status_does_not_leak_the_api_key(client: TestClient, settings: ScrappySettings) -> None:
    from pydantic import SecretStr

    settings.openai_api_key = SecretStr("sk-must-not-appear-in-status")
    assert "sk-must-not-appear-in-status" not in client.get("/status").text


def test_submitting_an_objective_returns_202_and_completes(client: TestClient) -> None:
    response = client.post(
        "/tasks",
        json={"objective": "Inspect disk usage and tell me what filesystem is most full"},
    )
    assert response.status_code == 202
    objective_id = response.json()["objective_id"]

    result = _wait_for_task(client, objective_id)
    assert result["succeeded"] is True
    assert result["state"] == "completed"
    assert result["steps"], "the task should have run at least one tool"
    assert all(step["risk"] == "read" for step in result["steps"])


def test_task_submission_rejects_unknown_fields(client: TestClient) -> None:
    """`extra=forbid` on the request body, same as everywhere else."""
    response = client.post("/tasks", json={"objective": "check disks", "bypass_policy": True})
    assert response.status_code == 422


def test_task_submission_rejects_an_empty_objective(client: TestClient) -> None:
    assert client.post("/tasks", json={"objective": ""}).status_code == 422


def test_unknown_task_is_404(client: TestClient) -> None:
    assert client.get("/tasks/not-a-real-id").status_code == 404


def test_audit_endpoint_returns_the_trail(client: TestClient) -> None:
    response = client.post("/tasks", json={"objective": "Check disk usage"})
    objective_id = response.json()["objective_id"]
    result = _wait_for_task(client, objective_id)

    audit = client.get("/audit", params={"task_id": result["task_id"]}).json()
    recorded = [event["event_type"] for event in audit["events"]]
    assert "task.created" in recorded
    assert "tool.completed" in recorded
    assert audit["calls"], "the tool-call ledger should have rows"


def test_audit_endpoint_bounds_its_result(client: TestClient) -> None:
    assert client.get("/audit", params={"limit": 0}).status_code == 422
    assert client.get("/audit", params={"limit": 5000}).status_code == 422


def test_event_stream_replays_task_events(client: TestClient) -> None:
    response = client.post("/tasks", json={"objective": "Check disk usage"})
    objective_id = response.json()["objective_id"]
    _wait_for_task(client, objective_id)

    with client.stream("GET", f"/tasks/{objective_id}/events") as stream:
        assert stream.status_code == 200
        body = ""
        for chunk in stream.iter_text():
            body += chunk
            if "task.completed" in body or "task.failed" in body:
                break

    assert "task.created" in body
    assert "data: " in body


def test_approvals_endpoint_is_empty_for_read_only_work(client: TestClient) -> None:
    body = client.get("/approvals").json()
    assert body == {"pending": [], "count": 0}


def test_resolving_an_unknown_approval_is_404(client: TestClient) -> None:
    response = client.post(
        "/approvals/00000000-0000-0000-0000-000000000000", json={"approved": True}
    )
    assert response.status_code == 404


def test_the_api_cannot_approve_on_its_own(client: TestClient, settings: ScrappySettings) -> None:
    """A privileged step parks; the HTTP layer never self-approves.

    The API installs no interactive approver, so a task needing approval fails
    with an instruction rather than proceeding.
    """
    response = client.post(
        "/tasks",
        json={
            "objective": "restart the nginx service",
            "max_risk": "privileged",
        },
    )
    objective_id = response.json()["objective_id"]
    result = _wait_for_task(client, objective_id)

    privileged_steps = [
        step for step in result.get("steps", []) if step["risk"] in {"privileged", "destructive"}
    ]
    for step in privileged_steps:
        assert not step["success"], "no privileged step may run without a human"


def test_openapi_document_is_served(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    assert schema["info"]["title"] == "Scrappy OS"
    for path in ("/health", "/status", "/tasks", "/audit"):
        assert path in schema["paths"]
