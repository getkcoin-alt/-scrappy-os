"""End-to-end SYNCBOND correlation tests at the HTTP boundary."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.syncbond import SYNCBOND_VERSION
from scrappy_os.interface.syncbond_http import create_app

pytestmark = pytest.mark.integration

API_TOKEN = "syncbond-test-token-with-enough-entropy"


@pytest.fixture
def sync_client(settings: ScrappySettings) -> Iterator[TestClient]:
    settings.ensure_directories()
    settings.api_token = SecretStr(API_TOKEN)
    app = create_app(settings, with_heartbeat=False)
    with TestClient(app, headers={"Authorization": f"Bearer {API_TOKEN}"}) as client:
        yield client


def _submit(client: TestClient, *, correlation_id: str | None = None) -> dict:
    headers: dict[str, str] = {}
    if correlation_id is not None:
        headers = {
            "X-Syncbond-Correlation-ID": correlation_id,
            "X-Syncbond-Version": SYNCBOND_VERSION,
        }
    response = client.post(
        "/tasks",
        headers=headers,
        json={"objective": "Inspect disk usage", "max_risk": "read", "dry_run": False},
    )
    assert response.status_code == 202
    return response.json()


def _wait(client: TestClient, objective_id: str) -> dict:
    for _ in range(200):
        response = client.get(f"/tasks/{objective_id}")
        assert response.status_code == 200
        payload = response.json()
        if payload.get("state") != "running":
            return payload
        time.sleep(0.02)
    raise AssertionError("task did not finish")


def test_valid_correlation_survives_create_and_status(sync_client: TestClient) -> None:
    correlation_id = str(uuid4())
    created = _submit(sync_client, correlation_id=correlation_id)

    assert created["correlation_id"] == correlation_id
    assert created["syncbond_version"] == SYNCBOND_VERSION

    status = _wait(sync_client, created["objective_id"])
    assert status["correlation_id"] == correlation_id
    assert status["syncbond_version"] == SYNCBOND_VERSION


def test_invalid_correlation_is_rejected_before_execution(sync_client: TestClient) -> None:
    response = sync_client.post(
        "/tasks",
        headers={
            "X-Syncbond-Correlation-ID": "not-a-uuid",
            "X-Syncbond-Version": SYNCBOND_VERSION,
        },
        json={"objective": "Inspect disk usage"},
    )
    assert response.status_code == 400
    assert "must be a UUID" in response.json()["detail"]


def test_unsupported_syncbond_version_fails_explicitly(sync_client: TestClient) -> None:
    response = sync_client.post(
        "/tasks",
        headers={
            "X-Syncbond-Correlation-ID": str(uuid4()),
            "X-Syncbond-Version": "99.0.0",
        },
        json={"objective": "Inspect disk usage"},
    )
    assert response.status_code == 400
    assert "unsupported SYNCBOND version" in response.json()["detail"]


def test_absent_header_does_not_invent_continuity(sync_client: TestClient) -> None:
    created = _submit(sync_client)
    assert created["correlation_id"] is None
    assert "syncbond_version" not in created

    status = sync_client.get(f"/tasks/{created['objective_id']}").json()
    assert status["correlation_id"] is None
    assert "syncbond_version" not in status


def test_sse_events_carry_the_original_correlation(sync_client: TestClient) -> None:
    correlation_id = str(uuid4())
    created = _submit(sync_client, correlation_id=correlation_id)
    _wait(sync_client, created["objective_id"])

    seen_data = False
    with sync_client.stream("GET", f"/tasks/{created['objective_id']}/events") as stream:
        assert stream.status_code == 200
        for line in stream.iter_lines():
            if not line.startswith("data: "):
                continue
            payload = json.loads(line[6:])
            assert payload["correlation_id"] == correlation_id
            assert payload["syncbond_version"] == SYNCBOND_VERSION
            seen_data = True
            if payload.get("type") in {"task.completed", "task.failed", "task.cancelled"}:
                break

    assert seen_data is True
