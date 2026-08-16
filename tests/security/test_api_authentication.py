"""The API authentication boundary.

These tests exist to fail loudly if the boundary is ever weakened. They assert
on the *absence* of a credential, so unlike ``tests/integration/test_api.py``
they build their own unauthenticated client - a shared fixture that helpfully
adds a token would silently turn every assertion here into a tautology.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.identity import ActorType, AuthMethod, Scope, all_scopes
from scrappy_os.interface.api import create_app
from scrappy_os.security.authn import (
    AuthenticationFailed,
    AuthFailureReason,
    NullAuthenticator,
    StaticTokenAuthenticator,
    TokenCredential,
    build_authenticator,
    generate_token,
    parse_bearer,
)

pytestmark = pytest.mark.security

TOKEN = "correct-horse-battery-staple-correct-horse"
WRONG = "wrong-horse-battery-staple-wrong-horse-xxx"

#: Every endpoint that must never answer an anonymous caller, with a body where
#: one is needed. If an endpoint is added to the API without being added here,
#: `test_no_endpoint_is_reachable_anonymously` fails on the route inventory.
PROTECTED: tuple[tuple[str, str, dict[str, object] | None], ...] = (
    ("GET", "/status", None),
    ("POST", "/tasks", {"objective": "check disks"}),
    ("GET", "/tasks/some-id", None),
    ("GET", "/tasks/some-id/events", None),
    ("GET", "/approvals", None),
    ("POST", "/approvals/some-id", {"approved": True}),
    ("GET", "/audit", None),
)


@pytest.fixture
def authed_settings(settings: ScrappySettings) -> ScrappySettings:
    settings.ensure_directories()
    settings.api_token = SecretStr(TOKEN)
    return settings


@pytest.fixture
def anon(authed_settings: ScrappySettings) -> Iterator[TestClient]:
    """A client that sends no credential unless a test adds one."""
    with TestClient(create_app(authed_settings, with_heartbeat=False)) as client:
        yield client


@pytest.fixture
def tokenless(settings: ScrappySettings) -> Iterator[TestClient]:
    """A deployment with no token configured at all."""
    settings.ensure_directories()
    with TestClient(create_app(settings, with_heartbeat=False)) as client:
        yield client


# ---------------------------------------------------------------------------
# Header handling
# ---------------------------------------------------------------------------


def test_missing_authorization_header_is_401(anon: TestClient) -> None:
    response = anon.get("/status")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].startswith("Bearer")


def test_wrong_token_is_401(anon: TestClient) -> None:
    assert anon.get("/status", headers={"Authorization": f"Bearer {WRONG}"}).status_code == 401


@pytest.mark.parametrize(
    "header",
    [
        f"Basic {TOKEN}",
        TOKEN,
        "Bearer",
        "Bearer ",
        f"Token {TOKEN}",
        f"Bearer {TOKEN} extra",
        "",
        "   ",
    ],
)
def test_malformed_authorization_schemes_are_401(anon: TestClient, header: str) -> None:
    """Anything that is not exactly ``Bearer <token>`` is refused."""
    assert anon.get("/status", headers={"Authorization": header}).status_code == 401


def test_bearer_scheme_is_case_insensitive(anon: TestClient) -> None:
    """RFC 6750 makes the scheme case-insensitive; clients rely on it."""
    for scheme in ("Bearer", "bearer", "BEARER", "BeArEr"):
        response = anon.get("/status", headers={"Authorization": f"{scheme} {TOKEN}"})
        assert response.status_code == 200, scheme


def test_correct_token_is_accepted(anon: TestClient) -> None:
    assert anon.get("/status", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200


def test_no_endpoint_is_reachable_anonymously(anon: TestClient) -> None:
    """The whole privileged surface, one assertion per endpoint."""
    for method, path, body in PROTECTED:
        response = anon.request(method, path, json=body)
        assert response.status_code == 401, f"{method} {path} answered {response.status_code}"


def test_protected_list_covers_every_route(anon: TestClient) -> None:
    """Guards against an endpoint being added without an auth decision.

    ``/health`` is the single documented exception; everything else in the
    OpenAPI document must appear in PROTECTED above.
    """
    documented = {
        path
        for path in anon.get("/openapi.json").json()["paths"]
        if not path.startswith(("/docs", "/redoc", "/openapi"))
    }
    covered = {path for _, path, _ in PROTECTED}
    # Path templates in the document use {task_id}; PROTECTED uses a concrete id.
    normalised = {path.replace("some-id", "{task_id}") for path in covered}
    normalised |= {path.replace("some-id", "{approval_id}") for path in covered}
    missing = documented - normalised - {"/health"}
    assert not missing, f"endpoints with no authentication decision: {sorted(missing)}"


# ---------------------------------------------------------------------------
# A deployment with no credentials configured
# ---------------------------------------------------------------------------


def test_unconfigured_deployment_refuses_everything(tokenless: TestClient) -> None:
    """No token configured is fail-closed, not fail-open.

    This is the assertion that replaces "the API is safe because it is bound to
    localhost". Absent configuration must not mean absent enforcement.
    """
    for method, path, body in PROTECTED:
        response = tokenless.request(method, path, json=body)
        assert response.status_code == 401, f"{method} {path} answered {response.status_code}"


def test_unconfigured_deployment_still_serves_health(tokenless: TestClient) -> None:
    """Liveness survives having no credential; a supervisor needs it to."""
    response = tokenless.get("/health")
    assert response.status_code == 200
    assert response.json()["healthy"] is True


# ---------------------------------------------------------------------------
# /health, the one deliberate exception
# ---------------------------------------------------------------------------


def test_health_is_public_but_thin(anon: TestClient) -> None:
    body = anon.get("/health").json()
    assert body["healthy"] is True
    assert "components" not in body, "component detail is reconnaissance, not liveness"


def test_health_is_detailed_when_authenticated(anon: TestClient) -> None:
    body = anon.get("/health", headers={"Authorization": f"Bearer {TOKEN}"}).json()
    assert {item["name"] for item in body["components"]} >= {"store", "model_provider"}


def test_health_ignores_a_bad_credential_rather_than_failing(anon: TestClient) -> None:
    """A liveness probe must not go red because someone else's token expired."""
    response = anon.get("/health", headers={"Authorization": f"Bearer {WRONG}"})
    assert response.status_code == 200
    assert "components" not in response.json()


# ---------------------------------------------------------------------------
# The credential itself must not leak
# ---------------------------------------------------------------------------


def test_token_never_appears_in_any_response(anon: TestClient) -> None:
    """Sweep every endpoint, authenticated and not, for the secret."""
    responses = [anon.get("/health").text, anon.get("/status").text]
    for method, path, body in PROTECTED:
        responses.append(anon.request(method, path, json=body).text)
        responses.append(
            anon.request(
                method, path, json=body, headers={"Authorization": f"Bearer {TOKEN}"}
            ).text
        )
    for text in responses:
        assert TOKEN not in text


def test_failed_authentication_does_not_echo_the_presented_credential(anon: TestClient) -> None:
    """A 401 body must not reflect what was sent back at the sender.

    Reflecting it would put a mistyped *real* credential into any log or proxy
    that records response bodies.
    """
    response = anon.get("/status", headers={"Authorization": f"Bearer {WRONG}"})
    assert WRONG not in response.text


def test_openapi_document_does_not_contain_the_token(anon: TestClient) -> None:
    assert TOKEN not in anon.get("/openapi.json").text


# ---------------------------------------------------------------------------
# The authenticator in isolation
# ---------------------------------------------------------------------------


def test_parse_bearer_rejects_a_missing_header() -> None:
    with pytest.raises(AuthenticationFailed) as excinfo:
        parse_bearer(None)
    assert excinfo.value.reason is AuthFailureReason.MISSING_CREDENTIAL


def test_parse_bearer_rejects_a_wrong_scheme() -> None:
    with pytest.raises(AuthenticationFailed) as excinfo:
        parse_bearer("Basic abc")
    assert excinfo.value.reason is AuthFailureReason.MALFORMED_CREDENTIAL


def test_authentication_failure_never_carries_the_credential() -> None:
    """The exception is the thing most likely to be logged or re-raised."""
    authenticator = build_authenticator(SecretStr(TOKEN))
    with pytest.raises(AuthenticationFailed) as excinfo:
        authenticator.authenticate(f"Bearer {WRONG}")
    rendered = f"{excinfo.value.message} {excinfo.value.context} {excinfo.value!r}"
    assert WRONG not in rendered
    assert TOKEN not in rendered


def test_null_authenticator_accepts_nothing() -> None:
    authenticator = NullAuthenticator()
    assert authenticator.configured is False
    with pytest.raises(AuthenticationFailed) as excinfo:
        authenticator.authenticate(f"Bearer {TOKEN}")
    assert excinfo.value.reason is AuthFailureReason.NO_CREDENTIALS_CONFIGURED


def test_build_authenticator_returns_null_for_an_empty_token() -> None:
    """An empty string is not a credential, and must not become one."""
    assert isinstance(build_authenticator(None), NullAuthenticator)
    assert isinstance(build_authenticator(SecretStr("")), NullAuthenticator)


def test_multiple_credentials_are_all_accepted() -> None:
    """The seam token rotation will use: issue the new one, retire the old.

    Asserted now so a future rotation feature cannot be built on a checker that
    turns out to only ever have matched the first entry.
    """
    authenticator = StaticTokenAuthenticator(
        [
            TokenCredential(token=SecretStr("old-token-aaaaaaaaaaaaaaaa"), actor_id="old"),
            TokenCredential(token=SecretStr("new-token-bbbbbbbbbbbbbbbb"), actor_id="new"),
        ]
    )
    assert authenticator.credential_count == 2
    assert authenticator.authenticate("Bearer old-token-aaaaaaaaaaaaaaaa").id == "old"
    assert authenticator.authenticate("Bearer new-token-bbbbbbbbbbbbbbbb").id == "new"


def test_the_authenticated_actor_is_a_bearer_token_identity() -> None:
    actor = build_authenticator(SecretStr(TOKEN), actor_id="ci-runner").authenticate(
        f"Bearer {TOKEN}"
    )
    assert actor.id == "ci-runner"
    assert actor.auth_method is AuthMethod.BEARER_TOKEN
    assert actor.actor_type is ActorType.SERVICE
    assert actor.scopes == all_scopes()


def test_a_narrowed_token_grants_only_what_it_was_given() -> None:
    actor = build_authenticator(
        SecretStr(TOKEN), scopes=frozenset({Scope.TASK_READ})
    ).authenticate(f"Bearer {TOKEN}")
    assert actor.has_scope(Scope.TASK_READ)
    assert not actor.has_scope(Scope.TASK_CREATE)


def test_generated_tokens_are_unique_and_long() -> None:
    tokens = {generate_token() for _ in range(50)}
    assert len(tokens) == 50
    assert all(len(token) >= 32 for token in tokens)
