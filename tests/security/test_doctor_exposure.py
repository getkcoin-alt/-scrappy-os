"""``scrappy doctor`` on the exposure question.

The check exists because the dangerous configuration is a *combination*, and
neither half is worth alarming about alone. Loopback with no token is the
shipped default. A token with an off-host bind is a real deployment. Reachable
by strangers *and* unable to identify them is the one that has to be a FAIL,
because a WARN in that state is something an operator scrolls past.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from scrappy_os.core.config import ScrappySettings
from scrappy_os.interface.doctor import CheckStatus, run_doctor

pytestmark = pytest.mark.security

TOKEN = "a-perfectly-adequate-doctor-token"


def _check(report: object, name: str) -> object:
    results = report.results  # type: ignore[attr-defined]
    matches = [result for result in results if result.name == name]
    assert matches, f"no check named {name!r}"
    return matches[0]


async def _report(settings: ScrappySettings) -> object:
    return await run_doctor(settings, check_provider=False)


async def test_loopback_without_a_token_passes_the_binding_check(
    settings: ScrappySettings,
) -> None:
    """The shipped default is not a problem and must not be reported as one."""
    settings.api_host = "127.0.0.1"
    settings.api_token = None
    report = await _report(settings)
    assert _check(report, "api binding").status is CheckStatus.PASS  # type: ignore[attr-defined]
    assert report.healthy is True  # type: ignore[attr-defined]


async def test_loopback_without_a_token_warns_about_authentication(
    settings: ScrappySettings,
) -> None:
    """Worth mentioning - the HTTP API is unusable - but not a failure."""
    settings.api_host = "127.0.0.1"
    settings.api_token = None
    result = _check(await _report(settings), "api authentication")
    assert result.status is CheckStatus.WARN  # type: ignore[attr-defined]


async def test_exposed_without_a_token_is_a_failure(settings: ScrappySettings) -> None:
    """The loud case. Both halves wrong at once."""
    settings.api_host = "0.0.0.0"
    settings.api_token = None

    report = await _report(settings)
    binding = _check(report, "api binding")
    assert binding.status is CheckStatus.FAIL  # type: ignore[attr-defined]
    assert "reachable off this host" in binding.detail  # type: ignore[attr-defined]
    assert "SCRAPPY_API_TOKEN" in binding.remedy  # type: ignore[attr-defined]
    assert report.healthy is False, "doctor must exit non-zero here"  # type: ignore[attr-defined]


async def test_exposed_with_a_token_warns_but_does_not_fail(settings: ScrappySettings) -> None:
    """A defensible deployment. Still worth saying what a bearer token is not."""
    settings.api_host = "0.0.0.0"
    settings.api_token = SecretStr(TOKEN)

    report = await _report(settings)
    binding = _check(report, "api binding")
    assert binding.status is CheckStatus.WARN  # type: ignore[attr-defined]
    assert "replayable" in binding.remedy  # type: ignore[attr-defined]
    assert report.healthy is True  # type: ignore[attr-defined]


async def test_a_short_token_is_called_out(settings: ScrappySettings) -> None:
    settings.api_token = SecretStr("short")
    result = _check(await _report(settings), "api authentication")
    assert result.status is CheckStatus.WARN  # type: ignore[attr-defined]


async def test_doctor_never_prints_the_token(settings: ScrappySettings) -> None:
    """Doctor reports presence and length. Never the value."""
    settings.api_token = SecretStr(TOKEN)
    report = await _report(settings)
    rendered = " ".join(
        f"{result.detail} {result.remedy or ''}"
        for result in report.results  # type: ignore[attr-defined]
    )
    assert TOKEN not in rendered


async def test_configured_token_reports_its_actor_and_scopes(settings: ScrappySettings) -> None:
    settings.api_token = SecretStr(TOKEN)
    settings.api_token_actor_id = "ci-runner"
    settings.api_token_scopes_raw = "task:read,audit:read"
    result = _check(await _report(settings), "api authentication")
    assert result.status is CheckStatus.PASS  # type: ignore[attr-defined]
    assert "ci-runner" in result.detail  # type: ignore[attr-defined]
    assert "task:read" in result.detail  # type: ignore[attr-defined]


def test_exposure_property_requires_both_halves() -> None:
    """The predicate itself, stated as a truth table."""
    exposed_no_token = ScrappySettings(api_host="0.0.0.0")
    exposed_token = ScrappySettings(api_host="0.0.0.0", api_token=SecretStr(TOKEN))
    local_no_token = ScrappySettings(api_host="127.0.0.1")
    local_token = ScrappySettings(api_host="127.0.0.1", api_token=SecretStr(TOKEN))

    assert exposed_no_token.api_exposure_is_unsafe is True
    assert exposed_token.api_exposure_is_unsafe is False
    assert local_no_token.api_exposure_is_unsafe is False
    assert local_token.api_exposure_is_unsafe is False


# ---------------------------------------------------------------------------
# A credential can be present and still be no credential at all.
# ---------------------------------------------------------------------------


async def test_a_guessable_token_on_an_exposed_bind_is_a_failure(
    settings: ScrappySettings,
) -> None:
    """A six-character secret facing the network is the no-token case wearing a hat.

    This previously reported WARN and let doctor exit 0, so a deployment
    pipeline gating on the exit code would ship it. The exposure is materially
    the same as having no token: the whole keyspace is searchable.
    """
    settings.api_host = "0.0.0.0"
    settings.api_token = SecretStr("abc123")

    report = await _report(settings)
    result = _check(report, "api authentication")
    assert result.status is CheckStatus.FAIL  # type: ignore[attr-defined]
    assert report.healthy is False  # type: ignore[attr-defined]


async def test_a_guessable_token_on_loopback_is_only_a_warning(
    settings: ScrappySettings,
) -> None:
    """The escalation must be driven by reachability, not by length alone."""
    settings.api_host = "127.0.0.1"
    settings.api_token = SecretStr("abc123")

    report = await _report(settings)
    assert _check(report, "api authentication").status is CheckStatus.WARN  # type: ignore[attr-defined]
    assert report.healthy is True  # type: ignore[attr-defined]


@pytest.mark.parametrize("blank", ["   ", "\t", "\n", " \t "])
async def test_a_whitespace_only_token_is_reported_as_no_token(
    settings: ScrappySettings, blank: str
) -> None:
    """Whitespace cannot be presented in a bearer header, so it is not a credential.

    `parse_bearer` splits the header on whitespace and requires exactly two
    parts, so no client can ever send this value. Reporting it as configured
    would promise an operator authentication that refuses every caller.
    """
    settings.api_host = "127.0.0.1"
    settings.api_token = SecretStr(blank)

    assert settings.api_auth_configured is False
    result = _check(await _report(settings), "api authentication")
    assert result.status is CheckStatus.WARN  # type: ignore[attr-defined]
    assert "no SCRAPPY_API_TOKEN" in result.detail  # type: ignore[attr-defined]


async def test_a_whitespace_only_token_on_an_exposed_bind_still_fails(
    settings: ScrappySettings,
) -> None:
    """The dangerous combination must not be masked by a token-shaped blank."""
    settings.api_host = "0.0.0.0"
    settings.api_token = SecretStr("   ")

    report = await _report(settings)
    assert _check(report, "api binding").status is CheckStatus.FAIL  # type: ignore[attr-defined]
    assert report.healthy is False  # type: ignore[attr-defined]
