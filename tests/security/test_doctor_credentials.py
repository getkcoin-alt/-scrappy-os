"""``scrappy doctor`` on where the token pepper lives.

The pepper is the difference between a stolen database being useless and a
stolen database being a list of testable guesses. An operator cannot see which
of the two they have by looking at the process, so doctor has to say. These
tests pin the three answers - environment, generated-on-disk, absent - and the
two things the check must never do: leak the key, or create one.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from scrappy_os.core.config import ScrappySettings
from scrappy_os.interface.doctor import CheckResult, CheckStatus, DoctorReport, run_doctor
from scrappy_os.security.pepper import PEPPER_FILENAME

pytestmark = pytest.mark.security

PEPPER = "a-perfectly-adequate-doctor-pepper"


def _check(report: DoctorReport, name: str) -> CheckResult:
    matches = [result for result in report.results if result.name == name]
    assert matches, f"no check named {name!r}"
    return matches[0]


async def _report(settings: ScrappySettings) -> DoctorReport:
    settings.ensure_directories()
    return await run_doctor(settings, check_provider=False)


async def test_an_environment_pepper_passes(settings: ScrappySettings) -> None:
    """The production answer: the key is not in the directory it protects."""
    settings.token_pepper = SecretStr(PEPPER)
    check = _check(await _report(settings), "credentials")
    assert check.status is CheckStatus.PASS
    assert "environment" in check.detail


async def test_no_pepper_yet_warns_rather_than_failing(
    settings: ScrappySettings,
) -> None:
    """A fresh install is not broken; it has simply not issued anything."""
    settings.token_pepper = None
    check = _check(await _report(settings), "credentials")
    assert check.status is CheckStatus.WARN
    assert check.remedy is not None
    assert "SCRAPPY_TOKEN_PEPPER" in check.remedy


async def test_a_generated_pepper_warns_that_it_sits_beside_the_database(
    settings: ScrappySettings,
) -> None:
    """Works out of the box, and honestly weaker. Doctor should say the second part."""
    settings.token_pepper = None
    settings.ensure_directories()
    pepper_file = settings.data_dir / PEPPER_FILENAME
    pepper_file.write_text("a-generated-pepper-value", encoding="utf-8")
    pepper_file.chmod(0o600)

    check = _check(await _report(settings), "credentials")
    assert check.status is CheckStatus.WARN
    assert "data directory" in check.detail


async def test_a_world_readable_pepper_is_a_failure(
    settings: ScrappySettings,
) -> None:
    """Anything that can read the pepper and the database can test guesses."""
    settings.token_pepper = None
    settings.ensure_directories()
    pepper_file = settings.data_dir / PEPPER_FILENAME
    pepper_file.write_text("a-generated-pepper-value", encoding="utf-8")
    pepper_file.chmod(0o644)

    check = _check(await _report(settings), "credentials")
    assert check.status is CheckStatus.FAIL
    assert "0o600" in check.detail or "600" in check.detail


async def test_the_check_never_prints_the_pepper(settings: ScrappySettings) -> None:
    """Doctor output gets pasted into issue trackers."""
    settings.token_pepper = SecretStr(PEPPER)
    report = await _report(settings)
    assert PEPPER not in str([(r.name, r.detail, r.remedy) for r in report.results])


async def test_the_check_does_not_create_a_pepper(settings: ScrappySettings) -> None:
    """Running doctor on a fresh install must not quietly mint a key.

    If it did, an operator who then set SCRAPPY_TOKEN_PEPPER would be left with
    an orphan file that looks like it is protecting something.
    """
    settings.token_pepper = None
    settings.ensure_directories()
    await _report(settings)
    assert not (settings.data_dir / PEPPER_FILENAME).exists()


async def test_the_credential_count_is_reported(settings: ScrappySettings) -> None:
    """Zero active credentials is the fact an operator needs when nothing works."""
    settings.token_pepper = SecretStr(PEPPER)
    check = _check(await _report(settings), "credentials")
    assert "0 active credential" in check.detail
