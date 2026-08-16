"""Doctor must say out loud how much privilege this instance is holding.

The policy engine confines operations a model proposed. Those boundaries live
in this process, so the account the process runs as decides what they are worth.
Doctor is the one place an operator looks before handing over work, so the
privilege facts belong there rather than only in deploy documentation.

The properties under test:

* An unprivileged run passes and says so.
* Running as root warns, even when everything else is fine.
* Root plus an off-host listener fails, because that combination is an
  unauthenticated remote root control plane rather than two separate warnings.
* A failing privilege check makes the whole report unhealthy.
"""

from __future__ import annotations

import pytest

from scrappy_os.core.config import ScrappySettings
from scrappy_os.interface.doctor import CheckStatus, _check_privileges


def test_unprivileged_run_passes(
    settings: ScrappySettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    result = _check_privileges(settings)
    assert result.status is CheckStatus.PASS
    assert "1000" in result.detail


def test_root_warns_even_when_bound_to_loopback(
    settings: ScrappySettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Loopback is not a reason to stay quiet about running as root."""
    monkeypatch.setattr("os.geteuid", lambda: 0)
    settings.api_host = "127.0.0.1"
    result = _check_privileges(settings)
    assert result.status is CheckStatus.WARN
    assert "root" in result.detail
    assert result.remedy is not None
    assert "deploy/README.md" in result.remedy


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "10.0.0.5"])
def test_root_plus_offhost_listener_fails(
    settings: ScrappySettings, monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    monkeypatch.setattr("os.geteuid", lambda: 0)
    settings.api_host = host
    result = _check_privileges(settings)
    assert result.status is CheckStatus.FAIL
    assert not result.ok, "a FAIL must make the report unhealthy"


def test_the_check_never_reports_pass_as_root(
    settings: ScrappySettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whatever else changes, root must never come back clean."""
    monkeypatch.setattr("os.geteuid", lambda: 0)
    for host in ("127.0.0.1", "localhost", "0.0.0.0", "192.168.1.10"):
        settings.api_host = host
        assert _check_privileges(settings).status is not CheckStatus.PASS
