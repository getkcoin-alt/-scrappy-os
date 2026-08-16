"""Security-sensitive configuration: loads correctly, never leaks.

Two failure modes, both quiet, both tested here:

* A secret that is **silently ignored** - the operator sets a token, believes
  the API is protected, and it is not. An alias that stops working is a security
  regression even though nothing looks broken.
* A secret that **leaks** - into ``config show``, a log line, a traceback, an
  audit row, or a ``repr`` in a debugger.

The existing ``openai_api_key`` is asserted alongside the new ``api_token``,
because the mechanism is shared and a change that protects one while dropping
the other would otherwise pass.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from pydantic import SecretStr

from scrappy_os.core.config import SECRET_FIELDS, ScrappySettings, load_settings
from scrappy_os.core.identity import Scope, all_scopes

pytestmark = pytest.mark.security

SECRET = "super-secret-token-value-do-not-print"
API_KEY = "sk-secret-openai-key-do-not-print"


# ---------------------------------------------------------------------------
# Loading: the value must actually arrive
# ---------------------------------------------------------------------------


def test_api_token_loads_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCRAPPY_API_TOKEN", SECRET)
    settings = ScrappySettings()
    assert settings.api_token is not None
    assert settings.api_token.get_secret_value() == SECRET
    assert settings.api_auth_configured is True


def test_api_token_loads_by_field_name(tmp_path: Path) -> None:
    """``populate_by_name`` must keep working: YAML and kwargs use field names."""
    settings = ScrappySettings(api_token=SecretStr(SECRET), data_dir=tmp_path)
    assert settings.api_token is not None
    assert settings.api_token.get_secret_value() == SECRET


def test_api_token_loads_from_a_yaml_config_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The YAML path is a supported way to configure a deployment."""
    config = tmp_path / "scrappy.yaml"
    config.write_text(f"api_token: {SECRET}\napi_token_actor_id: from-yaml\n", encoding="utf-8")
    monkeypatch.setenv("SCRAPPY_CONFIG_FILE", str(config))
    settings = load_settings()
    assert settings.api_token is not None
    assert settings.api_token.get_secret_value() == SECRET
    assert settings.api_token_actor_id == "from-yaml"


def test_environment_beats_the_yaml_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Documented precedence, asserted for the field where it matters most."""
    config = tmp_path / "scrappy.yaml"
    config.write_text("api_token: from-the-file\n", encoding="utf-8")
    monkeypatch.setenv("SCRAPPY_CONFIG_FILE", str(config))
    monkeypatch.setenv("SCRAPPY_API_TOKEN", SECRET)
    settings = load_settings()
    assert settings.api_token is not None
    assert settings.api_token.get_secret_value() == SECRET


def test_environment_beats_yaml_for_aliased_fields_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The precedence fix must work through validation aliases, not just names.

    ``allowed_read_roots`` is the YAML spelling of ``allowed_read_roots_raw``.
    A fix that only matched field names would leave every aliased setting -
    including the read roots that bound what the agent can see - still being
    overridden by a stale file.
    """
    config = tmp_path / "scrappy.yaml"
    config.write_text("allowed_read_roots: /etc\n", encoding="utf-8")
    monkeypatch.setenv("SCRAPPY_CONFIG_FILE", str(config))
    monkeypatch.setenv("SCRAPPY_ALLOWED_READ_ROOTS", "/proc,/sys")
    assert load_settings().allowed_read_roots_raw == "/proc,/sys"


def test_yaml_still_applies_when_the_environment_is_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fix must not turn into "YAML is ignored"."""
    config = tmp_path / "scrappy.yaml"
    config.write_text("max_plan_steps: 7\napi_token_actor_id: from-yaml\n", encoding="utf-8")
    monkeypatch.setenv("SCRAPPY_CONFIG_FILE", str(config))
    monkeypatch.delenv("SCRAPPY_MAX_PLAN_STEPS", raising=False)
    settings = load_settings()
    assert settings.max_plan_steps == 7
    assert settings.api_token_actor_id == "from-yaml"


def test_explicit_arguments_still_beat_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Top of the documented precedence order, unchanged."""
    monkeypatch.setenv("SCRAPPY_API_TOKEN", "from-the-environment")
    settings = load_settings(None, api_token=SecretStr(SECRET), data_dir=tmp_path)
    assert settings.api_token is not None
    assert settings.api_token.get_secret_value() == SECRET


def test_an_unset_token_is_not_configured() -> None:
    settings = ScrappySettings()
    assert settings.api_token is None
    assert settings.api_auth_configured is False


def test_an_empty_token_does_not_count_as_configured() -> None:
    """An empty string is a common shape of "unset" in .env files."""
    settings = ScrappySettings(api_token=SecretStr(""))
    assert settings.api_auth_configured is False


def test_existing_aliases_still_work(monkeypatch: pytest.MonkeyPatch) -> None:
    """v0.1 alias behaviour is unchanged; regressing it would be silent."""
    monkeypatch.setenv("OPENAI_API_KEY", API_KEY)
    monkeypatch.setenv("SCRAPPY_MODEL", "gpt-4o")
    monkeypatch.setenv("SCRAPPY_SHELL_ALLOWLIST", "ls,cat")
    settings = ScrappySettings()
    assert settings.openai_api_key is not None
    assert settings.openai_api_key.get_secret_value() == API_KEY
    assert settings.model_name == "gpt-4o"
    assert settings.shell_allowlist == ("ls", "cat")


def test_token_scopes_load_and_narrow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCRAPPY_API_TOKEN_SCOPES", "task:read,audit:read")
    settings = ScrappySettings()
    assert settings.api_token_scopes == {Scope.TASK_READ, Scope.AUDIT_READ}


def test_unset_token_scopes_grant_everything() -> None:
    assert ScrappySettings().api_token_scopes == all_scopes()


# ---------------------------------------------------------------------------
# Redaction: the value must never be rendered
# ---------------------------------------------------------------------------


def test_redacted_dict_hides_the_token_but_admits_it_exists() -> None:
    """An operator must be able to tell "set" from "unset" without seeing it."""
    settings = ScrappySettings(api_token=SecretStr(SECRET), openai_api_key=SecretStr(API_KEY))
    rendered = settings.redacted_dict()
    assert rendered["api_token"] == "<set>"
    assert rendered["openai_api_key"] == "<set>"
    assert SECRET not in json.dumps(rendered, default=str)
    assert API_KEY not in json.dumps(rendered, default=str)


def test_redacted_dict_reports_an_unset_token() -> None:
    assert ScrappySettings().redacted_dict()["api_token"] == "<unset>"


def test_every_secret_field_is_redacted() -> None:
    """Guards the list itself.

    A future secret added to the settings without being added to SECRET_FIELDS
    would be dumped in full by ``config show``; this fails when that happens.
    """
    values = {name: f"leaked-value-for-{name}" for name in SECRET_FIELDS}
    settings = ScrappySettings(**{name: SecretStr(value) for name, value in values.items()})
    rendered = json.dumps(settings.redacted_dict(), default=str)
    for name, value in values.items():
        assert value not in rendered, f"{name} leaked through redacted_dict()"
        assert rendered.count(f'"{name}"') == 1, f"{name} must still appear as a marker"


def test_secret_fields_matches_the_declared_secret_types() -> None:
    """Every SecretStr field on the model must be in SECRET_FIELDS.

    Catches the reverse mistake: declaring a field as SecretStr (so it looks
    protected) while forgetting the redaction list that ``config show`` uses.
    """
    declared = {
        name
        for name, field in ScrappySettings.model_fields.items()
        if "SecretStr" in str(field.annotation)
    }
    assert declared == set(SECRET_FIELDS)


def test_repr_does_not_leak_the_token() -> None:
    """The shape that leaks in a debugger, a crash dump or an f-string."""
    settings = ScrappySettings(api_token=SecretStr(SECRET))
    assert SECRET not in repr(settings)
    assert SECRET not in str(settings)
    assert SECRET not in repr(settings.api_token)
    assert SECRET not in f"{settings.api_token}"


def test_model_dump_does_not_leak_the_token() -> None:
    """``mode="json"`` is what serialises into API responses and log payloads."""
    settings = ScrappySettings(api_token=SecretStr(SECRET))
    assert SECRET not in json.dumps(settings.model_dump(mode="json"), default=str)


def test_exception_from_bad_settings_does_not_leak_the_token() -> None:
    """A traceback is a leak path: validation errors echo offending input."""
    with pytest.raises(Exception) as excinfo:
        ScrappySettings(api_token=SecretStr(SECRET), api_port=999_999)
    assert SECRET not in str(excinfo.value)
    assert SECRET not in repr(excinfo.value)


def test_token_does_not_reach_the_log_stream(caplog: pytest.LogCaptureFixture) -> None:
    """Constructing and rendering settings must emit nothing sensitive."""
    with caplog.at_level(logging.DEBUG):
        settings = ScrappySettings(api_token=SecretStr(SECRET))
        settings.redacted_dict()
        logging.getLogger("scrappy").info("settings loaded: %s", settings)
    assert SECRET not in caplog.text


def test_config_show_output_has_no_secret(capsys: pytest.CaptureFixture[str]) -> None:
    """The exact command an operator runs when pasting output into a ticket."""
    from typer.testing import CliRunner

    from scrappy_os.interface.cli import app

    runner = CliRunner()
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setenv("SCRAPPY_API_TOKEN", SECRET)
        monkeypatch.setenv("OPENAI_API_KEY", API_KEY)
        result = runner.invoke(app, ["config", "show"])
        json_result = runner.invoke(app, ["config", "show", "--json"])

    assert result.exit_code == 0
    assert SECRET not in result.output
    assert API_KEY not in result.output
    assert "<set>" in result.output

    assert json_result.exit_code == 0
    assert SECRET not in json_result.output
    assert API_KEY not in json_result.output


def test_doctor_output_has_no_secret() -> None:
    """Doctor reports that a token exists and how long it is, never what it is."""
    from typer.testing import CliRunner

    from scrappy_os.interface.cli import app

    runner = CliRunner()
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setenv("SCRAPPY_API_TOKEN", SECRET)
        result = runner.invoke(app, ["doctor", "--skip-provider"])

    assert SECRET not in result.output
    assert "bearer token configured" in result.output
