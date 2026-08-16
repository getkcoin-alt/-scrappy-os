"""Settings resolution and orchestration budgets."""

from __future__ import annotations

from pathlib import Path

import pytest

from scrappy_os.brain.limits import TaskBudget
from scrappy_os.core.config import ScrappySettings, load_settings, load_yaml_overrides
from scrappy_os.core.enums import RiskLevel
from scrappy_os.core.errors import ConfigurationError, LimitExceeded

# ---------------------------------------------------------------------------
# settings
# ---------------------------------------------------------------------------


def test_defaults_are_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    """A fresh install must be read-only, offline and local."""
    for variable in ("SCRAPPY_MODEL_PROVIDER", "SCRAPPY_DEFAULT_MAX_RISK", "SCRAPPY_API_HOST"):
        monkeypatch.delenv(variable, raising=False)
    settings = ScrappySettings(_env_file=None)  # type: ignore[call-arg]

    assert settings.model_provider == "mock"
    assert settings.default_max_risk is RiskLevel.READ
    assert settings.api_is_local_only
    assert not settings.http_allow_private_networks
    assert settings.allow_approvals


def test_environment_variables_are_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCRAPPY_MODEL_PROVIDER", "ollama")
    monkeypatch.setenv("SCRAPPY_MODEL", "llama3")
    monkeypatch.setenv("SCRAPPY_MAX_PLAN_STEPS", "3")
    settings = ScrappySettings(_env_file=None)  # type: ignore[call-arg]

    assert settings.model_provider == "ollama"
    assert settings.model_name == "llama3"
    assert settings.max_plan_steps == 3


def test_unprefixed_credential_variables_are_honoured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OPENAI_API_KEY and OLLAMA_BASE_URL are conventional names, not ours to rename."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-from-env")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://gpu-box:11434")
    settings = ScrappySettings(_env_file=None)  # type: ignore[call-arg]

    assert settings.openai_api_key is not None
    assert settings.openai_api_key.get_secret_value() == "sk-from-env"
    assert settings.ollama_base_url == "http://gpu-box:11434"


def test_secret_does_not_appear_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-should-not-print")
    settings = ScrappySettings(_env_file=None)  # type: ignore[call-arg]
    assert "sk-should-not-print" not in repr(settings)


def test_csv_settings_parse_into_tuples() -> None:
    """Field names work as well as env aliases, so YAML config files apply."""
    settings = ScrappySettings(
        _env_file=None,  # type: ignore[call-arg]
        allowed_read_roots_raw="/etc, /var/log ,/etc",
        shell_allowlist_raw="ls,cat,ls",
    )
    assert settings.allowed_read_roots == (Path("/etc"), Path("/var/log"))
    assert settings.shell_allowlist == ("ls", "cat")


def test_empty_csv_setting_is_empty_not_a_blank_entry() -> None:
    settings = ScrappySettings(_env_file=None, shell_allowlist_raw="")  # type: ignore[call-arg]
    assert settings.shell_allowlist == ()


def test_paths_are_expanded(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    settings = ScrappySettings(_env_file=None, data_dir=Path("~/scrappy"))  # type: ignore[call-arg]
    assert settings.data_dir == tmp_path / "scrappy"


def test_base_urls_are_normalised() -> None:
    settings = ScrappySettings(
        _env_file=None,  # type: ignore[call-arg]
        openai_base_url="https://api.example.com/v1/",
    )
    assert settings.openai_base_url == "https://api.example.com/v1"


def test_out_of_range_values_are_refused() -> None:
    from pydantic import ValidationError

    for kwargs in (
        {"max_plan_steps": 0},
        {"max_plan_steps": 1000},
        {"api_port": 0},
        {"model_timeout_seconds": -1},
        {"approval_ttl_minutes": 0},
    ):
        with pytest.raises(ValidationError):
            ScrappySettings(_env_file=None, **kwargs)  # type: ignore[arg-type, call-arg]


def test_yaml_overrides_are_loaded(tmp_path: Path) -> None:
    config = tmp_path / "scrappy.yaml"
    config.write_text("model_provider: ollama\nmax_plan_steps: 4\n")
    values = load_yaml_overrides(config)
    assert values == {"model_provider": "ollama", "max_plan_steps": 4}


def test_missing_yaml_file_is_not_an_error(tmp_path: Path) -> None:
    assert load_yaml_overrides(tmp_path / "absent.yaml") == {}


def test_malformed_yaml_is_reported(tmp_path: Path) -> None:
    config = tmp_path / "bad.yaml"
    config.write_text("just a string, not a mapping")
    with pytest.raises(ConfigurationError, match="mapping"):
        load_yaml_overrides(config)


def test_explicit_arguments_beat_yaml(tmp_path: Path) -> None:
    config = tmp_path / "scrappy.yaml"
    config.write_text("max_plan_steps: 4\n")
    settings = load_settings(config, max_plan_steps=9)
    assert settings.max_plan_steps == 9


def test_ensure_directories_creates_private_trees(tmp_path: Path) -> None:
    settings = ScrappySettings(
        _env_file=None,  # type: ignore[call-arg]
        data_dir=tmp_path / "data",
        workspace=tmp_path / "data" / "ws",
    )
    settings.ensure_directories()
    assert settings.data_dir.is_dir()
    assert settings.workspace.is_dir()
    assert settings.data_dir.stat().st_mode & 0o077 == 0


def test_db_path_lives_under_the_data_dir(settings: ScrappySettings) -> None:
    assert settings.db_path.parent == settings.data_dir


# ---------------------------------------------------------------------------
# budgets
# ---------------------------------------------------------------------------


def test_step_budget_stops_the_loop(settings: ScrappySettings) -> None:
    budget = TaskBudget.from_settings(settings)
    for _ in range(settings.max_plan_steps):
        budget.record_step(success=True)
    with pytest.raises(LimitExceeded) as excinfo:
        budget.check_steps()
    assert excinfo.value.limit_name == "max_plan_steps"


def test_model_call_budget_stops_the_loop(settings: ScrappySettings) -> None:
    budget = TaskBudget.from_settings(settings)
    for _ in range(settings.max_model_calls):
        budget.record_model_call()
    with pytest.raises(LimitExceeded, match="inference"):
        budget.check_model_calls()


def test_replan_budget_stops_the_loop(settings: ScrappySettings) -> None:
    budget = TaskBudget.from_settings(settings)
    for _ in range(settings.max_replans):
        budget.record_replan()
    with pytest.raises(LimitExceeded, match="replan"):
        budget.check_replans()


def test_consecutive_failures_stop_the_loop(settings: ScrappySettings) -> None:
    """Repeated failure means stop, not try harder."""
    budget = TaskBudget.from_settings(settings)
    for _ in range(settings.max_consecutive_tool_failures):
        budget.record_step(success=False)
    with pytest.raises(LimitExceeded, match="consecutive"):
        budget.check_failures()


def test_a_success_resets_the_failure_streak(settings: ScrappySettings) -> None:
    budget = TaskBudget.from_settings(settings)
    budget.record_step(success=False)
    budget.record_step(success=False)
    budget.record_step(success=True)
    assert budget.consecutive_failures == 0
    budget.check_failures()


def test_time_budget_stops_the_loop(settings: ScrappySettings) -> None:
    budget = TaskBudget.from_settings(settings)
    budget.max_task_seconds = 0.0
    with pytest.raises(LimitExceeded, match="budget"):
        budget.check_time()


def test_snapshot_reports_usage_against_every_limit(settings: ScrappySettings) -> None:
    budget = TaskBudget.from_settings(settings)
    budget.record_step(success=True)
    budget.record_model_call()
    snapshot = budget.snapshot()

    assert snapshot["steps_executed"] == 1
    assert snapshot["model_calls"] == 1
    assert snapshot["max_plan_steps"] == settings.max_plan_steps
    assert "elapsed_seconds" in snapshot


def test_check_all_covers_every_budget(settings: ScrappySettings) -> None:
    budget = TaskBudget.from_settings(settings)
    budget.check_all()  # fresh budget passes

    budget.steps_executed = settings.max_plan_steps
    with pytest.raises(LimitExceeded):
        budget.check_all()
