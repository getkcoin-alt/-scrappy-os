"""Settings for the whole control plane.

Precedence, highest first: explicit constructor arguments, process environment,
``.env``, an optional YAML file, then defaults. The defaults are chosen so that
a fresh checkout boots read-only, writes nothing outside its own data directory,
and talks to no network service.

Secrets live in :class:`~pydantic.SecretStr` and are excluded from every
serialisation path used by logging, audit or the API.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from scrappy_os.core.enums import RiskLevel
from scrappy_os.core.errors import ConfigurationError

ProviderName = Literal["mock", "openai", "ollama"]

DEFAULT_READ_ROOTS = "/etc,/proc,/sys,/var/log,/usr/share"
DEFAULT_SHELL_ALLOWLIST = (
    "ls,cat,head,tail,grep,find,df,du,free,uptime,ps,systemctl,journalctl,"
    "uname,hostname,id,which,stat,wc,date,nginx"
)
DEFAULT_SHELL_DENYLIST = (
    "rm,dd,mkfs,shutdown,reboot,halt,poweroff,chown,chmod,passwd,useradd,userdel,visudo,sudo,su"
)


def _split_csv(raw: str) -> tuple[str, ...]:
    """Parse a comma-separated setting into a de-duplicated tuple.

    Lists arrive as CSV strings rather than JSON because these values are edited
    by humans in ``.env`` files and systemd units, where JSON is hostile.
    """
    seen: dict[str, None] = {}
    for chunk in raw.split(","):
        item = chunk.strip()
        if item:
            seen.setdefault(item, None)
    return tuple(seen)


class ScrappySettings(BaseSettings):
    """Every knob Scrappy OS exposes."""

    model_config = SettingsConfigDict(
        env_prefix="SCRAPPY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        protected_namespaces=(),
        case_sensitive=False,
    )

    # -- model routing ------------------------------------------------------
    model_provider: ProviderName = Field(
        default="mock",
        description="Which provider performs inference. 'mock' is deterministic and offline.",
    )
    model_name: str = Field(
        default="gpt-4o-mini",
        validation_alias=AliasChoices("SCRAPPY_MODEL", "SCRAPPY_MODEL_NAME"),
    )
    model_timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    model_temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    model_max_tokens: int = Field(default=2048, gt=0, le=32768)

    openai_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("OPENAI_API_KEY", "SCRAPPY_OPENAI_API_KEY"),
    )
    openai_base_url: str = Field(default="https://api.openai.com/v1")
    ollama_base_url: str = Field(
        default="http://127.0.0.1:11434",
        validation_alias=AliasChoices("OLLAMA_BASE_URL", "SCRAPPY_OLLAMA_BASE_URL"),
    )

    # -- storage ------------------------------------------------------------
    data_dir: Path = Field(default=Path("~/.local/share/scrappy-os"))
    workspace: Path = Field(
        default=Path("~/.local/share/scrappy-os/workspace"),
        description="The only tree tools may write to by default.",
    )
    allowed_read_roots_raw: str = Field(
        default=DEFAULT_READ_ROOTS,
        validation_alias=AliasChoices("SCRAPPY_ALLOWED_READ_ROOTS"),
    )

    # -- orchestration limits ----------------------------------------------
    max_plan_steps: int = Field(default=12, ge=1, le=100)
    max_replans: int = Field(default=2, ge=0, le=10)
    max_task_seconds: float = Field(default=300.0, gt=0, le=86400)
    max_consecutive_tool_failures: int = Field(default=3, ge=1, le=20)
    max_model_calls: int = Field(default=24, ge=1, le=500)

    # -- policy -------------------------------------------------------------
    allow_approvals: bool = Field(
        default=True,
        description="When false, anything above WRITE is denied instead of escalated.",
    )
    approval_ttl_minutes: int = Field(default=15, ge=1, le=1440)
    default_max_risk: RiskLevel = Field(
        default=RiskLevel.READ,
        description="Risk ceiling applied to objectives that do not set their own.",
    )

    # -- shell tool ---------------------------------------------------------
    shell_allowlist_raw: str = Field(
        default=DEFAULT_SHELL_ALLOWLIST,
        validation_alias=AliasChoices("SCRAPPY_SHELL_ALLOWLIST"),
    )
    shell_denylist_raw: str = Field(
        default=DEFAULT_SHELL_DENYLIST,
        validation_alias=AliasChoices("SCRAPPY_SHELL_DENYLIST"),
    )
    shell_timeout_seconds: float = Field(default=30.0, gt=0, le=600)
    shell_max_output_bytes: int = Field(default=64 * 1024, ge=1024, le=8 * 1024 * 1024)

    # -- http tool ----------------------------------------------------------
    http_enabled: bool = True
    http_timeout_seconds: float = Field(default=15.0, gt=0, le=120)
    http_max_bytes: int = Field(default=1024 * 1024, ge=1024, le=64 * 1024 * 1024)
    http_max_redirects: int = Field(default=3, ge=0, le=10)
    http_allow_private_networks: bool = Field(
        default=False,
        description="Leave false. True re-opens the cloud-metadata SSRF path.",
    )

    # -- runtime ------------------------------------------------------------
    api_host: str = Field(default="127.0.0.1")
    api_port: int = Field(default=8787, ge=1, le=65535)
    heartbeat_seconds: float = Field(default=30.0, gt=0, le=3600)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["console", "json"] = "console"

    # -- validators ---------------------------------------------------------

    @field_validator("data_dir", "workspace", mode="after")
    @classmethod
    def _expand(cls, value: Path) -> Path:
        return Path(os.path.expandvars(str(value))).expanduser()

    @field_validator("log_level", mode="before")
    @classmethod
    def _upper(cls, value: Any) -> Any:
        return value.upper() if isinstance(value, str) else value

    @field_validator("openai_base_url", "ollama_base_url", mode="after")
    @classmethod
    def _no_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")

    # -- derived views ------------------------------------------------------

    @property
    def allowed_read_roots(self) -> tuple[Path, ...]:
        """Directories tools may read from, in addition to the workspace."""
        roots = [Path(item).expanduser() for item in _split_csv(self.allowed_read_roots_raw)]
        return tuple(roots)

    @property
    def shell_allowlist(self) -> tuple[str, ...]:
        return _split_csv(self.shell_allowlist_raw)

    @property
    def shell_denylist(self) -> tuple[str, ...]:
        return _split_csv(self.shell_denylist_raw)

    @property
    def db_path(self) -> Path:
        """SQLite file holding audit, episodic memory and approvals."""
        return self.data_dir / "scrappy.db"

    @property
    def api_is_local_only(self) -> bool:
        return self.api_host in {"127.0.0.1", "localhost", "::1"}

    def ensure_directories(self) -> None:
        """Create the data and workspace trees with private permissions.

        Called on startup rather than at import: a settings object must be
        constructible without touching the filesystem, so tests stay hermetic.
        """
        for directory in (self.data_dir, self.workspace):
            try:
                directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            except OSError as exc:
                raise ConfigurationError(
                    f"Cannot create directory {directory}: {exc}", path=str(directory)
                ) from exc

    def redacted_dict(self) -> dict[str, Any]:
        """Settings safe to print, log or return over the API.

        Secrets are replaced with a presence marker so operators can tell
        "unset" from "set" without the value leaking.
        """
        data = self.model_dump(mode="json", exclude={"openai_api_key"})
        data["openai_api_key"] = "<set>" if self.openai_api_key else "<unset>"
        data["allowed_read_roots"] = [str(path) for path in self.allowed_read_roots]
        data["shell_allowlist"] = list(self.shell_allowlist)
        data["shell_denylist"] = list(self.shell_denylist)
        data["db_path"] = str(self.db_path)
        return data


def load_yaml_overrides(path: Path) -> dict[str, Any]:
    """Read a YAML settings file into constructor kwargs.

    Unknown keys are left in place; :class:`ScrappySettings` ignores extras
    rather than failing a boot over a stale config comment.
    """
    if not path.exists():
        return {}
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Cannot read config file {path}: {exc}", path=str(path)) from exc
    if not isinstance(raw, dict):
        raise ConfigurationError(f"Config file {path} must contain a mapping", path=str(path))
    return raw


def load_settings(config_file: Path | None = None, **overrides: Any) -> ScrappySettings:
    """Build settings from YAML (optional), the environment and explicit kwargs."""
    values: dict[str, Any] = {}
    candidate = config_file or _default_config_file()
    if candidate is not None:
        values.update(load_yaml_overrides(candidate))
    values.update(overrides)
    return ScrappySettings(**values)


def _default_config_file() -> Path | None:
    env_path = os.environ.get("SCRAPPY_CONFIG_FILE")
    if env_path:
        return Path(env_path).expanduser()
    local = Path("config/scrappy.yaml")
    return local if local.exists() else None


@lru_cache(maxsize=1)
def get_settings() -> ScrappySettings:
    """Process-wide settings singleton.

    Cached because settings are immutable for a process lifetime. Tests call
    :func:`reset_settings_cache` rather than mutating a global.
    """
    return load_settings()


def reset_settings_cache() -> None:
    """Drop the cached settings. For tests and for ``scrappy config reload``."""
    get_settings.cache_clear()


__all__ = [
    "ProviderName",
    "ScrappySettings",
    "get_settings",
    "load_settings",
    "load_yaml_overrides",
    "reset_settings_cache",
]
