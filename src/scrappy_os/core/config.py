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

#: Fields excluded from every human-readable rendering of the settings.
#: :meth:`ScrappySettings.redacted_dict` re-adds each one as a presence marker,
#: so adding a secret here hides its value without hiding its existence.
SECRET_FIELDS: frozenset[str] = frozenset({"openai_api_key", "api_token"})

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
        # Fields with a validation_alias would otherwise be unreachable by their
        # own name, which breaks YAML config files and explicit constructor
        # overrides. Both are supported paths, so both must work.
        populate_by_name=True,
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
        validation_alias=AliasChoices("SCRAPPY_ALLOWED_READ_ROOTS", "allowed_read_roots"),
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
        validation_alias=AliasChoices("SCRAPPY_SHELL_ALLOWLIST", "shell_allowlist"),
    )
    shell_denylist_raw: str = Field(
        default=DEFAULT_SHELL_DENYLIST,
        validation_alias=AliasChoices("SCRAPPY_SHELL_DENYLIST", "shell_denylist"),
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
    api_token: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("SCRAPPY_API_TOKEN", "api_token"),
        description=(
            "Bearer token for the HTTP API. Unset means no credential is valid and every "
            "authenticated endpoint refuses, which is not the same as being open."
        ),
    )
    api_token_actor_id: str = Field(
        default="api-token",
        max_length=128,
        description="Principal id recorded in the audit trail for the configured token.",
    )
    api_token_scopes_raw: str = Field(
        default="",
        validation_alias=AliasChoices("SCRAPPY_API_TOKEN_SCOPES", "api_token_scopes"),
        description="Comma-separated scopes for the API token. Empty grants every scope.",
    )
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

    @property
    def api_token_scopes(self) -> frozenset[Any]:
        """Scopes granted to the configured API token.

        An empty setting grants every scope: a single-token deployment that has
        not opted into narrowing should behave as the operator expects, and
        narrowing is the explicit act. Unknown scope names raise rather than
        being dropped - see :func:`scrappy_os.security.authz.parse_scopes`.
        """
        from scrappy_os.core.identity import all_scopes
        from scrappy_os.security.authz import parse_scopes

        raw = self.api_token_scopes_raw.strip()
        if not raw:
            return all_scopes()
        return parse_scopes(raw)

    @property
    def api_auth_configured(self) -> bool:
        """Whether any credential can authenticate to the API.

        False does not mean "open": it means every authenticated endpoint has no
        acceptable credential and refuses. See :mod:`scrappy_os.security.authn`.
        """
        return self.api_token is not None and bool(self.api_token.get_secret_value())

    @property
    def api_exposure_is_unsafe(self) -> bool:
        """Bound off-host *and* unable to authenticate anyone.

        The combination doctor shouts about. Either half alone is a considered
        choice; together they are a control plane reachable by strangers with no
        way to tell them apart.
        """
        return not self.api_is_local_only and not self.api_auth_configured

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
        data = self.model_dump(mode="json", exclude=set(SECRET_FIELDS))
        data["openai_api_key"] = "<set>" if self.openai_api_key else "<unset>"
        data["api_token"] = "<set>" if self.api_auth_configured else "<unset>"
        data["api_token_scopes"] = sorted(str(scope) for scope in self.api_token_scopes)
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


def _env_names_for(field_name: str) -> set[str]:
    """Every environment variable that can populate ``field_name``.

    Mirrors what pydantic-settings itself would look for: the declared
    :class:`~pydantic.AliasChoices` when a field has them, otherwise the
    prefixed field name.
    """
    field = ScrappySettings.model_fields.get(field_name)
    if field is None:
        return set()
    alias = field.validation_alias
    if isinstance(alias, AliasChoices):
        return {str(choice) for choice in alias.choices if isinstance(choice, str)}
    if isinstance(alias, str):
        return {alias}
    return {f"SCRAPPY_{field_name}"}


def _field_for_key(key: str) -> str | None:
    """Resolve a YAML key to a model field, whether it used the name or an alias."""
    if key in ScrappySettings.model_fields:
        return key
    lowered = key.lower()
    for name in ScrappySettings.model_fields:
        if any(alias.lower() == lowered for alias in _env_names_for(name)):
            return name
    return None


def _environment_supplied(field_name: str, dotenv_keys: frozenset[str]) -> bool:
    """Whether the process environment or ``.env`` already sets this field."""
    present = {key.upper() for key in os.environ} | {key.upper() for key in dotenv_keys}
    return any(name.upper() in present for name in _env_names_for(field_name))


def load_settings(config_file: Path | None = None, **overrides: Any) -> ScrappySettings:
    """Build settings from YAML (optional), the environment and explicit kwargs.

    Precedence is the documented one: explicit kwargs, then the environment,
    then ``.env``, then YAML, then defaults.

    Getting that ordering right takes the loop below rather than a single
    ``dict.update``. YAML values have to reach the model as constructor
    arguments, and pydantic-settings ranks constructor arguments *above* the
    environment - so passing the file's contents through verbatim would silently
    invert two layers, and a stale ``api_token`` in ``config/scrappy.yaml``
    would quietly beat the one a systemd ``EnvironmentFile`` supplies. An
    operator rotating a credential would then be rotating the wrong one. So a
    YAML value is dropped when the environment already speaks for that field.
    """
    values: dict[str, Any] = {}
    candidate = config_file or _default_config_file()
    if candidate is not None:
        dotenv_keys = _dotenv_keys()
        for key, value in load_yaml_overrides(candidate).items():
            field_name = _field_for_key(key)
            if field_name is None:
                # Unknown keys are still passed through; extra="ignore" drops
                # them, and failing a boot over a stale comment is worse.
                values[key] = value
                continue
            if _environment_supplied(field_name, dotenv_keys):
                continue
            values[field_name] = value
    values.update(overrides)
    return ScrappySettings(**values)


def _dotenv_keys() -> frozenset[str]:
    """Keys defined in the ``.env`` file, which also outranks YAML."""
    configured = ScrappySettings.model_config.get("env_file")
    path = Path(configured) if isinstance(configured, str | os.PathLike) else Path(".env")
    if not path.exists():
        return frozenset()
    try:
        from dotenv import dotenv_values

        return frozenset(key for key in dotenv_values(path) if key)
    except (OSError, ValueError):  # pragma: no cover - unreadable .env
        return frozenset()


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
    "SECRET_FIELDS",
    "ProviderName",
    "ScrappySettings",
    "get_settings",
    "load_settings",
    "load_yaml_overrides",
    "reset_settings_cache",
]
