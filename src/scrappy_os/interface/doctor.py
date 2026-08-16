"""``scrappy doctor`` - the pre-flight self-check.

Answers one question: if I run a task right now, what will break? Each check is
independent and reports PASS, WARN or FAIL with a specific remedy, because
"something is wrong" is not an actionable diagnosis.

A check never raises. An exception inside one becomes a FAIL for that check and
the rest still run - a doctor that dies on the first problem is useless exactly
when it is needed.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from scrappy_os import __version__
from scrappy_os.core.config import ScrappySettings
from scrappy_os.memory.store import Store
from scrappy_os.models.registry import ModelRouter
from scrappy_os.security.authn import MIN_TOKEN_LENGTH
from scrappy_os.tools.base import ToolRegistry

MINIMUM_PYTHON = (3, 12)


class CheckStatus(StrEnum):
    """Outcome of one diagnostic check."""

    PASS = "PASS"  # noqa: S105 -- a check outcome, not a credential
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass(frozen=True, slots=True)
class CheckResult:
    """One diagnostic answer."""

    name: str
    status: CheckStatus
    detail: str
    remedy: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is not CheckStatus.FAIL


@dataclass(slots=True)
class DoctorReport:
    """The full set of checks."""

    results: list[CheckResult]

    @property
    def healthy(self) -> bool:
        """False only if something would actually stop a task from running."""
        return all(result.ok for result in self.results)

    @property
    def counts(self) -> dict[str, int]:
        counts = {status.value: 0 for status in CheckStatus}
        for result in self.results:
            counts[result.status.value] += 1
        return counts


async def run_doctor(
    settings: ScrappySettings,
    *,
    registry: ToolRegistry | None = None,
    router: ModelRouter | None = None,
    check_provider: bool = True,
) -> DoctorReport:
    """Run every check and collect the results."""
    results: list[CheckResult] = [
        _check_python(),
        _check_settings(settings),
        _check_data_dir(settings),
        _check_workspace(settings),
        _check_read_roots(settings),
        _check_privileges(settings),
        _check_api_binding(settings),
        _check_api_authentication(settings),
        _check_shell_config(settings),
        _check_optional_binaries(),
    ]
    results.append(await _safely(lambda: _check_database(settings), "database"))
    if registry is not None:
        results.append(_check_tools(registry))
    if check_provider:
        active_router = router or ModelRouter(settings)
        results.append(await _safely(lambda: _check_provider(active_router), "model provider"))
    return DoctorReport(results=results)


async def _safely(check: Callable[[], Awaitable[CheckResult]], name: str) -> CheckResult:
    """Run a check, turning any exception into a FAIL for that check alone."""
    try:
        return await check()
    except Exception as exc:  # noqa: BLE001 - one broken check must not hide the others
        return CheckResult(
            name=name,
            status=CheckStatus.FAIL,
            detail=f"{type(exc).__name__}: {exc}",
            remedy="This is unexpected; please report it with the message above.",
        )


def _check_python() -> CheckResult:
    version = sys.version_info
    rendered = f"{version.major}.{version.minor}.{version.micro}"
    if (version.major, version.minor) < MINIMUM_PYTHON:
        return CheckResult(
            "python",
            CheckStatus.FAIL,
            f"Python {rendered} is too old",
            f"Scrappy OS needs Python {MINIMUM_PYTHON[0]}.{MINIMUM_PYTHON[1]} or newer.",
        )
    return CheckResult("python", CheckStatus.PASS, f"Python {rendered}, scrappy-os {__version__}")


def _check_settings(settings: ScrappySettings) -> CheckResult:
    if settings.model_provider == "openai" and settings.openai_api_key is None:
        return CheckResult(
            "configuration",
            CheckStatus.FAIL,
            "provider is 'openai' but OPENAI_API_KEY is not set",
            "Set OPENAI_API_KEY in .env, or set SCRAPPY_MODEL_PROVIDER=ollama or mock.",
        )
    if settings.max_task_seconds > 3600:
        return CheckResult(
            "configuration",
            CheckStatus.WARN,
            f"max_task_seconds is {settings.max_task_seconds:.0f}",
            "A task budget over an hour weakens the runaway-loop protection.",
        )
    return CheckResult(
        "configuration",
        CheckStatus.PASS,
        f"provider={settings.model_provider} model={settings.model_name} "
        f"max_steps={settings.max_plan_steps} max_risk={settings.default_max_risk}",
    )


def _check_data_dir(settings: ScrappySettings) -> CheckResult:
    path = settings.data_dir
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        return CheckResult(
            "data directory",
            CheckStatus.FAIL,
            f"cannot create {path}: {exc}",
            "Set SCRAPPY_DATA_DIR to a directory this user can write to.",
        )
    if not os.access(path, os.W_OK):
        return CheckResult(
            "data directory",
            CheckStatus.FAIL,
            f"{path} is not writable",
            f"chown this directory to the user running Scrappy OS: {path}",
        )
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        return CheckResult(
            "data directory",
            CheckStatus.WARN,
            f"{path} is mode {oct(mode)}",
            f"The audit trail lives here. Tighten it: chmod 700 {path}",
        )
    return CheckResult("data directory", CheckStatus.PASS, f"{path} (mode {oct(mode)})")


def _check_workspace(settings: ScrappySettings) -> CheckResult:
    path = settings.workspace
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        return CheckResult(
            "workspace",
            CheckStatus.FAIL,
            f"cannot create {path}: {exc}",
            "Set SCRAPPY_WORKSPACE to a directory this user can write to.",
        )

    resolved = path.resolve(strict=False)
    dangerous = [Path("/"), Path("/etc"), Path("/usr"), Path("/var"), Path("/home"), Path("/root")]
    if resolved in dangerous:
        return CheckResult(
            "workspace",
            CheckStatus.FAIL,
            f"workspace is {resolved}, which makes WRITE operations unrestricted",
            "Point SCRAPPY_WORKSPACE at a dedicated directory.",
        )
    return CheckResult("workspace", CheckStatus.PASS, f"{resolved} (writes confined here)")


def _check_read_roots(settings: ScrappySettings) -> CheckResult:
    roots = settings.allowed_read_roots
    if not roots:
        return CheckResult(
            "read roots",
            CheckStatus.WARN,
            "no read roots configured; only the workspace is readable",
            "Set SCRAPPY_ALLOWED_READ_ROOTS if the agent needs to inspect /etc or /var/log.",
        )
    if Path("/") in {root.resolve(strict=False) for root in roots}:
        return CheckResult(
            "read roots",
            CheckStatus.WARN,
            "'/' is an allowed read root, so every readable file on the host is in scope",
            "Narrow SCRAPPY_ALLOWED_READ_ROOTS to the directories actually needed.",
        )
    missing = [str(root) for root in roots if not root.exists()]
    detail = ", ".join(str(root) for root in roots)
    if missing:
        return CheckResult(
            "read roots",
            CheckStatus.WARN,
            f"{detail} (missing: {', '.join(missing)})",
            "Remove paths that do not exist on this host.",
        )
    return CheckResult("read roots", CheckStatus.PASS, detail)


def _check_privileges(settings: ScrappySettings) -> CheckResult:
    """Report the account Scrappy OS is running as.

    Every containment property in docs/SECURITY.md - the workspace boundary,
    the read roots, the forbidden write trees - is enforced in this process,
    against operations a model proposed. As root those boundaries are the only
    thing standing between a generated plan and the whole machine, and the
    kernel adds nothing underneath them. That is worth saying out loud even
    when nothing is broken.

    Root plus an off-host listener is not two warnings, it is one unauthenticated
    remote root control plane, so it is a FAIL rather than the sum of its parts.
    """
    if os.geteuid() != 0:
        return CheckResult(
            "privileges",
            CheckStatus.PASS,
            f"running as uid {os.geteuid()} (unprivileged)",
        )

    if not settings.api_is_local_only:
        return CheckResult(
            "privileges",
            CheckStatus.FAIL,
            f"running as root AND the API binds {settings.api_host}:{settings.api_port}, "
            "which is reachable off this host",
            "This combination is an unauthenticated remote root control plane. "
            "Set SCRAPPY_API_HOST=127.0.0.1 and run as a dedicated account "
            "(deploy/README.md) before giving this instance any work.",
        )

    return CheckResult(
        "privileges",
        CheckStatus.WARN,
        "running as root; the policy engine is the only thing confining generated actions",
        "Run as a dedicated unprivileged account - see deploy/README.md. "
        "The shipped systemd unit already does this.",
    )


def _check_api_binding(settings: ScrappySettings) -> CheckResult:
    """Bind address and credentials, judged together.

    Neither fact is alarming alone. Loopback with no token is the default and is
    fine. A token with an off-host bind is a deliberate, defensible deployment.
    The combination of *reachable by strangers* and *cannot tell strangers
    apart* is the one that has to stop being a warning and start being a
    failure, because a warning in that state is something an operator scrolls
    past.
    """
    if settings.api_exposure_is_unsafe:
        return CheckResult(
            "api binding",
            CheckStatus.FAIL,
            f"API binds {settings.api_host}:{settings.api_port} - reachable off this host - "
            "and SCRAPPY_API_TOKEN is not set, so no caller can be identified",
            "Set SCRAPPY_API_TOKEN, or bind loopback with SCRAPPY_API_HOST=127.0.0.1. "
            "Until then every authenticated endpoint refuses, so this instance is "
            "exposed and useless at the same time.",
        )

    if settings.api_is_local_only:
        credentials = "token set" if settings.api_auth_configured else "no token set"
        return CheckResult(
            "api binding",
            CheckStatus.PASS,
            f"{settings.api_host}:{settings.api_port} (local only, {credentials})",
        )

    return CheckResult(
        "api binding",
        CheckStatus.WARN,
        f"API binds {settings.api_host}:{settings.api_port}, reachable off this host; "
        "bearer authentication is configured",
        "A bearer token is a shared secret sent on every request: it is replayable if "
        "intercepted and it does not authenticate the server to the client. Terminate TLS "
        "in front of this, or bind loopback and reach it over SSH.",
    )


def _check_api_authentication(settings: ScrappySettings) -> CheckResult:
    """Whether the API can identify anyone, and how well.

    Reports the presence and shape of the credential. It never reports the
    credential: the value is not read here, only its length and its existence.
    """
    if not settings.api_auth_configured:
        detail = "no SCRAPPY_API_TOKEN set; every authenticated endpoint will refuse"
        if settings.api_is_local_only:
            return CheckResult(
                "api authentication",
                CheckStatus.WARN,
                detail + " (the API is loopback-only, so nothing is exposed)",
                "Set SCRAPPY_API_TOKEN to use the HTTP API. The CLI works without one - "
                "it drives the runtime in-process.",
            )
        return CheckResult(
            "api authentication",
            CheckStatus.FAIL,
            detail,
            "Set SCRAPPY_API_TOKEN before binding a non-loopback address.",
        )

    token = settings.api_token
    length = len(token.get_secret_value()) if token else 0
    if length < MIN_TOKEN_LENGTH:
        generate = 'python -c "import secrets; print(secrets.token_urlsafe(32))"'
        if not settings.api_is_local_only:
            # Same reasoning as the no-token branch above. A guessable secret on
            # an interface strangers can reach is not a weaker version of
            # authentication, it is the absence of it with extra steps, and a
            # deployment pipeline that only checks doctor's exit code must not
            # be told this is fine.
            return CheckResult(
                "api authentication",
                CheckStatus.FAIL,
                f"SCRAPPY_API_TOKEN is only {length} characters and the API binds "
                f"{settings.api_host}:{settings.api_port}, reachable off this host",
                f"A token this short is brute-forceable. Use at least {MIN_TOKEN_LENGTH} "
                f"characters from `{generate}`, or bind loopback with "
                "SCRAPPY_API_HOST=127.0.0.1.",
            )
        return CheckResult(
            "api authentication",
            CheckStatus.WARN,
            f"SCRAPPY_API_TOKEN is only {length} characters",
            f"Use at least {MIN_TOKEN_LENGTH}, ideally from `{generate}`.",
        )

    scopes = sorted(str(scope) for scope in settings.api_token_scopes)
    return CheckResult(
        "api authentication",
        CheckStatus.PASS,
        f"bearer token configured for actor {settings.api_token_actor_id!r} "
        f"with {len(scopes)} scope(s): {', '.join(scopes)}",
    )


def _check_shell_config(settings: ScrappySettings) -> CheckResult:
    if not settings.shell_allowlist:
        return CheckResult("shell tool", CheckStatus.PASS, "disabled (empty allowlist)")
    overlap = set(settings.shell_allowlist) & set(settings.shell_denylist)
    if overlap:
        return CheckResult(
            "shell tool",
            CheckStatus.WARN,
            f"{', '.join(sorted(overlap))} appear on both lists; the denylist wins",
            "Remove them from SCRAPPY_SHELL_ALLOWLIST to make the intent clear.",
        )
    return CheckResult(
        "shell tool",
        CheckStatus.PASS,
        f"{len(settings.shell_allowlist)} allowed, {len(settings.shell_denylist)} denied, "
        f"timeout {settings.shell_timeout_seconds:.0f}s",
    )


def _check_optional_binaries() -> CheckResult:
    optional = ("git", "systemctl", "journalctl", "docker")
    found = [name for name in optional if shutil.which(name)]
    missing = [name for name in optional if name not in found]
    detail = f"available: {', '.join(found) or 'none'}"
    if missing:
        detail += f"; unavailable: {', '.join(missing)}"
    return CheckResult("optional tools", CheckStatus.PASS, detail)


def _check_tools(registry: ToolRegistry) -> CheckResult:
    enabled = registry.enabled()
    read_only = [tool for tool in enabled if str(tool.risk) == "read"]
    return CheckResult(
        "tool registry",
        CheckStatus.PASS,
        f"{len(enabled)} tools registered ({len(read_only)} read-only), "
        f"{len(registry.disabled)} disabled",
    )


async def _check_database(settings: ScrappySettings) -> CheckResult:
    store = Store(settings.db_path)
    try:
        await store.connect()
        ok, detail = await store.health_check()
    finally:
        await store.close()
    if not ok:
        return CheckResult(
            "database",
            CheckStatus.FAIL,
            detail,
            f"Check permissions on {settings.db_path}, or remove it to recreate the schema.",
        )
    return CheckResult("database", CheckStatus.PASS, detail)


async def _check_provider(router: ModelRouter) -> CheckResult:
    info = router.provider.info
    health = await router.health_check()

    if router.is_development_provider:
        return CheckResult(
            "model provider",
            CheckStatus.WARN,
            "using the deterministic development provider; no model is being consulted",
            "Set SCRAPPY_MODEL_PROVIDER=openai or ollama for real reasoning.",
        )
    if not health.healthy:
        return CheckResult(
            "model provider",
            CheckStatus.FAIL,
            f"{info.name}: {health.detail}",
            "Fix connectivity or credentials, or switch SCRAPPY_MODEL_PROVIDER=mock "
            "to work offline.",
        )
    latency = f" ({health.latency_ms:.0f}ms)" if health.latency_ms else ""
    return CheckResult("model provider", CheckStatus.PASS, f"{info.name}: {health.detail}{latency}")


__all__ = ["CheckResult", "CheckStatus", "DoctorReport", "run_doctor"]
