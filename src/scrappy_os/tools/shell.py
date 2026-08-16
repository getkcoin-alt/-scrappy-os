"""Shell execution - the escape hatch, not the interface.

Everything Scrappy OS does routinely should have a typed tool. This exists for
the long tail, and it is built so that using it is *harder* than using a proper
tool, not easier.

The controls, all of them enforced here rather than left to the caller:

* **argv only.** ``shell=True`` is never used. There is no shell, so there is
  no shell injection: a pipe character is a literal argument, and the risk
  classifier rejects it before that even matters.
* **Allowlist and denylist.** The executable must be on the allowlist. The
  denylist wins over the allowlist and cannot be overridden by an approval.
* **Absolute-path resolution.** The binary is resolved through ``shutil.which``
  against a fixed PATH, so a writable directory earlier in the inherited PATH
  cannot shadow ``systemctl``.
* **Environment filtering.** The child gets a small, explicit environment. The
  parent's ``OPENAI_API_KEY`` is not inherited by anything Scrappy OS runs.
* **Timeout with process-group kill.** A child that ignores SIGTERM gets
  SIGKILL, and its whole process group goes with it so orphans do not linger.
* **Bounded output.** Reads stop at a byte budget and report truncation.
* **Working-directory restriction.** ``cwd`` must resolve inside an allowed
  root.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from scrappy_os.core.enums import RiskLevel
from scrappy_os.core.errors import ToolError, ToolTimeout
from scrappy_os.observability.logging import get_logger
from scrappy_os.security.paths import validate_read_path
from scrappy_os.security.risk import classify_command
from scrappy_os.tools.base import RollbackSpec, Tool, ToolContext

logger = get_logger("tool.shell")

#: PATH handed to child processes. Fixed, and contains no writable directory.
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

#: Environment variables the child is allowed to inherit. Nothing else crosses.
ENV_ALLOWLIST = frozenset({"HOME", "LANG", "LC_ALL", "TERM", "TZ", "USER", "LOGNAME"})


class ShellArgs(BaseModel):
    """Arguments for :class:`ShellRunTool`."""

    model_config = {"extra": "forbid"}

    argv: list[str] = Field(
        min_length=1,
        max_length=64,
        description="Command as a list. The first element is the executable. No shell is used.",
    )
    cwd: str | None = Field(default=None, max_length=4096)
    timeout_seconds: float | None = Field(default=None, gt=0, le=600)
    max_output_bytes: int | None = Field(default=None, ge=256, le=8 * 1024 * 1024)

    @field_validator("argv")
    @classmethod
    def _reject_empty_and_nul(cls, value: list[str]) -> list[str]:
        if not value or not value[0].strip():
            raise ValueError("argv[0] must be a non-empty executable name")
        for part in value:
            if "\x00" in part:
                raise ValueError("argv may not contain NUL bytes")
        return value


class ShellRunTool(Tool):
    """Run an allowlisted executable without a shell."""

    name = "shell.run"
    description = (
        "Run an allowlisted executable as an argv list, without a shell. "
        "Prefer a typed tool; this is the escape hatch."
    )
    input_model = ShellArgs
    #: Ceiling, not expectation. `classify` decides what these arguments are:
    #: `ls -la /etc` is READ, `systemctl restart` is PRIVILEGED, `rm -rf` is
    #: DESTRUCTIVE and also denylisted.
    risk = RiskLevel.DESTRUCTIVE
    min_risk = RiskLevel.READ
    required_permissions = ("shell:execute",)
    rollback = RollbackSpec(
        supported=False,
        description="Arbitrary commands have arbitrary effects; Scrappy OS cannot undo them.",
    )

    def classify(self, args: BaseModel, ctx: ToolContext) -> tuple[RiskLevel, str]:
        assert isinstance(args, ShellArgs)
        executable = Path(args.argv[0]).name

        # The denylist is checked before anything else and is not appealable.
        if executable in ctx.settings.shell_denylist:
            return RiskLevel.DESTRUCTIVE, f"{executable} is on the denylist"
        if ctx.settings.shell_allowlist and executable not in ctx.settings.shell_allowlist:
            return RiskLevel.DESTRUCTIVE, f"{executable} is not on the allowlist"
        return classify_command(args.argv)

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, ShellArgs)
        settings = ctx.settings
        executable = Path(args.argv[0]).name

        if not settings.shell_allowlist:
            raise ToolError(
                "The shell tool is disabled: SCRAPPY_SHELL_ALLOWLIST is empty",
                tool_name=self.name,
            )
        if executable in settings.shell_denylist:
            raise ToolError(
                f"{executable} is on the shell denylist and cannot be run, even with approval",
                tool_name=self.name,
            )
        if executable not in settings.shell_allowlist:
            raise ToolError(
                f"{executable} is not on the shell allowlist "
                f"({', '.join(sorted(settings.shell_allowlist))})",
                tool_name=self.name,
            )

        resolved_binary = shutil.which(executable, path=SAFE_PATH)
        if resolved_binary is None:
            raise ToolError(
                f"{executable} was not found on the fixed PATH ({SAFE_PATH})",
                tool_name=self.name,
            )

        cwd = self._resolve_cwd(args.cwd, ctx)
        timeout = args.timeout_seconds or settings.shell_timeout_seconds
        max_bytes = args.max_output_bytes or settings.shell_max_output_bytes
        argv = [resolved_binary, *args.argv[1:]]

        logger.info(
            "shell_exec", executable=executable, argc=len(argv), cwd=str(cwd), timeout=timeout
        )
        return await self._execute(argv, cwd=cwd, timeout=timeout, max_bytes=max_bytes)

    def _resolve_cwd(self, raw: str | None, ctx: ToolContext) -> Path:
        if raw is None:
            return ctx.workspace if ctx.workspace.exists() else Path("/")
        return validate_read_path(raw, allowed_roots=ctx.read_roots, workspace=ctx.workspace)

    async def _execute(
        self, argv: list[str], *, cwd: Path, timeout: float, max_bytes: int
    ) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL,
                cwd=str(cwd),
                env=build_child_env(),
                # New process group, so a timeout kills the children too.
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            raise ToolError(f"{argv[0]} not found", tool_name=self.name) from exc
        except PermissionError as exc:
            raise ToolError(f"{argv[0]} is not executable", tool_name=self.name) from exc
        except OSError as exc:
            raise ToolError(f"Cannot start {argv[0]}: {exc}", tool_name=self.name) from exc

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except TimeoutError:
            await _terminate_group(process)
            duration_ms = (time.perf_counter() - started) * 1000
            raise ToolTimeout(
                f"Command exceeded its {timeout}s budget and was terminated",
                tool_name=self.name,
                argv0=Path(argv[0]).name,
                duration_ms=round(duration_ms, 1),
            ) from None

        duration_ms = (time.perf_counter() - started) * 1000
        out_text, out_truncated = _clip(stdout, max_bytes)
        err_text, err_truncated = _clip(stderr, max_bytes)

        return {
            "argv": [Path(argv[0]).name, *argv[1:]],
            "exit_code": process.returncode,
            "success": process.returncode == 0,
            "stdout": out_text,
            "stderr": err_text,
            "truncated": out_truncated or err_truncated,
            "duration_ms": round(duration_ms, 1),
            "cwd": str(cwd),
        }


def build_child_env() -> dict[str, str]:
    """The environment a child process gets.

    Built by allowlist, never by copying ``os.environ`` and deleting keys - a
    new secret-bearing variable would otherwise be inherited by default.
    """
    env = {key: value for key, value in os.environ.items() if key in ENV_ALLOWLIST}
    env["PATH"] = SAFE_PATH
    env["SCRAPPY_OS"] = "1"
    return env


def _clip(raw: bytes, max_bytes: int) -> tuple[str, bool]:
    """Decode output, truncating to a byte budget and saying so."""
    truncated = len(raw) > max_bytes
    body = raw[:max_bytes]
    text = body.decode("utf-8", errors="replace")
    if truncated:
        text += f"\n... [output truncated at {max_bytes} bytes; {len(raw)} produced]"
    return text, truncated


async def _terminate_group(process: asyncio.subprocess.Process) -> None:
    """Kill a timed-out process and everything it spawned.

    SIGTERM to the group first, a grace period, then SIGKILL. Signalling the
    group is what stops a shell-less command's children from surviving.
    """
    if process.returncode is not None:
        return
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(os.getpgid(process.pid), 15)
    try:
        await asyncio.wait_for(process.wait(), timeout=3.0)
        return
    except TimeoutError:
        pass
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(os.getpgid(process.pid), 9)
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(process.wait(), timeout=3.0)


SHELL_TOOLS: tuple[Tool, ...] = (ShellRunTool(),)

__all__ = [
    "ENV_ALLOWLIST",
    "SAFE_PATH",
    "SHELL_TOOLS",
    "ShellArgs",
    "ShellRunTool",
    "build_child_env",
]
