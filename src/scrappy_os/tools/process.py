"""Process inspection tools.

Listing and inspecting processes is READ. Signalling one is not, and lives
behind a separate tool with a separate permission - ``process.kill`` is
PRIVILEGED at best and DESTRUCTIVE when aimed at PID 1 or at init-adjacent
processes, so it can never run without an approval.

Command lines are redacted before they leave this module: ``mysql -p<password>``
is a real and common way for a credential to end up in an audit log.
"""

from __future__ import annotations

import os
import signal as signal_module
from typing import Any, Literal

import psutil
from pydantic import BaseModel, Field

from scrappy_os.core.enums import RiskLevel
from scrappy_os.core.errors import ToolError
from scrappy_os.observability.redaction import redact_text
from scrappy_os.tools.base import RollbackSpec, Tool, ToolContext
from scrappy_os.tools.system import human_bytes

#: Signalling these is an availability incident, not maintenance.
PROTECTED_PIDS = frozenset({0, 1})

#: Killing these by name takes the machine down or locks you out.
PROTECTED_PROCESS_NAMES = frozenset(
    {"systemd", "init", "kthreadd", "sshd", "dbus-daemon", "kernel"}
)


class ProcessListArgs(BaseModel):
    model_config = {"extra": "forbid"}

    limit: int = Field(default=20, ge=1, le=500)
    sort_by: Literal["memory", "cpu", "pid", "name"] = "memory"
    name_contains: str | None = Field(default=None, max_length=128)


class ProcessInspectArgs(BaseModel):
    model_config = {"extra": "forbid"}

    pid: int = Field(ge=0, le=2**22)


class ProcessKillArgs(BaseModel):
    model_config = {"extra": "forbid"}

    pid: int = Field(ge=2, le=2**22, description="PID 0 and 1 are rejected outright.")
    signal: Literal["TERM", "HUP", "INT", "KILL"] = Field(
        default="TERM", description="KILL denies the process any chance to shut down cleanly."
    )


class ProcessListTool(Tool):
    """Enumerate running processes."""

    name = "process.list"
    description = "List running processes with PID, user, memory, CPU and command."
    input_model = ProcessListArgs
    risk = RiskLevel.READ
    required_permissions = ("process:read",)

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, ProcessListArgs)
        fields = ["pid", "name", "username", "status", "memory_info", "cpu_percent", "create_time"]
        processes: list[dict[str, Any]] = []

        for proc in psutil.process_iter(fields):
            try:
                info = proc.info
                if (
                    args.name_contains
                    and args.name_contains.lower() not in (info.get("name") or "").lower()
                ):
                    continue
                memory = info.get("memory_info")
                processes.append(
                    {
                        "pid": info["pid"],
                        "name": info.get("name") or "?",
                        "user": info.get("username") or "?",
                        "status": info.get("status") or "?",
                        "rss_bytes": memory.rss if memory else 0,
                        "rss_human": human_bytes(memory.rss) if memory else "0B",
                        "cpu_percent": info.get("cpu_percent") or 0.0,
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Processes exit while we iterate. That is normal, not an error.
                continue

        key = {
            "memory": lambda item: -item["rss_bytes"],
            "cpu": lambda item: -item["cpu_percent"],
            "pid": lambda item: item["pid"],
            "name": lambda item: item["name"],
        }[args.sort_by]
        processes.sort(key=key)

        return {
            "processes": processes[: args.limit],
            "total_running": len(processes),
            "shown": min(args.limit, len(processes)),
            "sorted_by": args.sort_by,
        }


class ProcessInspectTool(Tool):
    """Detail for one process."""

    name = "process.inspect"
    description = "Full detail for one PID: command line, resources, parent, open file count."
    input_model = ProcessInspectArgs
    risk = RiskLevel.READ
    required_permissions = ("process:read",)

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, ProcessInspectArgs)
        try:
            proc = psutil.Process(args.pid)
            with proc.oneshot():
                memory = proc.memory_info()
                result: dict[str, Any] = {
                    "pid": proc.pid,
                    "name": proc.name(),
                    "status": proc.status(),
                    "user": proc.username(),
                    "created_at": proc.create_time(),
                    "cmdline": [redact_text(part) for part in proc.cmdline()],
                    "cwd": _safe(lambda: proc.cwd()),
                    "exe": _safe(lambda: proc.exe()),
                    "parent_pid": proc.ppid(),
                    "num_threads": proc.num_threads(),
                    "rss_bytes": memory.rss,
                    "rss_human": human_bytes(memory.rss),
                    "vms_bytes": memory.vms,
                    "cpu_percent": proc.cpu_percent(interval=None),
                    "open_files": _safe(lambda: len(proc.open_files())),
                    "connections": _safe(lambda: len(proc.net_connections())),
                }
        except psutil.NoSuchProcess as exc:
            raise ToolError(f"No process with PID {args.pid}", tool_name=self.name) from exc
        except psutil.AccessDenied as exc:
            raise ToolError(
                f"Permission denied inspecting PID {args.pid}", tool_name=self.name
            ) from exc
        return result


class ProcessResourcesTool(Tool):
    """Aggregate resource usage across all processes."""

    name = "process.resources"
    description = "Totals and top consumers of memory and CPU across all processes."
    input_model = ProcessListArgs
    risk = RiskLevel.READ
    required_permissions = ("process:read",)

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, ProcessListArgs)
        listing = await ProcessListTool().run(args, ctx)
        processes = listing["processes"]
        total_rss = sum(item["rss_bytes"] for item in processes)
        return {
            "process_count": listing["total_running"],
            "sampled": len(processes),
            "total_rss_bytes": total_rss,
            "total_rss_human": human_bytes(total_rss),
            "top_by_memory": sorted(processes, key=lambda i: -i["rss_bytes"])[:5],
            "top_by_cpu": sorted(processes, key=lambda i: -i["cpu_percent"])[:5],
        }


class ProcessKillTool(Tool):
    """Signal a process.

    Separately gated from every read tool. Statically PRIVILEGED; aiming at a
    protected process raises it to DESTRUCTIVE, and the executor refuses PID 0
    and 1 before the policy engine is even consulted.
    """

    name = "process.kill"
    description = "Send a termination signal to a process. Requires approval."
    input_model = ProcessKillArgs
    risk = RiskLevel.PRIVILEGED
    required_permissions = ("process:signal",)
    rollback = RollbackSpec(
        supported=False,
        description="A terminated process cannot be resumed; it must be restarted by its manager.",
    )

    def classify(self, args: BaseModel, ctx: ToolContext) -> tuple[RiskLevel, str]:
        assert isinstance(args, ProcessKillArgs)
        if args.pid in PROTECTED_PIDS:
            return RiskLevel.DESTRUCTIVE, f"PID {args.pid} is the init system"
        try:
            name = psutil.Process(args.pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return RiskLevel.PRIVILEGED, f"cannot identify PID {args.pid} before signalling"
        if name in PROTECTED_PROCESS_NAMES:
            return RiskLevel.DESTRUCTIVE, f"{name} is critical to machine availability"
        if args.signal == "KILL":
            return RiskLevel.DESTRUCTIVE, f"SIGKILL gives {name} no chance to shut down cleanly"
        return RiskLevel.PRIVILEGED, f"SIG{args.signal} to {name} (pid {args.pid})"

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, ProcessKillArgs)
        if args.pid in PROTECTED_PIDS:
            raise ToolError(
                f"Refusing to signal PID {args.pid}: it is the init system", tool_name=self.name
            )
        if args.pid == os.getpid():
            raise ToolError("Refusing to signal the Scrappy OS process", tool_name=self.name)

        try:
            proc = psutil.Process(args.pid)
            name = proc.name()
            if name in PROTECTED_PROCESS_NAMES:
                raise ToolError(
                    f"Refusing to signal {name} (pid {args.pid}): protected process",
                    tool_name=self.name,
                )
            proc.send_signal(getattr(signal_module, f"SIG{args.signal}"))
        except psutil.NoSuchProcess as exc:
            raise ToolError(f"No process with PID {args.pid}", tool_name=self.name) from exc
        except psutil.AccessDenied as exc:
            raise ToolError(
                f"Permission denied signalling PID {args.pid}", tool_name=self.name
            ) from exc

        return {"pid": args.pid, "name": name, "signal": f"SIG{args.signal}", "sent": True}


def _safe(getter: Any) -> Any:
    """Call an accessor that may be denied; report None rather than failing the tool."""
    try:
        return getter()
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return None


PROCESS_TOOLS: tuple[Tool, ...] = (
    ProcessListTool(),
    ProcessInspectTool(),
    ProcessResourcesTool(),
    ProcessKillTool(),
)

__all__ = [
    "PROCESS_TOOLS",
    "PROTECTED_PIDS",
    "PROTECTED_PROCESS_NAMES",
    "ProcessInspectTool",
    "ProcessKillTool",
    "ProcessListTool",
    "ProcessResourcesTool",
]
