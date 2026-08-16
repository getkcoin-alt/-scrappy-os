"""System inspection tools - Scrappy OS's senses.

Every tool here is READ. None of them can change the machine, which is why the
default risk ceiling permits them without approval and why the first milestone
is built out of them.

``psutil`` does the portable heavy lifting; where it does not cover something
(``/etc/os-release``) we read the file directly through the validated path
helpers rather than shelling out.
"""

from __future__ import annotations

import os
import platform
import socket
from datetime import UTC, datetime
from typing import Any

import psutil
from pydantic import BaseModel, Field

from scrappy_os.core.enums import RiskLevel
from scrappy_os.core.errors import ToolError
from scrappy_os.tools.base import EmptyArgs, Tool, ToolContext


class SystemInfoTool(Tool):
    """Host identity and operating-system release."""

    name = "system.info"
    description = "Hostname, OS distribution, kernel, architecture and boot time."
    input_model = EmptyArgs
    risk = RiskLevel.READ
    required_permissions = ("system:read",)

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        uname = platform.uname()
        boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=UTC)
        return {
            "hostname": socket.gethostname(),
            "system": uname.system,
            "kernel_release": uname.release,
            "kernel_version": uname.version,
            "architecture": uname.machine,
            "processor": uname.processor or uname.machine,
            "python_version": platform.python_version(),
            "distribution": _read_os_release(),
            "boot_time": boot_time.isoformat(),
            "cpu_count_logical": psutil.cpu_count(logical=True),
            "cpu_count_physical": psutil.cpu_count(logical=False),
        }


class SystemCPUTool(Tool):
    """Per-core and aggregate CPU utilisation."""

    name = "system.cpu"
    description = "CPU count, frequency and utilisation percentage per core."
    input_model = EmptyArgs
    risk = RiskLevel.READ
    required_permissions = ("system:read",)

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        # interval=None returns usage since the last call, which is instant.
        # A blocking sample would stall the event loop for no analytical gain.
        percentages = psutil.cpu_percent(interval=None, percpu=True)
        try:
            frequency = psutil.cpu_freq()
        except (NotImplementedError, OSError):  # containers often lack this
            frequency = None
        return {
            "logical_cores": psutil.cpu_count(logical=True),
            "physical_cores": psutil.cpu_count(logical=False),
            "per_core_percent": percentages,
            "total_percent": round(sum(percentages) / len(percentages), 2) if percentages else 0.0,
            "frequency_mhz": round(frequency.current, 1) if frequency else None,
            "note": "percentages are measured since the previous call to this tool",
        }


class SystemMemoryTool(Tool):
    """Physical and swap memory."""

    name = "system.memory"
    description = "Total, used, available and swap memory in bytes and human units."
    input_model = EmptyArgs
    risk = RiskLevel.READ
    required_permissions = ("system:read",)

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        virtual = psutil.virtual_memory()
        swap = psutil.swap_memory()
        return {
            "total_bytes": virtual.total,
            "available_bytes": virtual.available,
            "used_bytes": virtual.used,
            "percent_used": virtual.percent,
            "total_human": human_bytes(virtual.total),
            "available_human": human_bytes(virtual.available),
            "used_human": human_bytes(virtual.used),
            "swap_total_bytes": swap.total,
            "swap_used_bytes": swap.used,
            "swap_percent_used": swap.percent,
        }


class DiskArgs(BaseModel):
    """Arguments for :class:`SystemDiskTool`."""

    model_config = {"extra": "forbid"}

    include_pseudo: bool = Field(
        default=False,
        description="Include tmpfs/devtmpfs/overlay mounts, which are usually noise.",
    )


PSEUDO_FILESYSTEMS = frozenset(
    {"tmpfs", "devtmpfs", "squashfs", "overlay", "proc", "sysfs", "cgroup", "cgroup2", "devpts"}
)


class SystemDiskTool(Tool):
    """Filesystem usage per mount point."""

    name = "system.disk"
    description = (
        "Usage for every mounted filesystem, sorted by percent used. "
        "Answers 'which filesystem is most full'."
    )
    input_model = DiskArgs
    risk = RiskLevel.READ
    required_permissions = ("system:read",)

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, DiskArgs)
        filesystems: list[dict[str, Any]] = []

        for partition in psutil.disk_partitions(all=True):
            if not args.include_pseudo and partition.fstype in PSEUDO_FILESYSTEMS:
                continue
            if not partition.fstype:
                continue
            try:
                usage = psutil.disk_usage(partition.mountpoint)
            except (PermissionError, OSError):
                # A mount we cannot stat is reported, not silently dropped -
                # "I could not read this" is information.
                filesystems.append(
                    {
                        "mountpoint": partition.mountpoint,
                        "device": partition.device,
                        "fstype": partition.fstype,
                        "error": "permission denied or unreadable",
                    }
                )
                continue
            filesystems.append(
                {
                    "mountpoint": partition.mountpoint,
                    "device": partition.device,
                    "fstype": partition.fstype,
                    "options": partition.opts,
                    "total_bytes": usage.total,
                    "used_bytes": usage.used,
                    "free_bytes": usage.free,
                    "percent_used": usage.percent,
                    "total_human": human_bytes(usage.total),
                    "used_human": human_bytes(usage.used),
                    "free_human": human_bytes(usage.free),
                }
            )

        readable = [entry for entry in filesystems if "percent_used" in entry]
        readable.sort(key=lambda entry: entry["percent_used"], reverse=True)
        unreadable = [entry for entry in filesystems if "percent_used" not in entry]

        fullest = readable[0] if readable else None
        return {
            "filesystems": readable + unreadable,
            "fullest": fullest,
            "fullest_summary": (
                f"{fullest['mountpoint']} at {fullest['percent_used']}% used "
                f"({fullest['used_human']} of {fullest['total_human']})"
                if fullest
                else "no readable filesystems"
            ),
            "count": len(readable),
        }


class SystemUptimeTool(Tool):
    """How long the machine has been up."""

    name = "system.uptime"
    description = "Boot time and uptime in seconds and human units."
    input_model = EmptyArgs
    risk = RiskLevel.READ
    required_permissions = ("system:read",)

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        boot = psutil.boot_time()
        uptime_seconds = datetime.now(tz=UTC).timestamp() - boot
        return {
            "boot_time": datetime.fromtimestamp(boot, tz=UTC).isoformat(),
            "uptime_seconds": round(uptime_seconds, 1),
            "uptime_human": human_duration(uptime_seconds),
        }


class SystemLoadTool(Tool):
    """Load averages relative to core count."""

    name = "system.load"
    description = "1/5/15-minute load averages, normalised by CPU count."
    input_model = EmptyArgs
    risk = RiskLevel.READ
    required_permissions = ("system:read",)

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        try:
            one, five, fifteen = os.getloadavg()
        except OSError as exc:  # pragma: no cover - Linux always provides this
            raise ToolError(f"Load average unavailable: {exc}", tool_name=self.name) from exc
        cores = psutil.cpu_count(logical=True) or 1
        return {
            "load_1m": round(one, 2),
            "load_5m": round(five, 2),
            "load_15m": round(fifteen, 2),
            "cpu_count": cores,
            "load_per_core_1m": round(one / cores, 2),
            "saturated": one > cores,
            "interpretation": (
                f"load {one:.2f} across {cores} cores "
                f"({'saturated' if one > cores else 'within capacity'})"
            ),
        }


class SystemNetworkTool(Tool):
    """Network interfaces and their addresses.

    Addresses are host configuration, not secrets, and an operator diagnosing a
    network problem needs them. MAC addresses are included for the same reason.
    """

    name = "system.network"
    description = "Network interfaces, addresses, link state and per-interface counters."
    input_model = EmptyArgs
    risk = RiskLevel.READ
    required_permissions = ("system:read", "network:read")

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        addresses = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        counters = psutil.net_io_counters(pernic=True)

        interfaces = []
        for name, entries in sorted(addresses.items()):
            stat = stats.get(name)
            counter = counters.get(name)
            interfaces.append(
                {
                    "name": name,
                    "is_up": stat.isup if stat else None,
                    "speed_mbps": stat.speed if stat else None,
                    "mtu": stat.mtu if stat else None,
                    "addresses": [
                        {
                            "family": _family_name(entry.family),
                            "address": entry.address,
                            "netmask": entry.netmask,
                        }
                        for entry in entries
                    ],
                    "bytes_sent": counter.bytes_sent if counter else None,
                    "bytes_received": counter.bytes_recv if counter else None,
                    "errors_in": counter.errin if counter else None,
                    "errors_out": counter.errout if counter else None,
                }
            )
        return {"interfaces": interfaces, "count": len(interfaces)}


def _family_name(family: Any) -> str:
    mapping = {
        socket.AF_INET: "ipv4",
        socket.AF_INET6: "ipv6",
        getattr(psutil, "AF_LINK", None): "link",
    }
    return mapping.get(family, str(family))


def _read_os_release() -> dict[str, str]:
    """Parse ``/etc/os-release`` into a dict. Missing file is not an error."""
    from pathlib import Path

    path = Path("/etc/os-release")
    if not path.exists():
        return {}
    result: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            result[key.strip().lower()] = value.strip().strip('"')
    except OSError:
        return {}
    return {
        key: result[key]
        for key in ("id", "name", "version_id", "pretty_name", "version_codename")
        if key in result
    }


def human_bytes(count: float) -> str:
    """Render a byte count the way ``df -h`` would."""
    step = 1024.0
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(count) < step:
            return f"{count:.1f}{unit}" if unit != "B" else f"{int(count)}B"
        count /= step
    return f"{count:.1f}EiB"


def human_duration(seconds: float) -> str:
    """Render a duration as ``3d 4h 12m``."""
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


SYSTEM_TOOLS: tuple[Tool, ...] = (
    SystemInfoTool(),
    SystemCPUTool(),
    SystemMemoryTool(),
    SystemDiskTool(),
    SystemUptimeTool(),
    SystemLoadTool(),
    SystemNetworkTool(),
)

__all__ = [
    "SYSTEM_TOOLS",
    "DiskArgs",
    "SystemCPUTool",
    "SystemDiskTool",
    "SystemInfoTool",
    "SystemLoadTool",
    "SystemMemoryTool",
    "SystemNetworkTool",
    "SystemUptimeTool",
    "human_bytes",
    "human_duration",
]
