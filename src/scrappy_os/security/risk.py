"""Risk classification.

Risk is decided in two places and the more dangerous answer always wins:

1. A tool's *static* risk - the worst thing that tool can do at all.
2. A tool's *dynamic* risk - what these particular arguments would do.

``fs.delete`` is DESTRUCTIVE statically, but deleting a scratch file inside the
workspace is not the same as ``rm -rf /var``. Conversely ``shell.run`` looks
harmless until you read the command line. This module holds the argument-aware
half; tools own the static half.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Sequence
from pathlib import Path

from scrappy_os.core.enums import RiskLevel
from scrappy_os.security.paths import is_inside_workspace

#: Executables that change system state. Running them at all is PRIVILEGED.
PRIVILEGED_EXECUTABLES: frozenset[str] = frozenset(
    {
        "apt",
        "apt-get",
        "chcon",
        "crontab",
        "dnf",
        "dpkg",
        "groupadd",
        "insmod",
        "ip",
        "iptables",
        "journalctl",
        "kill",
        "killall",
        "mount",
        "nft",
        "nmcli",
        "pip",
        "pkill",
        "rmmod",
        "service",
        "setenforce",
        "snap",
        "sysctl",
        "systemctl",
        "ufw",
        "umount",
        "update-alternatives",
        "yum",
    }
)

#: Executables that lose data or availability.
DESTRUCTIVE_EXECUTABLES: frozenset[str] = frozenset(
    {
        "dd",
        "fdisk",
        "halt",
        "init",
        "mkfs",
        "parted",
        "poweroff",
        "reboot",
        "rm",
        "shred",
        "shutdown",
        "userdel",
        "wipefs",
    }
)

#: Argument shapes that make an otherwise-tame command destructive.
DESTRUCTIVE_ARGUMENT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^--?(force|f)$"),
    re.compile(r"^-[a-z]*r[a-z]*f[a-z]*$"),  # -rf, -Rf, -rvf ...
    re.compile(r"^-[a-z]*f[a-z]*r[a-z]*$"),  # -fr ...
    re.compile(r"^--no-preserve-root$"),
)

#: Shell metacharacters. Their presence means the caller is trying to build a
#: shell pipeline, which the typed interface deliberately does not offer.
SHELL_METACHARACTERS: tuple[str, ...] = (";", "&&", "||", "|", "`", "$(", ">", "<", "\n")

#: Subcommands that mutate service or package state.
PRIVILEGED_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "systemctl": frozenset(
        {"start", "stop", "restart", "reload", "enable", "disable", "mask", "unmask", "kill"}
    ),
    "service": frozenset({"start", "stop", "restart", "reload"}),
    "apt": frozenset({"install", "remove", "purge", "upgrade", "dist-upgrade", "autoremove"}),
    "apt-get": frozenset({"install", "remove", "purge", "upgrade", "dist-upgrade", "autoremove"}),
    "pip": frozenset({"install", "uninstall"}),
}

#: Read-only subcommands that keep an otherwise-privileged binary at READ.
READ_ONLY_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "systemctl": frozenset(
        {
            "status",
            "show",
            "list-units",
            "list-unit-files",
            "is-active",
            "is-enabled",
            "is-failed",
            "cat",
            "get-default",
        }
    ),
    "service": frozenset({"status"}),
    "ip": frozenset({"addr", "a", "link", "route", "neigh"}),
    "pip": frozenset({"list", "show", "freeze"}),
    "apt": frozenset({"list", "show", "policy"}),
}


def classify_command(argv: Sequence[str]) -> tuple[RiskLevel, str]:
    """Classify an argv vector. Returns ``(risk, human-readable reason)``.

    Never returns below PRIVILEGED for anything it does not recognise as safe:
    an unfamiliar binary is an unknown capability, and unknown means "make a
    human look at it".
    """
    if not argv:
        return RiskLevel.DESTRUCTIVE, "empty command"

    executable = Path(argv[0]).name.lower()
    arguments = [str(item) for item in argv[1:]]

    for token in argv:
        for meta in SHELL_METACHARACTERS:
            if meta in str(token):
                return (
                    RiskLevel.DESTRUCTIVE,
                    f"argument contains shell metacharacter {meta!r}; "
                    "pipelines are not available through this interface",
                )

    if executable in DESTRUCTIVE_EXECUTABLES:
        return RiskLevel.DESTRUCTIVE, f"{executable} destroys data or availability"

    subcommand = next((arg.lower() for arg in arguments if not arg.startswith("-")), None)

    if executable in PRIVILEGED_SUBCOMMANDS:
        mutating = PRIVILEGED_SUBCOMMANDS[executable]
        read_only = READ_ONLY_SUBCOMMANDS.get(executable, frozenset())
        if subcommand in mutating:
            return RiskLevel.PRIVILEGED, f"{executable} {subcommand} changes system state"
        if subcommand in read_only:
            return RiskLevel.READ, f"{executable} {subcommand} only reads state"
        return RiskLevel.PRIVILEGED, f"unrecognised {executable} subcommand {subcommand!r}"

    if executable in PRIVILEGED_EXECUTABLES:
        read_only = READ_ONLY_SUBCOMMANDS.get(executable, frozenset())
        if subcommand is not None and subcommand in read_only:
            return RiskLevel.READ, f"{executable} {subcommand} only reads state"
        return RiskLevel.PRIVILEGED, f"{executable} can change system state"

    for argument in arguments:
        for pattern in DESTRUCTIVE_ARGUMENT_PATTERNS:
            if pattern.match(argument):
                return RiskLevel.DESTRUCTIVE, f"forcing flag {argument!r}"

    return RiskLevel.READ, f"{executable} is treated as a read-only inspection command"


def classify_command_string(command: str) -> tuple[RiskLevel, str]:
    """Classify a command written as a single string.

    Provided for auditing and for classifying model output *before* it becomes
    an argv vector. Parsing uses :func:`shlex.split`, never a shell.
    """
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        return RiskLevel.DESTRUCTIVE, f"unparseable command: {exc}"
    return classify_command(argv)


def classify_path_write(path: str | Path, *, workspace: Path) -> tuple[RiskLevel, str]:
    """Risk of creating or modifying ``path``."""
    if is_inside_workspace(path, workspace=workspace):
        return RiskLevel.WRITE, "inside the configured workspace"
    return RiskLevel.PRIVILEGED, "outside the configured workspace"


def classify_path_delete(path: str | Path, *, workspace: Path) -> tuple[RiskLevel, str]:
    """Risk of deleting ``path``.

    Deletion inside the workspace is a normal WRITE; anywhere else it is
    DESTRUCTIVE, because the data is not ours and may not be recoverable.
    """
    if is_inside_workspace(path, workspace=workspace):
        return RiskLevel.WRITE, "deleting inside the configured workspace"
    return RiskLevel.DESTRUCTIVE, "deleting outside the configured workspace"


__all__ = [
    "DESTRUCTIVE_ARGUMENT_PATTERNS",
    "DESTRUCTIVE_EXECUTABLES",
    "PRIVILEGED_EXECUTABLES",
    "SHELL_METACHARACTERS",
    "classify_command",
    "classify_command_string",
    "classify_path_delete",
    "classify_path_write",
]
