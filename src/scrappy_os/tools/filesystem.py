"""Filesystem tools.

Reads and writes are separately permissioned and separately classified. Every
path argument goes through :mod:`scrappy_os.security.paths` before it is used,
and the *resolved* path is what gets opened - validating one string and opening
another is how containment checks get defeated.

Risk here is argument-dependent:

* ``fs.read`` / ``fs.list`` / ``fs.stat`` - READ, restricted to allowed roots.
* ``fs.write`` / ``fs.mkdir`` / ``fs.move`` - WRITE inside the workspace,
  PRIVILEGED outside it.
* ``fs.delete`` - WRITE inside the workspace, DESTRUCTIVE outside it.

All file I/O runs in a worker thread. Blocking the event loop while reading a
slow disk would stall the heartbeat and every other task.
"""

from __future__ import annotations

import asyncio
import os
import shutil
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from scrappy_os.core.enums import RiskLevel
from scrappy_os.core.errors import ToolError
from scrappy_os.security.paths import validate_read_path, validate_write_path
from scrappy_os.security.risk import classify_path_delete, classify_path_write
from scrappy_os.tools.base import RollbackSpec, Tool, ToolContext
from scrappy_os.tools.system import human_bytes

#: Refuse to load a file larger than this into memory or a prompt.
MAX_READ_BYTES = 1024 * 1024
#: Refuse to write more than this in one call.
MAX_WRITE_BYTES = 4 * 1024 * 1024
#: Cap directory listings so one call cannot exhaust memory or a context window.
MAX_ENTRIES = 1000


class PathArgs(BaseModel):
    model_config = {"extra": "forbid"}

    path: str = Field(min_length=1, max_length=4096)


class ListArgs(PathArgs):
    limit: int = Field(default=200, ge=1, le=MAX_ENTRIES)
    include_hidden: bool = False


class ReadArgs(PathArgs):
    max_bytes: int = Field(default=64 * 1024, ge=1, le=MAX_READ_BYTES)
    encoding: str = Field(default="utf-8", max_length=32)


class WriteArgs(PathArgs):
    content: str = Field(max_length=MAX_WRITE_BYTES)
    create_parents: bool = True
    overwrite: bool = Field(
        default=False, description="Refuse to clobber an existing file unless true."
    )


class MoveArgs(BaseModel):
    model_config = {"extra": "forbid"}

    source: str = Field(min_length=1, max_length=4096)
    destination: str = Field(min_length=1, max_length=4096)
    overwrite: bool = False


class DeleteArgs(PathArgs):
    recursive: bool = Field(default=False, description="Required to remove a non-empty directory.")


class FSListTool(Tool):
    """Directory listing."""

    name = "fs.list"
    description = "List directory entries with type, size and modification time."
    input_model = ListArgs
    risk = RiskLevel.READ
    required_permissions = ("fs:read",)

    def affected_paths(self, args: BaseModel) -> Sequence[Path]:
        assert isinstance(args, ListArgs)
        return (Path(args.path),)

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, ListArgs)
        resolved = validate_read_path(
            args.path, allowed_roots=ctx.read_roots, workspace=ctx.workspace
        )
        return await asyncio.to_thread(self._list, resolved, args.limit, args.include_hidden)

    def _list(self, resolved: Path, limit: int, include_hidden: bool) -> dict[str, Any]:
        if not resolved.is_dir():
            raise ToolError(f"{resolved} is not a directory", tool_name=self.name)
        entries: list[dict[str, Any]] = []
        truncated = False
        try:
            with os.scandir(resolved) as scanner:
                for entry in scanner:
                    if not include_hidden and entry.name.startswith("."):
                        continue
                    if len(entries) >= limit:
                        truncated = True
                        break
                    entries.append(_describe_entry(entry))
        except PermissionError as exc:
            raise ToolError(f"Permission denied reading {resolved}", tool_name=self.name) from exc
        except OSError as exc:
            raise ToolError(f"Cannot list {resolved}: {exc}", tool_name=self.name) from exc

        entries.sort(key=lambda item: (item["type"] != "directory", item["name"]))
        return {
            "path": str(resolved),
            "entries": entries,
            "count": len(entries),
            "truncated": truncated,
        }


class FSStatTool(Tool):
    """Metadata for a single path."""

    name = "fs.stat"
    description = "Size, mode, owner, timestamps and type for one path."
    input_model = PathArgs
    risk = RiskLevel.READ
    required_permissions = ("fs:read",)

    def affected_paths(self, args: BaseModel) -> Sequence[Path]:
        assert isinstance(args, PathArgs)
        return (Path(args.path),)

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, PathArgs)
        resolved = validate_read_path(
            args.path, allowed_roots=ctx.read_roots, workspace=ctx.workspace
        )
        return await asyncio.to_thread(self._stat, resolved)

    def _stat(self, resolved: Path) -> dict[str, Any]:
        try:
            info = resolved.lstat()
        except FileNotFoundError as exc:
            raise ToolError(f"{resolved} does not exist", tool_name=self.name) from exc
        except OSError as exc:
            raise ToolError(f"Cannot stat {resolved}: {exc}", tool_name=self.name) from exc
        return {
            "path": str(resolved),
            "exists": True,
            "type": _path_type(resolved),
            "size_bytes": info.st_size,
            "size_human": human_bytes(info.st_size),
            "mode": oct(info.st_mode & 0o7777),
            "uid": info.st_uid,
            "gid": info.st_gid,
            "modified_at": datetime.fromtimestamp(info.st_mtime, tz=UTC).isoformat(),
            "is_symlink": resolved.is_symlink(),
        }


class FSReadTool(Tool):
    """Read a text file, bounded."""

    name = "fs.read"
    description = "Read a UTF-8 text file, truncated to a byte budget."
    input_model = ReadArgs
    risk = RiskLevel.READ
    required_permissions = ("fs:read",)

    def affected_paths(self, args: BaseModel) -> Sequence[Path]:
        assert isinstance(args, ReadArgs)
        return (Path(args.path),)

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, ReadArgs)
        resolved = validate_read_path(
            args.path, allowed_roots=ctx.read_roots, workspace=ctx.workspace
        )
        return await asyncio.to_thread(self._read, resolved, args.max_bytes, args.encoding)

    def _read(self, resolved: Path, max_bytes: int, encoding: str) -> dict[str, Any]:
        try:
            if resolved.is_dir():
                raise ToolError(f"{resolved} is a directory", tool_name=self.name)
            with resolved.open("rb") as handle:
                raw = handle.read(max_bytes + 1)
        except FileNotFoundError as exc:
            raise ToolError(f"{resolved} does not exist", tool_name=self.name) from exc
        except PermissionError as exc:
            raise ToolError(f"Permission denied reading {resolved}", tool_name=self.name) from exc
        except OSError as exc:
            raise ToolError(f"Cannot read {resolved}: {exc}", tool_name=self.name) from exc

        truncated = len(raw) > max_bytes
        body = raw[:max_bytes]
        try:
            text = body.decode(encoding, errors="replace")
        except LookupError as exc:
            raise ToolError(f"Unknown encoding {encoding!r}", tool_name=self.name) from exc

        return {
            "path": str(resolved),
            "content": text,
            "bytes_read": len(body),
            "truncated": truncated,
            "lines": text.count("\n") + (1 if text and not text.endswith("\n") else 0),
        }


class FSMkdirTool(Tool):
    """Create a directory."""

    name = "fs.mkdir"
    description = "Create a directory, with parents, inside the workspace."
    input_model = PathArgs
    risk = RiskLevel.WRITE
    required_permissions = ("fs:write",)
    rollback = RollbackSpec(
        supported=True,
        description="Remove the created directory if it is still empty.",
        inverse_tool="fs.delete",
    )

    def affected_paths(self, args: BaseModel) -> Sequence[Path]:
        assert isinstance(args, PathArgs)
        return (Path(args.path),)

    def classify(self, args: BaseModel, ctx: ToolContext) -> tuple[RiskLevel, str]:
        assert isinstance(args, PathArgs)
        return classify_path_write(args.path, workspace=ctx.workspace)

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, PathArgs)
        resolved = validate_write_path(args.path, workspace=ctx.workspace)
        existed = await asyncio.to_thread(resolved.exists)
        try:
            await asyncio.to_thread(lambda: resolved.mkdir(parents=True, exist_ok=True))
        except OSError as exc:
            raise ToolError(f"Cannot create {resolved}: {exc}", tool_name=self.name) from exc
        return {"path": str(resolved), "created": not existed, "already_existed": existed}


class FSWriteTool(Tool):
    """Write a text file."""

    name = "fs.write"
    description = "Write UTF-8 text to a file inside the workspace."
    input_model = WriteArgs
    risk = RiskLevel.WRITE
    required_permissions = ("fs:write",)
    rollback = RollbackSpec(
        supported=True,
        description="A .scrappy-bak copy of any overwritten file is kept alongside it.",
    )

    def affected_paths(self, args: BaseModel) -> Sequence[Path]:
        assert isinstance(args, WriteArgs)
        return (Path(args.path),)

    def classify(self, args: BaseModel, ctx: ToolContext) -> tuple[RiskLevel, str]:
        assert isinstance(args, WriteArgs)
        return classify_path_write(args.path, workspace=ctx.workspace)

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, WriteArgs)
        resolved = validate_write_path(args.path, workspace=ctx.workspace)
        return await asyncio.to_thread(self._write, resolved, args)

    def _write(self, resolved: Path, args: WriteArgs) -> dict[str, Any]:
        existed = resolved.exists()
        if existed and not args.overwrite:
            raise ToolError(
                f"{resolved} exists; pass overwrite=true to replace it", tool_name=self.name
            )

        backup: str | None = None
        try:
            if args.create_parents:
                resolved.parent.mkdir(parents=True, exist_ok=True)
            if existed:
                # Preserve before-state so rollback is possible at all.
                backup_path = resolved.with_suffix(resolved.suffix + ".scrappy-bak")
                shutil.copy2(resolved, backup_path)
                backup = str(backup_path)
            payload = args.content.encode("utf-8")
            resolved.write_bytes(payload)
        except OSError as exc:
            raise ToolError(f"Cannot write {resolved}: {exc}", tool_name=self.name) from exc

        return {
            "path": str(resolved),
            "bytes_written": len(payload),
            "overwrote": existed,
            "backup_path": backup,
        }


class FSMoveTool(Tool):
    """Move or rename a path."""

    name = "fs.move"
    description = "Move or rename a file or directory within the workspace."
    input_model = MoveArgs
    risk = RiskLevel.WRITE
    required_permissions = ("fs:write",)
    rollback = RollbackSpec(supported=True, description="Move it back.", inverse_tool="fs.move")

    def affected_paths(self, args: BaseModel) -> Sequence[Path]:
        assert isinstance(args, MoveArgs)
        return (Path(args.source), Path(args.destination))

    def classify(self, args: BaseModel, ctx: ToolContext) -> tuple[RiskLevel, str]:
        assert isinstance(args, MoveArgs)
        workspace = ctx.workspace
        source_risk, source_reason = classify_path_delete(args.source, workspace=workspace)
        dest_risk, dest_reason = classify_path_write(args.destination, workspace=workspace)
        if source_risk.rank >= dest_risk.rank:
            return source_risk, f"source: {source_reason}"
        return dest_risk, f"destination: {dest_reason}"

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, MoveArgs)
        source = validate_write_path(args.source, workspace=ctx.workspace)
        destination = validate_write_path(args.destination, workspace=ctx.workspace)
        return await asyncio.to_thread(self._move, source, destination, args.overwrite)

    def _move(self, source: Path, destination: Path, overwrite: bool) -> dict[str, Any]:
        if not source.exists():
            raise ToolError(f"{source} does not exist", tool_name=self.name)
        if destination.exists() and not overwrite:
            raise ToolError(
                f"{destination} exists; pass overwrite=true to replace it", tool_name=self.name
            )
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source), str(destination))
        except OSError as exc:
            raise ToolError(
                f"Cannot move {source} to {destination}: {exc}", tool_name=self.name
            ) from exc
        return {"source": str(source), "destination": str(destination), "moved": True}


class FSDeleteTool(Tool):
    """Delete a path.

    Statically DESTRUCTIVE. Deleting inside the workspace is downgraded to
    WRITE by :meth:`classify`, because scratch files are ours to remove; every
    other path stays DESTRUCTIVE and needs a typed confirmation.
    """

    name = "fs.delete"
    description = "Delete a file or directory. Destructive outside the workspace."
    input_model = DeleteArgs
    risk = RiskLevel.DESTRUCTIVE
    required_permissions = ("fs:write", "fs:delete")
    rollback = RollbackSpec(
        supported=False,
        description="Deletion is not reversible. Preserve state before deleting.",
    )

    def affected_paths(self, args: BaseModel) -> Sequence[Path]:
        assert isinstance(args, DeleteArgs)
        return (Path(args.path),)

    def classify(self, args: BaseModel, ctx: ToolContext) -> tuple[RiskLevel, str]:
        assert isinstance(args, DeleteArgs)
        risk, reason = classify_path_delete(args.path, workspace=ctx.workspace)
        if args.recursive and risk is RiskLevel.WRITE:
            return RiskLevel.WRITE, f"{reason} (recursive)"
        return risk, reason

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, DeleteArgs)
        resolved = validate_write_path(args.path, workspace=ctx.workspace)
        return await asyncio.to_thread(self._delete, resolved, args.recursive)

    def _delete(self, resolved: Path, recursive: bool) -> dict[str, Any]:
        if not resolved.exists():
            raise ToolError(f"{resolved} does not exist", tool_name=self.name)
        try:
            if resolved.is_dir():
                if any(resolved.iterdir()) and not recursive:
                    raise ToolError(
                        f"{resolved} is not empty; pass recursive=true", tool_name=self.name
                    )
                if recursive:
                    shutil.rmtree(resolved)
                else:
                    resolved.rmdir()
                kind = "directory"
            else:
                resolved.unlink()
                kind = "file"
        except OSError as exc:
            raise ToolError(f"Cannot delete {resolved}: {exc}", tool_name=self.name) from exc
        return {"path": str(resolved), "deleted": True, "type": kind}


def _describe_entry(entry: os.DirEntry[str]) -> dict[str, Any]:
    try:
        info = entry.stat(follow_symlinks=False)
        size = info.st_size
        modified = datetime.fromtimestamp(info.st_mtime, tz=UTC).isoformat()
    except OSError:
        size, modified = 0, None
    return {
        "name": entry.name,
        "type": "directory"
        if entry.is_dir(follow_symlinks=False)
        else "symlink"
        if entry.is_symlink()
        else "file",
        "size_bytes": size,
        "modified_at": modified,
    }


def _path_type(path: Path) -> str:
    if path.is_symlink():
        return "symlink"
    if path.is_dir():
        return "directory"
    if path.is_file():
        return "file"
    return "other"


FILESYSTEM_TOOLS: tuple[Tool, ...] = (
    FSListTool(),
    FSStatTool(),
    FSReadTool(),
    FSMkdirTool(),
    FSWriteTool(),
    FSMoveTool(),
    FSDeleteTool(),
)

__all__ = [
    "FILESYSTEM_TOOLS",
    "MAX_READ_BYTES",
    "FSDeleteTool",
    "FSListTool",
    "FSMkdirTool",
    "FSMoveTool",
    "FSReadTool",
    "FSStatTool",
    "FSWriteTool",
]
