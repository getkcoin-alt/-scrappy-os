"""Git tools - typed, read-only in v0.1.

Git is exposed as named operations rather than "run git with these arguments",
so there is no path from a model to ``git push --force`` or ``git clean -xfd``
through this module. Mutating operations are a v0.2 item and will be separate
tools with their own risk classifications, not extra flags on these.

Each tool runs ``git`` directly (no shell) with a filtered environment, and the
repository path is validated before use.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from scrappy_os.core.enums import RiskLevel
from scrappy_os.core.errors import ToolError
from scrappy_os.security.paths import validate_read_path
from scrappy_os.tools.base import Tool, ToolContext
from scrappy_os.tools.shell import SAFE_PATH, build_child_env

#: Output cap for git commands, which can be enormous on a large diff.
MAX_GIT_OUTPUT = 256 * 1024
GIT_TIMEOUT_SECONDS = 30.0


class RepoArgs(BaseModel):
    model_config = {"extra": "forbid"}

    repo_path: str = Field(default=".", max_length=4096)


class LogArgs(RepoArgs):
    limit: int = Field(default=20, ge=1, le=200)


class DiffArgs(RepoArgs):
    staged: bool = Field(default=False, description="Show the index instead of the working tree.")
    name_only: bool = Field(default=True, description="Paths only; full patches get large fast.")


class BranchArgs(RepoArgs):
    include_remote: bool = False


class _GitTool(Tool):
    """Shared plumbing for the read-only git tools."""

    risk = RiskLevel.READ
    required_permissions = ("git:read",)

    async def _git(self, arguments: list[str], repo_path: str, ctx: ToolContext) -> str:
        binary = shutil.which("git", path=SAFE_PATH)
        if binary is None:
            raise ToolError("git is not installed on this machine", tool_name=self.name)

        repo = validate_read_path(repo_path, allowed_roots=ctx.read_roots, workspace=ctx.workspace)
        if not repo.is_dir():
            raise ToolError(f"{repo} is not a directory", tool_name=self.name)
        if not await asyncio.to_thread(_is_repository, repo):
            raise ToolError(f"{repo} is not inside a git repository", tool_name=self.name)

        argv = [
            binary,
            "-c",
            "core.pager=cat",
            "-C",
            str(repo),
            *arguments,
        ]
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL,
                env={**build_child_env(), "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat"},
                start_new_session=True,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=GIT_TIMEOUT_SECONDS
            )
        except TimeoutError as exc:
            raise ToolError(
                f"git {arguments[0]} exceeded {GIT_TIMEOUT_SECONDS}s", tool_name=self.name
            ) from exc
        except OSError as exc:
            raise ToolError(f"Cannot run git: {exc}", tool_name=self.name) from exc

        if process.returncode != 0:
            detail = stderr.decode("utf-8", errors="replace").strip()[:500]
            raise ToolError(
                f"git {arguments[0]} failed (exit {process.returncode}): {detail}",
                tool_name=self.name,
                exit_code=process.returncode,
            )
        return stdout[:MAX_GIT_OUTPUT].decode("utf-8", errors="replace")


class GitStatusTool(_GitTool):
    """Working-tree status."""

    name = "git.status"
    description = "Branch, upstream and changed files for a repository."
    input_model = RepoArgs

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, RepoArgs)
        raw = await self._git(["status", "--porcelain=v2", "--branch"], args.repo_path, ctx)

        branch: str | None = None
        upstream: str | None = None
        changes: list[dict[str, str]] = []
        untracked: list[str] = []

        for line in raw.splitlines():
            if line.startswith("# branch.head"):
                branch = line.split(" ", 2)[-1]
            elif line.startswith("# branch.upstream"):
                upstream = line.split(" ", 2)[-1]
            elif line.startswith("1 ") or line.startswith("2 "):
                parts = line.split(" ", 9)
                changes.append({"status": parts[1], "path": parts[-1]})
            elif line.startswith("? "):
                untracked.append(line[2:])

        return {
            "repo_path": args.repo_path,
            "branch": branch,
            "upstream": upstream,
            "changed_files": changes,
            "untracked_files": untracked,
            "is_clean": not changes and not untracked,
            "change_count": len(changes) + len(untracked),
        }


class GitLogTool(_GitTool):
    """Recent commits."""

    name = "git.log"
    description = "Recent commits with hash, author, date and subject."
    input_model = LogArgs

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, LogArgs)
        raw = await self._git(
            ["log", f"-{args.limit}", "--pretty=format:%H%x1f%an%x1f%aI%x1f%s"],
            args.repo_path,
            ctx,
        )
        commits = []
        for line in raw.splitlines():
            fields = line.split("\x1f")
            if len(fields) == 4:
                commits.append(
                    {
                        "sha": fields[0],
                        "short_sha": fields[0][:8],
                        "author": fields[1],
                        "date": fields[2],
                        "subject": fields[3],
                    }
                )
        return {"repo_path": args.repo_path, "commits": commits, "count": len(commits)}


class GitDiffTool(_GitTool):
    """Working-tree or staged diff."""

    name = "git.diff"
    description = "Changed paths, or a full patch when name_only is false."
    input_model = DiffArgs

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, DiffArgs)
        arguments = ["diff"]
        if args.staged:
            arguments.append("--cached")
        arguments.append("--name-status" if args.name_only else "--unified=3")
        raw = await self._git(arguments, args.repo_path, ctx)

        if args.name_only:
            files = [
                {"status": parts[0], "path": parts[1]}
                for parts in (line.split("\t", 1) for line in raw.splitlines())
                if len(parts) == 2
            ]
            return {"repo_path": args.repo_path, "files": files, "count": len(files)}
        return {
            "repo_path": args.repo_path,
            "patch": raw,
            "truncated": len(raw) >= MAX_GIT_OUTPUT,
        }


class GitBranchTool(_GitTool):
    """Branch listing."""

    name = "git.branch"
    description = "List branches and identify the checked-out one."
    input_model = BranchArgs

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, BranchArgs)
        arguments = ["branch", "--format=%(refname:short)%00%(HEAD)"]
        if args.include_remote:
            arguments.append("--all")
        raw = await self._git(arguments, args.repo_path, ctx)

        branches = []
        current: str | None = None
        for line in raw.splitlines():
            name, _, marker = line.partition("\x00")
            if not name:
                continue
            is_current = marker.strip() == "*"
            if is_current:
                current = name
            branches.append({"name": name, "current": is_current})
        return {
            "repo_path": args.repo_path,
            "branches": branches,
            "current": current,
            "count": len(branches),
        }


def _is_repository(path: Path) -> bool:
    """Walk up looking for a ``.git`` entry, the way git itself does."""
    for candidate in [path, *path.parents]:
        if (candidate / ".git").exists():
            return True
    return False


GIT_TOOLS: tuple[Tool, ...] = (
    GitStatusTool(),
    GitLogTool(),
    GitDiffTool(),
    GitBranchTool(),
)

__all__ = [
    "GIT_TOOLS",
    "GitBranchTool",
    "GitDiffTool",
    "GitLogTool",
    "GitStatusTool",
]
