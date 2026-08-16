"""Filesystem containment must hold.

These are the tests that matter most in this repository. If path validation can
be bypassed, every other control is decoration.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.errors import PathNotAllowed
from scrappy_os.security.paths import (
    is_within,
    validate_read_path,
    validate_write_path,
)
from scrappy_os.tools.base import ToolContext
from scrappy_os.tools.filesystem import FSReadTool, FSWriteTool, ReadArgs, WriteArgs

pytestmark = pytest.mark.security


TRAVERSAL_ATTEMPTS = [
    "../../../etc/shadow",
    "../../etc/passwd",
    "..",
    "../",
    "subdir/../../../../etc/passwd",
    "./../../root/.ssh/id_rsa",
    "/etc/shadow",
    "/root/.ssh/authorized_keys",
]


@pytest.mark.parametrize("attempt", TRAVERSAL_ATTEMPTS)
def test_write_path_cannot_escape_the_workspace(workspace: Path, attempt: str) -> None:
    """Relative traversal, absolute paths and bare `..` are all refused."""
    candidate = workspace / attempt if not attempt.startswith("/") else Path(attempt)
    with pytest.raises(PathNotAllowed):
        validate_write_path(candidate, workspace=workspace)


@pytest.mark.parametrize("attempt", TRAVERSAL_ATTEMPTS)
def test_read_path_cannot_escape_the_allowed_roots(workspace: Path, attempt: str) -> None:
    """Reads are confined to the configured roots, workspace included."""
    candidate = workspace / attempt if not attempt.startswith("/") else Path(attempt)
    with pytest.raises(PathNotAllowed):
        validate_read_path(candidate, allowed_roots=(), workspace=workspace)


def test_symlink_out_of_workspace_is_refused(workspace: Path, tmp_path: Path) -> None:
    """The check follows symlinks: a link is not a way out.

    This is the bypass that defeats naive string-prefix validation - the path
    starts with the workspace, but the file it opens does not live there.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("private")

    link = workspace / "innocent.txt"
    link.symlink_to(secret)

    with pytest.raises(PathNotAllowed):
        validate_read_path(link, allowed_roots=(), workspace=workspace)
    with pytest.raises(PathNotAllowed):
        validate_write_path(link, workspace=workspace)


def test_symlinked_directory_out_of_workspace_is_refused(workspace: Path, tmp_path: Path) -> None:
    """A symlinked *directory* cannot be used as a staging point either."""
    outside = tmp_path / "escape-hatch"
    outside.mkdir()
    (workspace / "link-dir").symlink_to(outside, target_is_directory=True)

    with pytest.raises(PathNotAllowed):
        validate_write_path(workspace / "link-dir" / "payload.txt", workspace=workspace)


def test_sibling_directory_prefix_is_not_containment(tmp_path: Path) -> None:
    """`/data-evil` is not inside `/data`, even though the string starts with it."""
    workspace = tmp_path / "data"
    workspace.mkdir()
    sibling = tmp_path / "data-evil"
    sibling.mkdir()

    assert not is_within(sibling.resolve(), workspace.resolve())
    with pytest.raises(PathNotAllowed):
        validate_write_path(sibling / "file.txt", workspace=workspace)


def test_nul_byte_in_path_is_refused(workspace: Path) -> None:
    with pytest.raises(PathNotAllowed, match="NUL"):
        validate_read_path("/etc/passwd\x00.txt", allowed_roots=(Path("/etc"),))


def test_credential_files_are_never_readable_even_inside_a_root() -> None:
    """`/etc` being readable does not make `/etc/shadow` readable."""
    with pytest.raises(PathNotAllowed, match="credentials"):
        validate_read_path("/etc/shadow", allowed_roots=(Path("/etc"),))


def test_system_directories_are_never_writable(tmp_path: Path) -> None:
    """Even a misconfigured workspace cannot make /etc writable."""
    with pytest.raises(PathNotAllowed, match="never writable"):
        validate_write_path("/etc/passwd", workspace=Path("/"))


def test_workspace_paths_are_allowed(workspace: Path) -> None:
    """The control is containment, not refusal: legitimate paths still work."""
    target = workspace / "notes" / "report.md"
    resolved = validate_write_path(target, workspace=workspace)
    assert resolved.is_relative_to(workspace.resolve())


async def test_fs_read_tool_refuses_traversal(settings: ScrappySettings) -> None:
    """The tool, not just the helper, enforces containment."""
    ctx = ToolContext(settings=settings, task_id="t", actor="test")
    tool = FSReadTool()
    with pytest.raises(PathNotAllowed):
        await tool.run(ReadArgs(path="/root/.ssh/id_rsa"), ctx)


async def test_fs_write_tool_refuses_outside_workspace(
    settings: ScrappySettings, tmp_path: Path
) -> None:
    ctx = ToolContext(settings=settings, task_id="t", actor="test")
    tool = FSWriteTool()
    target = tmp_path / "outside-workspace.txt"
    with pytest.raises(PathNotAllowed):
        await tool.run(WriteArgs(path=str(target), content="x"), ctx)
    assert not target.exists(), "the file must not exist after a refused write"


async def test_fs_write_tool_writes_inside_workspace(
    settings: ScrappySettings, workspace: Path
) -> None:
    ctx = ToolContext(settings=settings, task_id="t", actor="test")
    result = await FSWriteTool().run(
        WriteArgs(path=str(workspace / "ok.txt"), content="hello"), ctx
    )
    assert result["bytes_written"] == 5
    assert (workspace / "ok.txt").read_text() == "hello"


def test_proc_self_environ_is_outside_the_default_read_roots(workspace: Path) -> None:
    """`/proc/self/environ` holds this process's secrets.

    It is readable only if an operator explicitly adds /proc, and that is a
    documented consequence rather than a default.
    """
    with pytest.raises(PathNotAllowed):
        validate_read_path("/proc/self/environ", allowed_roots=(Path("/etc"),), workspace=workspace)


def test_resolved_path_is_returned_not_the_input(workspace: Path) -> None:
    """Callers must use the resolved path, so validation and use cannot diverge."""
    messy = workspace / "a" / ".." / "b.txt"
    resolved = validate_write_path(messy, workspace=workspace)
    assert resolved == (workspace / "b.txt").resolve()
    assert ".." not in str(resolved)


def test_home_expansion_does_not_escape(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`~` expands before validation, so it cannot smuggle a path out."""
    monkeypatch.setenv("HOME", str(workspace.parent))
    with pytest.raises(PathNotAllowed):
        validate_write_path("~/escaped.txt", workspace=workspace)


def test_environment_variable_in_path_is_not_expanded(workspace: Path) -> None:
    """`$HOME/x` is treated as a literal name, not an expansion.

    Path validation deliberately does not run shell expansion; a literal
    directory named ``$HOME`` inside the workspace is fine, and a path that
    *depends* on expansion to escape simply does not resolve out.
    """
    resolved = validate_write_path(str(workspace / "$HOME" / "x.txt"), workspace=workspace)
    assert resolved.is_relative_to(workspace.resolve())


def test_relative_path_resolves_against_cwd_and_is_still_checked(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bare relative path is resolved, then checked like anything else."""
    monkeypatch.chdir(workspace)
    resolved = validate_write_path("inside.txt", workspace=workspace)
    assert resolved == (workspace / "inside.txt").resolve()

    monkeypatch.chdir(os.path.sep)
    with pytest.raises(PathNotAllowed):
        validate_write_path("outside.txt", workspace=workspace)
