"""Filesystem path validation - the immune system's first checkpoint.

The threat is not only ``../../../etc/shadow``. It is also symlinks that point
out of the workspace, absolute paths smuggled in as "relative", NUL bytes, and
TOCTOU races where a path validates as a file and is swapped for a link before
it is opened.

The approach: resolve the path fully (following symlinks), then require the
*resolved* result to sit under an allowed root. Resolution happens once and the
resolved path is what callers use - validating one string and opening another
is the classic way this check gets defeated.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path

from scrappy_os.core.errors import PathNotAllowed

#: Trees that are never writable, whatever the configuration says.
FORBIDDEN_WRITE_ROOTS: tuple[str, ...] = (
    "/boot",
    "/dev",
    "/etc",
    "/proc",
    "/sys",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/var/lib/dpkg",
    "/var/lib/rpm",
)

#: Files whose contents are secret even when the directory is readable.
SENSITIVE_READ_PATHS: tuple[str, ...] = (
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/root/.ssh",
    "/root/.aws",
    "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssh/ssh_host_ecdsa_key",
    "/etc/ssh/ssh_host_ed25519_key",
)


def _resolve(raw: str | Path) -> Path:
    """Normalise and fully resolve a path, rejecting obvious garbage.

    ``strict=False`` so that a not-yet-created file can still be validated -
    the parent chain is resolved, which is what matters for containment.
    """
    text = str(raw)
    if "\x00" in text:
        raise PathNotAllowed(text, reason="path contains a NUL byte")
    if not text.strip():
        raise PathNotAllowed(text, reason="path is empty")
    try:
        return Path(text).expanduser().resolve(strict=False)
    except (OSError, RuntimeError) as exc:  # RuntimeError: symlink loop
        raise PathNotAllowed(text, reason=f"cannot resolve: {exc}") from exc


def is_within(candidate: Path, root: Path) -> bool:
    """Containment test on already-resolved paths.

    ``Path.is_relative_to`` is used rather than string prefixes so that
    ``/data-evil`` is not considered inside ``/data``.
    """
    return candidate == root or candidate.is_relative_to(root)


def validate_read_path(
    raw: str | Path,
    *,
    allowed_roots: Sequence[Path],
    workspace: Path | None = None,
) -> Path:
    """Resolve ``raw`` and confirm it may be read.

    Returns the resolved path. Callers must use the returned value, never the
    original string.
    """
    resolved = _resolve(raw)
    roots = _all_roots(allowed_roots, workspace)

    for sensitive in SENSITIVE_READ_PATHS:
        sensitive_path = Path(sensitive)
        if resolved == sensitive_path or is_within(resolved, sensitive_path):
            raise PathNotAllowed(str(resolved), reason="path holds credentials and is never read")

    if not any(is_within(resolved, root) for root in roots):
        raise PathNotAllowed(
            str(resolved),
            reason=f"outside every allowed read root ({', '.join(str(r) for r in roots)})",
        )
    return resolved


def validate_write_path(
    raw: str | Path,
    *,
    workspace: Path,
    extra_roots: Iterable[Path] = (),
) -> Path:
    """Resolve ``raw`` and confirm it may be written.

    Writes are far more restricted than reads: the workspace plus whatever the
    operator explicitly added, minus the never-writable system trees. A write
    root that overlaps ``/etc`` is refused even if configured, because a
    misconfiguration should not become a privilege escalation.
    """
    resolved = _resolve(raw)
    roots = [workspace.expanduser().resolve(strict=False)]
    roots.extend(root.expanduser().resolve(strict=False) for root in extra_roots)

    for forbidden in FORBIDDEN_WRITE_ROOTS:
        forbidden_path = Path(forbidden)
        if is_within(resolved, forbidden_path):
            raise PathNotAllowed(
                str(resolved), reason=f"{forbidden} is never writable by Scrappy OS"
            )

    if not any(is_within(resolved, root) for root in roots):
        raise PathNotAllowed(
            str(resolved),
            reason=f"outside the writable workspace ({', '.join(str(r) for r in roots)})",
        )

    if resolved.is_symlink():
        raise PathNotAllowed(str(resolved), reason="refusing to write through a symlink")

    return resolved


def is_inside_workspace(raw: str | Path, *, workspace: Path) -> bool:
    """Cheap predicate used by risk classification, never for enforcement."""
    try:
        resolved = _resolve(raw)
    except PathNotAllowed:
        return False
    return is_within(resolved, workspace.expanduser().resolve(strict=False))


def _all_roots(allowed_roots: Sequence[Path], workspace: Path | None) -> list[Path]:
    roots = [root.expanduser().resolve(strict=False) for root in allowed_roots]
    if workspace is not None:
        roots.append(workspace.expanduser().resolve(strict=False))
    if not roots:
        raise PathNotAllowed("<none>", reason="no read roots are configured")
    return roots


__all__ = [
    "FORBIDDEN_WRITE_ROOTS",
    "SENSITIVE_READ_PATHS",
    "is_inside_workspace",
    "is_within",
    "validate_read_path",
    "validate_write_path",
]
