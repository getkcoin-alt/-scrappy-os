"""Terminal rendering.

Plain ANSI rather than a table library: the output is read by operators over
SSH and piped into files, so it stays legible without colour and does not
depend on a renderer's idea of terminal width. Colour is dropped automatically
when stdout is not a TTY.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import Any

import typer

from scrappy_os.core.models import ApprovalRequest


def _colour_enabled() -> bool:
    return sys.stdout.isatty()


def _wrap(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _colour_enabled() else text


def bold(text: str) -> str:
    return _wrap(text, "1")


def dim(text: str) -> str:
    return _wrap(text, "2")


def green(text: str) -> str:
    return _wrap(text, "32")


def yellow(text: str) -> str:
    return _wrap(text, "33")


def red(text: str) -> str:
    return _wrap(text, "31")


def success(text: str) -> str:
    return green(text)


def warn(text: str, *, prefix: bool = True) -> str:
    return yellow(f"  warning: {text}" if prefix else text)


def error(text: str) -> str:
    return red(text)


def heading(text: str) -> None:
    typer.echo("")
    typer.echo(bold(f"  {text}"))
    typer.echo(dim("  " + "-" * max(len(text), 10)))


def key_value(key: str, value: str) -> None:
    typer.echo(f"  {key:<20} {value}")


def status_badge(status: str) -> str:
    rendered = status.upper()
    if status in {"healthy", "up", "PASS", "completed"}:
        return green(rendered)
    if status in {"degraded", "unknown", "WARN", "starting", "stopping"}:
        return yellow(rendered)
    if status in {"down", "FAIL", "failed"}:
        return red(rendered)
    return rendered


def render_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    """Print an aligned table. Column widths adapt to content."""
    if not rows:
        typer.echo(dim("  (nothing to show)"))
        return

    columns = len(headers)
    widths = [len(str(header)) for header in headers]
    for row in rows:
        for index in range(columns):
            cell = str(row[index]) if index < len(row) else ""
            widths[index] = max(widths[index], len(_strip_ansi(cell)))

    header_line = "  ".join(str(header).ljust(widths[i]) for i, header in enumerate(headers))
    typer.echo(f"  {dim(header_line)}")
    for row in rows:
        cells = []
        for index in range(columns):
            cell = str(row[index]) if index < len(row) else ""
            padding = widths[index] - len(_strip_ansi(cell))
            cells.append(cell + " " * max(0, padding))
        typer.echo("  " + "  ".join(cells))


def _strip_ansi(text: str) -> str:
    """Length of the visible text, for alignment with colour codes present."""
    import re

    return re.sub(r"\033\[[0-9;]*m", "", text)


def render_approval_prompt(request: ApprovalRequest, *, objective: str = "") -> str:
    """The approval block shown at a terminal.

    The exact operation is shown, not a category. An operator approving
    "restart a service" without being told *which* service has not really
    approved anything.
    """
    risk = str(request.risk).upper()
    colour = red if risk == "DESTRUCTIVE" else yellow
    lines = [
        "",
        colour("  Approval required"),
        f"  Task:    {objective or request.task_id}",
        f"  Action:  {bold(request.summary)}",
        f"  Risk:    {colour(risk)}",
        f"  Reason:  {request.reason}",
    ]
    if request.expires_at:
        lines.append(f"  Expires: {request.expires_at.isoformat(timespec='seconds')}")
    if request.requires_confirmation_phrase:
        lines.append(red("  This operation destroys data or availability."))
    return "\n".join(lines)


def render_outcome(payload: dict[str, Any]) -> None:
    """Render the result of ``scrappy ask``."""
    heading("Result")
    key_value("task", payload["task_id"])
    key_value("state", status_badge(payload["state"]))

    calls = payload.get("tool_calls") or []
    if calls:
        heading("Steps")
        render_table(
            ["tool", "risk", "policy", "outcome", "ms"],
            [
                [
                    call["tool"],
                    str(call["risk"]).upper(),
                    call["rule"],
                    green("ok") if call["success"] else red("failed"),
                    f"{call['duration_ms']:.0f}",
                ]
                for call in calls
            ],
        )
        refused = [call for call in calls if call["decision"] == "deny"]
        if refused:
            typer.echo("")
            for call in refused:
                typer.echo(yellow(f"  refused: {call['tool']} - {call['error']}"))

    heading("Conclusion")
    for line in (payload.get("conclusion") or "(no conclusion)").splitlines():
        typer.echo(f"  {line}")

    if payload.get("stopped_because"):
        typer.echo("")
        typer.echo(yellow(f"  stopped: {payload['stopped_because']}"))

    budget = payload.get("budget") or {}
    if budget:
        typer.echo("")
        typer.echo(
            dim(
                f"  {budget.get('steps_executed', 0)} step(s), "
                f"{budget.get('model_calls', 0)} inference call(s), "
                f"{budget.get('elapsed_seconds', 0)}s"
            )
        )
    if payload.get("development_provider"):
        typer.echo(
            dim(
                "  Provider: deterministic development stub. "
                "Set SCRAPPY_MODEL_PROVIDER=openai or ollama for real reasoning."
            )
        )


__all__ = [
    "bold",
    "dim",
    "error",
    "heading",
    "key_value",
    "render_approval_prompt",
    "render_outcome",
    "render_table",
    "status_badge",
    "success",
    "warn",
]
