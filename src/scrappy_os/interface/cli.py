"""``scrappy`` - the command-line face.

The CLI is the only interface that can approve an operation interactively: it
installs a prompt on the executor, so a PRIVILEGED step stops at a terminal and
waits for a human. The API deliberately cannot do this - see
:mod:`scrappy_os.interface.api`.

Commands intentionally do not share a long-lived runtime. Each one starts what
it needs, does its job and shuts down, so a crashed command cannot leave a
half-open database behind.

**The CLI drives the runtime in-process; it does not call the HTTP API.**

That is a deliberate choice, and the alternative was considered. Routing the CLI
through the authenticated API would look more uniform, but the uniformity would
be theatre: the CLI runs as a user who can already read ``.env`` (where the token
lives), open the SQLite audit trail directly, and restart the service. A
credential check against a secret the caller can simply read off disk enforces
nothing - it only makes the boundary *look* stronger than it is, which is worse
than an honest one, because it is the kind of thing that ends up in a diagram.

So the CLI's trust comes from the operating system, and it says so: every command
runs as :func:`~scrappy_os.core.identity.local_cli_actor`, an actor whose
``auth_method`` is ``local_process``. Audit rows from the CLI are therefore
distinguishable from token-authenticated API rows at a glance, which is the
property that actually matters for accountability.

The real boundary is the host's file permissions on the data directory (0700)
and the database (0600). If an untrusted user can run ``scrappy`` on this
machine, they have already lost that fight, and no in-process token would have
saved them. See ``docs/SECURITY.md``.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Annotated, Any

import typer

from scrappy_os import __version__
from scrappy_os.core.config import ScrappySettings, load_settings
from scrappy_os.core.enums import RiskLevel
from scrappy_os.core.identity import local_cli_actor
from scrappy_os.core.models import ApprovalDecision, ApprovalRequest, Objective
from scrappy_os.heart.runtime import Runtime
from scrappy_os.interface.doctor import CheckStatus, run_doctor
from scrappy_os.interface.formatting import (
    dim,
    error,
    heading,
    key_value,
    render_approval_prompt,
    render_outcome,
    render_table,
    status_badge,
    success,
    warn,
)
from scrappy_os.memory.store import open_store
from scrappy_os.observability.logging import configure_logging
from scrappy_os.security.approvals import ApprovalManager
from scrappy_os.security.audit import AuditLog
from scrappy_os.tools import build_default_registry

app = typer.Typer(
    name="scrappy",
    help="Scrappy OS - an AI-native control plane for a Linux machine.",
    add_completion=False,
)
config_app = typer.Typer(help="Inspect configuration.", no_args_is_help=True)
app.add_typer(config_app, name="config")


def _settings(quiet: bool = True) -> ScrappySettings:
    settings = load_settings()
    configure_logging(level="ERROR" if quiet else settings.log_level, fmt=settings.log_format)
    return settings


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    version: Annotated[bool, typer.Option("--version", help="Print the version and exit.")] = False,
) -> None:
    """Handle top-level flags before any subcommand runs."""
    if version:
        typer.echo(f"scrappy-os {__version__}")
        raise typer.Exit(0)
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(0)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


@app.command()
def status(
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Show runtime state, component health and pending approvals."""
    settings = _settings()

    async def run() -> dict[str, Any]:
        runtime = Runtime(settings)
        await runtime.start(configure_logs=False)
        try:
            state = await runtime.health()
            pending = await runtime.approvals.pending()
            audit_count = await runtime.audit.count()
            return {
                "state": state.model_dump(mode="json"),
                "pending_approvals": len(pending),
                "audit_events": audit_count,
                "development_provider": runtime.router.is_development_provider,
            }
        finally:
            await runtime.stop()

    payload = asyncio.run(run())
    if as_json:
        typer.echo(json.dumps(payload, indent=2, default=str))
        return

    state = payload["state"]
    heading("Scrappy OS")
    key_value("version", state["version"])
    key_value("status", status_badge(state["status"]))
    key_value("host", f"{state['hostname']} (pid {state['pid']})")
    key_value("provider", f"{state['provider']} / {state['model']}")
    if payload["development_provider"]:
        typer.echo(warn("inference is the deterministic development provider, not a model"))
    key_value("active tasks", str(len(state["active_task_ids"])))
    key_value("completed / failed", f"{state['completed_tasks']} / {state['failed_tasks']}")
    key_value("audit events", str(payload["audit_events"]))
    key_value("pending approvals", str(payload["pending_approvals"]))

    heading("Components")
    render_table(
        ["component", "status", "detail"],
        [
            [item["name"], status_badge(item["status"]), item["detail"] or ""]
            for item in state["components"]
        ],
    )


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


@app.command()
def doctor(
    skip_provider: Annotated[
        bool, typer.Option("--skip-provider", help="Do not probe the model provider.")
    ] = False,
) -> None:
    """Check that this installation can actually run a task."""
    settings = _settings()
    registry = build_default_registry()

    report = asyncio.run(run_doctor(settings, registry=registry, check_provider=not skip_provider))

    heading("scrappy doctor")
    for result in report.results:
        line = f"  [{result.status.value}] {result.name}: {result.detail}"
        if result.status is CheckStatus.PASS:
            typer.echo(success(line))
        elif result.status is CheckStatus.WARN:
            typer.echo(warn(line, prefix=False))
        else:
            typer.echo(error(line))
        if result.remedy and result.status is not CheckStatus.PASS:
            typer.echo(dim(f"        -> {result.remedy}"))

    counts = report.counts
    typer.echo("")
    typer.echo(f"  {counts['PASS']} passed, {counts['WARN']} warnings, {counts['FAIL']} failures")
    if not report.healthy:
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# ask
# ---------------------------------------------------------------------------


@app.command()
def ask(
    objective: Annotated[str, typer.Argument(help="What you want Scrappy OS to do.")],
    max_risk: Annotated[
        str,
        typer.Option(
            "--max-risk",
            help="Risk ceiling: read, write, privileged or destructive.",
        ),
    ] = "read",
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Describe mutating steps instead of running them.")
    ] = False,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            help="Pre-approve PRIVILEGED steps. DESTRUCTIVE steps still need the typed phrase.",
        ),
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show step logs.")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Give Scrappy OS an objective.

    Read-only by default: raising the ceiling with --max-risk is a deliberate
    act, and even then PRIVILEGED and DESTRUCTIVE steps stop for approval.
    """
    settings = _settings(quiet=not verbose)
    try:
        ceiling = RiskLevel(max_risk.lower())
    except ValueError:
        typer.echo(
            error(f"Unknown risk level {max_risk!r}. Use: read, write, privileged, destructive.")
        )
        raise typer.Exit(2) from None

    async def run() -> dict[str, Any]:
        runtime = Runtime(settings)
        await runtime.start(configure_logs=False)
        runtime.set_approval_prompt(_make_prompt(objective, auto_yes=yes))
        try:
            outcome = await runtime.submit(
                Objective(
                    text=objective,
                    identity=local_cli_actor(),
                    max_risk=ceiling,
                    dry_run=dry_run,
                )
            )
            return {
                "task_id": outcome.task.id,
                "succeeded": outcome.succeeded,
                "state": str(outcome.task.state),
                "conclusion": outcome.conclusion,
                "tool_calls": [
                    {
                        "tool": item.call.tool_name,
                        "risk": str(item.call.risk_level),
                        "decision": str(item.verdict.decision),
                        "rule": item.verdict.rule,
                        "success": item.result.success,
                        "error": item.result.error,
                        "duration_ms": round(item.result.duration_ms, 1),
                    }
                    for item in outcome.executed
                ],
                "budget": outcome.budget,
                "stopped_because": outcome.stopped_because,
                "development_provider": runtime.router.is_development_provider,
            }
        finally:
            await runtime.stop()

    payload = asyncio.run(run())
    if as_json:
        typer.echo(json.dumps(payload, indent=2, default=str))
    else:
        render_outcome(payload)
    if not payload["succeeded"]:
        raise typer.Exit(1)


def _make_prompt(objective: str, *, auto_yes: bool) -> Any:
    """Build the interactive approver used by ``scrappy ask``."""

    async def prompt(request: ApprovalRequest) -> ApprovalDecision:
        typer.echo(render_approval_prompt(request, objective=objective))

        if request.requires_confirmation_phrase:
            # --yes never covers DESTRUCTIVE. A flag typed before the operation
            # was known cannot be informed consent for deleting something.
            if not sys.stdin.isatty():
                return ApprovalDecision(
                    request_id=request.id,
                    approved=False,
                    identity=local_cli_actor(),
                    note="destructive operations cannot be approved without a terminal",
                )
            typed = typer.prompt(f"  Type '{request.confirmation_phrase}' to proceed", default="")
            approved = typed.strip() == request.confirmation_phrase
            return ApprovalDecision(
                request_id=request.id,
                approved=approved,
                identity=local_cli_actor(),
                confirmation_phrase=typed.strip(),
                note=None if approved else "confirmation phrase did not match",
            )

        if auto_yes:
            typer.echo(dim("  auto-approved by --yes"))
            return ApprovalDecision(
                request_id=request.id,
                approved=True,
                identity=local_cli_actor(),
                note="auto-approved by --yes",
            )

        if not sys.stdin.isatty():
            return ApprovalDecision(
                request_id=request.id,
                approved=False,
                identity=local_cli_actor(),
                note="no terminal available to ask for approval",
            )

        approved = typer.confirm("  Approve?", default=False)
        return ApprovalDecision(
            request_id=request.id,
            approved=approved,
            identity=local_cli_actor(),
            note=None if approved else "declined at the prompt",
        )

    return prompt


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


@app.command()
def audit(
    task_id: Annotated[str | None, typer.Argument(help="Show the full trace for one task.")] = None,
    limit: Annotated[int, typer.Option("--limit", "-n", help="How many events.")] = 30,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Show the audit trail."""
    settings = _settings()

    async def run() -> dict[str, Any]:
        async with open_store(settings.db_path) as store:
            log = AuditLog(store)
            if task_id:
                return {
                    "task_id": task_id,
                    "events": await log.for_task(task_id, limit=limit),
                    "calls": await log.calls_for_task(task_id),
                }
            return {"events": await log.recent(limit=limit)}

    payload = asyncio.run(run())
    if as_json:
        typer.echo(json.dumps(payload, indent=2, default=str))
        return

    events = payload["events"]
    if not events:
        typer.echo(dim("No audit events recorded yet."))
        return

    if task_id:
        heading(f"Audit trail for task {task_id}")
        render_table(
            ["time", "event", "component", "tool", "risk", "outcome"],
            [
                [
                    str(event["timestamp"])[11:19],
                    event["event_type"],
                    event["component"],
                    event["tool_name"] or "",
                    event["risk"] or "",
                    _outcome_cell(event),
                ]
                for event in events
            ],
        )
        calls = payload["calls"]
        if calls:
            heading("Tool calls")
            render_table(
                ["tool", "risk", "policy", "approval", "success", "ms"],
                [
                    [
                        call["tool_name"],
                        call["risk_level"],
                        call["policy_decision"] or "",
                        call["approval_state"] or "-",
                        "yes" if call["success"] else "no",
                        f"{call['duration_ms']:.0f}" if call["duration_ms"] else "",
                    ]
                    for call in calls
                ],
            )
        return

    heading(f"Last {len(events)} audit events")
    render_table(
        ["time", "task", "event", "tool", "risk", "outcome"],
        [
            [
                str(event["timestamp"])[:19].replace("T", " "),
                (event["task_id"] or "")[:8],
                event["event_type"],
                event["tool_name"] or "",
                event["risk"] or "",
                _outcome_cell(event),
            ]
            for event in events
        ],
    )


def _outcome_cell(event: dict[str, Any]) -> str:
    if event["event_type"] == "security.denied":
        return "DENIED"
    if event["success"] is None:
        return ""
    return "ok" if event["success"] else "failed"


# ---------------------------------------------------------------------------
# approvals
# ---------------------------------------------------------------------------


@app.command()
def approvals(
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """List approval requests still waiting for a human."""
    settings = _settings()

    async def run() -> list[dict[str, Any]]:
        async with open_store(settings.db_path) as store:
            manager = ApprovalManager(settings, store)
            return [request.model_dump(mode="json") for request in await manager.pending()]

    pending = asyncio.run(run())
    if as_json:
        typer.echo(json.dumps(pending, indent=2, default=str))
        return
    if not pending:
        typer.echo(dim("No pending approvals."))
        return

    heading(f"{len(pending)} pending approval(s)")
    render_table(
        ["id", "risk", "operation", "requested", "expires"],
        [
            [
                item["id"][:8],
                str(item["risk"]).upper(),
                item["summary"][:60],
                str(item["requested_at"])[11:19],
                str(item["expires_at"])[11:19] if item["expires_at"] else "never",
            ]
            for item in pending
        ],
    )
    typer.echo(
        dim("\n  Approve with: scrappy approve <id>   Deny with: scrappy approve <id> --deny")
    )


@app.command()
def approve(
    approval_id: Annotated[str, typer.Argument(help="Approval id, or its first 8 characters.")],
    deny: Annotated[bool, typer.Option("--deny", help="Refuse instead of approving.")] = False,
    phrase: Annotated[
        str | None,
        typer.Option("--phrase", help="Confirmation phrase, required for DESTRUCTIVE requests."),
    ] = None,
) -> None:
    """Resolve a pending approval out of band."""
    settings = _settings()

    async def run() -> str:
        async with open_store(settings.db_path) as store:
            manager = ApprovalManager(settings, store)
            pending = await manager.pending()
            matches = [item for item in pending if item.id.startswith(approval_id)]
            if not matches:
                return f"No pending approval matching {approval_id!r}"
            if len(matches) > 1:
                return f"{approval_id!r} is ambiguous; it matches {len(matches)} requests"

            request = matches[0]
            decision = ApprovalDecision(
                request_id=request.id,
                approved=not deny,
                identity=local_cli_actor(),
                confirmation_phrase=phrase,
                note="resolved via scrappy approve",
            )
            resolved = await manager.resolve(decision)
            return f"Approval {resolved.id} is now {resolved.state}"

    typer.echo(asyncio.run(run()))


# ---------------------------------------------------------------------------
# tools / config / serve
# ---------------------------------------------------------------------------


@app.command()
def tools(
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """List registered tools and their risk classifications."""
    _settings()
    registry = build_default_registry()
    if as_json:
        typer.echo(json.dumps(registry.schemas(), indent=2))
        return
    heading(f"{len(registry.enabled())} registered tools")
    render_table(
        ["tool", "risk", "permissions", "description"],
        [
            [
                tool.name,
                str(tool.risk).upper(),
                ",".join(tool.required_permissions),
                tool.description,
            ]
            for tool in registry.enabled()
        ],
    )


@config_app.command("show")
def config_show(
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Print the effective configuration. Secrets are never printed."""
    settings = _settings()
    data = settings.redacted_dict()
    if as_json:
        typer.echo(json.dumps(data, indent=2, default=str))
        return
    heading("Effective configuration")
    for key, value in sorted(data.items()):
        key_value(key, json.dumps(value, default=str) if isinstance(value, list) else str(value))
    typer.echo(
        dim("\n  Secrets are shown as <set>/<unset> and are never written to logs or audit.")
    )


@app.command()
def serve(
    host: Annotated[str | None, typer.Option("--host", help="Override the bind address.")] = None,
    port: Annotated[int | None, typer.Option("--port", help="Override the port.")] = None,
    heartbeat: Annotated[
        bool, typer.Option("--heartbeat/--no-heartbeat", help="Run the heartbeat loop.")
    ] = True,
) -> None:
    """Run the local API and the runtime supervisor."""
    import uvicorn

    settings = load_settings()
    configure_logging(level=settings.log_level, fmt=settings.log_format)

    bind_host = host or settings.api_host
    bind_port = port or settings.api_port

    is_local = bind_host in {"127.0.0.1", "localhost", "::1"}
    if not settings.api_auth_configured:
        typer.echo(
            warn(
                "SCRAPPY_API_TOKEN is not set. The API will start and refuse every "
                "authenticated request; only GET /health will answer.",
                prefix=True,
            )
        )
    if not is_local and not settings.api_auth_configured:
        # Refusing to start would be the stricter choice, but an operator who
        # passed --host explicitly has said what they want, and a daemon that
        # silently declines to boot is its own kind of outage. Say it loudly and
        # let the (useless, because unauthenticated) instance come up.
        typer.echo(
            error(
                f"Binding {bind_host}:{bind_port} with no API token. This instance is "
                "reachable off-host and cannot identify any caller. Run `scrappy doctor`."
            )
        )
    elif not is_local:
        typer.echo(
            warn(
                f"Binding {bind_host}:{bind_port}. Bearer tokens are replayable if "
                "intercepted - terminate TLS in front of this.",
                prefix=True,
            )
        )

    from scrappy_os.interface.api import create_app

    application = create_app(settings, with_heartbeat=heartbeat)
    uvicorn.run(application, host=bind_host, port=bind_port, log_level=settings.log_level.lower())


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
