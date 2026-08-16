"""structlog configuration.

Every log line is a structured event with a stable name (``tool_completed``,
not ``"Tool %s finished in %sms"``) plus context. Task correlation is handled
by contextvars, so a log emitted deep inside a tool still carries the task id
without threading it through every signature.

A redaction processor sits in the chain, which means the logging path cannot
leak a credential even if a caller passes one in by mistake.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import structlog
from structlog.contextvars import bind_contextvars, clear_contextvars, unbind_contextvars

from scrappy_os.observability.redaction import redact

_configured = False


def _redaction_processor(_logger: Any, _method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """Scrub secrets from every log event before it is rendered."""
    result = redact(event_dict)
    assert isinstance(result, dict)
    return result


def configure_logging(
    *, level: str = "INFO", fmt: str = "console", stream: Any | None = None
) -> None:
    """Install the processor chain. Idempotent per process configuration.

    ``fmt="json"`` is what systemd and log shippers want; ``console`` is for
    humans at a terminal.
    """
    global _configured

    logging.basicConfig(
        format="%(message)s",
        stream=stream or sys.stderr,
        level=getattr(logging, level.upper(), logging.INFO),
        force=True,
    )

    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        _redaction_processor,
    ]

    renderer: Any
    if fmt == "json":
        shared.append(structlog.processors.format_exc_info)
        renderer = structlog.processors.JSONRenderer(sort_keys=True)
    else:
        shared.append(structlog.processors.ExceptionPrettyPrinter())
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())

    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(file=stream or sys.stderr),
        cache_logger_on_first_use=False,
    )
    _configured = True


def get_logger(component: str) -> structlog.stdlib.BoundLogger:
    """A logger bound to a component name.

    Returns structlog's *lazy* proxy rather than calling ``.bind()`` here.
    ``.bind()`` materialises a bound logger immediately, freezing the level in
    place - and module-level loggers are created at import time, before the CLI
    has chosen a level for the command being run. Staying lazy means
    :func:`configure_logging` takes effect no matter when it is called.
    """
    if not _configured:
        configure_logging()
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(component, component=component)
    return logger


@contextmanager
def bind_task(task_id: str, **extra: Any) -> Iterator[None]:
    """Attach a task id (and anything else) to all logs inside the block."""
    bind_contextvars(task_id=task_id, **extra)
    try:
        yield
    finally:
        unbind_contextvars("task_id", *extra.keys())


def reset_context() -> None:
    """Clear all bound context. Used between tasks in long-lived processes."""
    clear_contextvars()


__all__ = ["bind_task", "configure_logging", "get_logger", "reset_context"]
