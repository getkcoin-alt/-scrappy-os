"""Installed CLI entrypoint with the SYNCBOND-aware API factory.

The existing CLI remains unchanged. Before delegating to it, this entrypoint
replaces only ``scrappy_os.interface.api.create_app`` with the additive
continuity wrapper. The serve command imports that factory lazily, so installed
``scrappy serve`` gets correlation validation/propagation while every execution,
authentication, policy and approval implementation remains the original one.
"""

from __future__ import annotations

from typing import Any


def main() -> Any:
    from scrappy_os.interface import api
    from scrappy_os.interface.syncbond_http import create_app

    api.create_app = create_app

    from scrappy_os.interface.cli import main as cli_main

    return cli_main()


__all__ = ["main"]
