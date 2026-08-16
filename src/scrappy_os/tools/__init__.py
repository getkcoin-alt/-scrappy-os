"""Tools - Scrappy OS's hands.

The default registry is assembled here. A tool that is not in this list does
not exist as far as the policy engine is concerned, which is the point.
"""

from __future__ import annotations

from scrappy_os.tools.base import RollbackSpec, Tool, ToolContext, ToolRegistry
from scrappy_os.tools.executor import ExecutionOutcome, ToolExecutor
from scrappy_os.tools.filesystem import FILESYSTEM_TOOLS
from scrappy_os.tools.git import GIT_TOOLS
from scrappy_os.tools.http import HTTP_TOOLS
from scrappy_os.tools.process import PROCESS_TOOLS
from scrappy_os.tools.shell import SHELL_TOOLS
from scrappy_os.tools.system import SYSTEM_TOOLS


def build_default_registry(
    *, include_shell: bool = True, include_http: bool = True
) -> ToolRegistry:
    """The standard tool set.

    ``include_shell`` and ``include_http`` exist because both are reasonable to
    switch off entirely on a hardened deployment, and a tool that is not
    registered cannot be called at all - a stronger guarantee than a policy rule.
    """
    registry = ToolRegistry()
    for tool in (*SYSTEM_TOOLS, *FILESYSTEM_TOOLS, *PROCESS_TOOLS, *GIT_TOOLS):
        registry.register(tool)
    if include_shell:
        for tool in SHELL_TOOLS:
            registry.register(tool)
    if include_http:
        for tool in HTTP_TOOLS:
            registry.register(tool)
    return registry


__all__ = [
    "ExecutionOutcome",
    "RollbackSpec",
    "Tool",
    "ToolContext",
    "ToolExecutor",
    "ToolRegistry",
    "build_default_registry",
]
