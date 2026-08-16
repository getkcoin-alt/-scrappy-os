"""The immune system: paths, risk, policy, approvals and audit.

Nothing in Scrappy OS reaches the machine without passing through this package.
"""

from __future__ import annotations

from scrappy_os.security.approvals import (
    CONFIRMATION_PHRASE,
    ApprovalManager,
    describe_operation,
    render_prompt,
)
from scrappy_os.security.audit import AuditLog
from scrappy_os.security.paths import validate_read_path, validate_write_path
from scrappy_os.security.policy import PolicyContext, PolicyEngine, PolicyVerdict
from scrappy_os.security.risk import classify_command, classify_command_string

__all__ = [
    "CONFIRMATION_PHRASE",
    "ApprovalManager",
    "AuditLog",
    "PolicyContext",
    "PolicyEngine",
    "PolicyVerdict",
    "classify_command",
    "classify_command_string",
    "describe_operation",
    "render_prompt",
    "validate_read_path",
    "validate_write_path",
]
