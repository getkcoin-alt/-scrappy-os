"""Vault Zeta - loading a portable assistant identity into Scrappy OS.

A vault is produced elsewhere and consumed here. It carries who the assistant is
(persona, operator, mission, invariants) and what it has learned, in a format
specified by ``docs/VAULT_PROTOCOL.md`` rather than by either implementation.

Nothing in this package writes a vault. Reading one is a deliberate act at
startup; persisting new knowledge is a separate, reviewed export on the host
that owns the store.
"""

from scrappy_os.vault.bundle import (
    SUPPORTED_MAJOR,
    Directive,
    Identity,
    IncompatibleVault,
    MalformedVault,
    Manifest,
    MemoryRecord,
    VaultBundle,
    check_compatible,
)
from scrappy_os.vault.semantic import VaultSemanticMemory

__all__ = [
    "SUPPORTED_MAJOR",
    "Directive",
    "Identity",
    "IncompatibleVault",
    "MalformedVault",
    "Manifest",
    "MemoryRecord",
    "VaultBundle",
    "VaultSemanticMemory",
    "check_compatible",
]
