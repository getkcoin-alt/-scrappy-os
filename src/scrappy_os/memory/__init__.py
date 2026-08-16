"""Memory - Scrappy OS's stomach.

Three layers with different lifetimes: working (task-scoped, in process),
episodic (durable history), semantic (distilled knowledge, interface only in
v0.1).
"""

from __future__ import annotations

from scrappy_os.memory.base import EpisodicMemory, SemanticMemory
from scrappy_os.memory.episodic import SQLiteEpisodicMemory
from scrappy_os.memory.semantic import NullSemanticMemory
from scrappy_os.memory.store import Store, StoreError, open_store
from scrappy_os.memory.working import WorkingMemory

__all__ = [
    "EpisodicMemory",
    "NullSemanticMemory",
    "SQLiteEpisodicMemory",
    "SemanticMemory",
    "Store",
    "StoreError",
    "WorkingMemory",
    "open_store",
]
