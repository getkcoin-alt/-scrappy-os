"""Shared fixtures.

Every fixture is hermetic: settings point at a tmp_path, the store is a fresh
file per test, and no test may touch the real data directory or reach the
network. Tests that need a "system" use read-only tools against the real host,
which is safe by construction - none of them can change anything.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
import pytest_asyncio

from scrappy_os.core.config import ScrappySettings, reset_settings_cache
from scrappy_os.core.events import InProcessEventBus
from scrappy_os.core.models import Objective, ToolCall
from scrappy_os.memory.store import Store
from scrappy_os.models.mock import MockProvider
from scrappy_os.models.registry import ModelRouter
from scrappy_os.security.approvals import ApprovalManager
from scrappy_os.security.audit import AuditLog
from scrappy_os.security.policy import PolicyEngine
from scrappy_os.tools import build_default_registry
from scrappy_os.tools.base import ToolContext, ToolRegistry
from scrappy_os.tools.executor import ToolExecutor


@pytest.fixture(autouse=True)
def _isolate_settings_cache() -> Iterator[None]:
    """No test may inherit another's cached settings singleton."""
    reset_settings_cache()
    yield
    reset_settings_cache()


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    path = tmp_path / "workspace"
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture
def settings(tmp_path: Path, workspace: Path) -> ScrappySettings:
    """Hermetic settings: everything under tmp_path, provider offline."""
    return ScrappySettings(
        model_provider="mock",
        data_dir=tmp_path / "data",
        workspace=workspace,
        allowed_read_roots_raw=f"{tmp_path},/etc,/proc",
        max_plan_steps=6,
        max_replans=1,
        max_task_seconds=30.0,
        max_model_calls=12,
        approval_ttl_minutes=5,
        log_level="ERROR",
    )


@pytest.fixture
def registry() -> ToolRegistry:
    return build_default_registry()


@pytest.fixture
def bus() -> InProcessEventBus:
    return InProcessEventBus()


@pytest_asyncio.fixture
async def store(settings: ScrappySettings) -> AsyncIterator[Store]:
    settings.ensure_directories()
    instance = Store(settings.db_path)
    await instance.connect()
    try:
        yield instance
    finally:
        await instance.close()


@pytest.fixture
def audit(store: Store, bus: InProcessEventBus) -> AuditLog:
    """An audit log attached to the bus, mirroring how Runtime wires it.

    Attaching here rather than in individual tests means the tests exercise the
    same event->audit path production uses; a test that passed against an
    unattached log would prove nothing about the real system.
    """
    log = AuditLog(store)
    log.attach(bus)
    return log


@pytest.fixture
def approvals(settings: ScrappySettings, store: Store, bus: InProcessEventBus) -> ApprovalManager:
    return ApprovalManager(settings, store, bus)


@pytest.fixture
def policy(settings: ScrappySettings) -> PolicyEngine:
    return PolicyEngine(settings)


@pytest.fixture
def executor(
    settings: ScrappySettings,
    registry: ToolRegistry,
    policy: PolicyEngine,
    approvals: ApprovalManager,
    audit: AuditLog,
    bus: InProcessEventBus,
) -> ToolExecutor:
    return ToolExecutor(
        settings=settings,
        registry=registry,
        policy=policy,
        approvals=approvals,
        audit=audit,
        bus=bus,
    )


@pytest.fixture
def tool_context(settings: ScrappySettings) -> ToolContext:
    return ToolContext(settings=settings, task_id="test-task", actor="test")


@pytest.fixture
def provider() -> MockProvider:
    return MockProvider()


@pytest.fixture
def router(settings: ScrappySettings, provider: MockProvider) -> ModelRouter:
    return ModelRouter(settings, provider=provider)


@pytest.fixture
def objective() -> Objective:
    return Objective(text="Inspect disk usage", actor="test")


def make_call(tool_name: str, **arguments: object) -> ToolCall:
    """A tool call for a fixed task id, so assertions can find it in audit."""
    return ToolCall(task_id="test-task", tool_name=tool_name, arguments=dict(arguments))
