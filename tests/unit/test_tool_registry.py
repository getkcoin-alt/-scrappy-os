"""The tool registry and the Tool contract."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel

from scrappy_os.core.enums import RiskLevel
from scrappy_os.core.errors import ToolNotFound, ValidationFailed
from scrappy_os.tools import build_default_registry
from scrappy_os.tools.base import EmptyArgs, Tool, ToolContext, ToolRegistry


class _EchoArgs(BaseModel):
    model_config = {"extra": "forbid"}

    message: str


class _EchoTool(Tool):
    name = "test.echo"
    description = "Echo a message back."
    input_model = _EchoArgs
    risk = RiskLevel.READ

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, _EchoArgs)
        return {"message": args.message}


def test_unknown_tool_raises_with_the_known_set() -> None:
    """The error names what *is* available, so a caller can correct itself."""
    registry = ToolRegistry()
    registry.register(_EchoTool())
    with pytest.raises(ToolNotFound) as excinfo:
        registry.get("test.nope")
    assert excinfo.value.context["known"] == ["test.echo"]


def test_duplicate_registration_is_refused() -> None:
    registry = ToolRegistry()
    registry.register(_EchoTool())
    with pytest.raises(ValueError, match="already registered"):
        registry.register(_EchoTool())
    registry.register(_EchoTool(), replace=True)


def test_a_tool_without_a_name_is_refused() -> None:
    class Nameless(Tool):
        input_model = EmptyArgs

        async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
            return {}

    with pytest.raises(ValueError, match="must declare a name"):
        ToolRegistry().register(Nameless())


def test_disabled_tools_stay_resolvable_for_audit() -> None:
    """Disabling must not erase the name; audit rows still have to resolve it."""
    registry = ToolRegistry()
    registry.register(_EchoTool())
    registry.disable("test.echo")

    assert "test.echo" in registry.names
    assert registry.get("test.echo") is not None
    assert registry.enabled() == []

    registry.enable("test.echo")
    assert len(registry.enabled()) == 1


def test_argument_validation_rejects_extra_fields() -> None:
    """A model inventing `sudo=True` fails here, not three layers down."""
    tool = _EchoTool()
    with pytest.raises(ValidationFailed, match="Invalid arguments"):
        tool.parse_arguments({"message": "hi", "sudo": True})


def test_argument_validation_rejects_missing_fields() -> None:
    with pytest.raises(ValidationFailed):
        _EchoTool().parse_arguments({})


def test_catalogue_hides_tools_that_could_never_run_at_the_ceiling() -> None:
    """A READ-ceiling agent is not shown a tool whose floor is above READ."""
    registry = build_default_registry()
    read_only = registry.catalogue(ceiling=RiskLevel.READ)

    assert "system.disk" in read_only
    assert "fs.write" not in read_only, "fs.write cannot be less than WRITE"
    assert "fs.delete" not in read_only
    assert "process.kill" not in read_only

    # shell.run *can* be READ (`ls -la /etc`), so hiding it would deny a
    # read-only task a capability it is entitled to use.
    assert "shell.run" in read_only


def test_catalogue_shows_a_tool_whose_floor_is_within_the_ceiling() -> None:
    """fs.delete reaches DESTRUCTIVE, but is a WRITE inside the workspace."""
    registry = build_default_registry()
    write_level = registry.catalogue(ceiling=RiskLevel.WRITE)
    assert "fs.delete" in write_level
    assert "fs.write" in write_level
    assert "process.kill" not in write_level, "process.kill is PRIVILEGED at best"


def test_catalogue_renders_the_risk_band_for_variable_tools() -> None:
    """A planner should see that a tool's risk depends on its arguments."""
    catalogue = build_default_registry().catalogue(ceiling=RiskLevel.DESTRUCTIVE)
    assert "[read..destructive]" in catalogue  # shell.run
    assert "[write..destructive]" in catalogue  # fs.delete
    assert "[read]" in catalogue  # system.disk, fixed


def test_by_max_risk_filters_on_the_floor_not_the_ceiling() -> None:
    registry = build_default_registry()
    for tool in registry.by_max_risk(RiskLevel.READ):
        assert tool.risk_floor is RiskLevel.READ


def test_default_registry_registers_every_tool_family() -> None:
    names = build_default_registry().names
    for expected in (
        "system.disk",
        "system.memory",
        "system.info",
        "fs.read",
        "fs.write",
        "fs.delete",
        "process.list",
        "process.kill",
        "git.status",
        "shell.run",
        "http.get",
    ):
        assert expected in names


def test_shell_and_http_can_be_left_unregistered() -> None:
    """Not registering a tool is a stronger control than a policy rule."""
    registry = build_default_registry(include_shell=False, include_http=False)
    assert "shell.run" not in registry.names
    assert "http.get" not in registry.names
    assert "system.disk" in registry.names


def test_json_schemas_are_generated_for_planning() -> None:
    schemas = {schema["name"]: schema for schema in build_default_registry().schemas()}
    disk = schemas["system.disk"]
    assert disk["risk"] == "read"
    assert "properties" in disk["parameters"]


@pytest.mark.parametrize(
    ("tool_name", "expected"),
    [
        ("system.disk", RiskLevel.READ),
        ("fs.read", RiskLevel.READ),
        ("git.status", RiskLevel.READ),
        ("fs.write", RiskLevel.PRIVILEGED),
        ("fs.mkdir", RiskLevel.PRIVILEGED),
        ("fs.move", RiskLevel.DESTRUCTIVE),
        ("process.kill", RiskLevel.DESTRUCTIVE),
        ("fs.delete", RiskLevel.DESTRUCTIVE),
        ("shell.run", RiskLevel.DESTRUCTIVE),
    ],
)
def test_static_risk_ceilings_are_declared_as_documented(
    tool_name: str, expected: RiskLevel
) -> None:
    assert build_default_registry().get(tool_name).risk is expected


@pytest.mark.parametrize(
    ("tool_name", "expected"),
    [
        ("system.disk", RiskLevel.READ),
        ("shell.run", RiskLevel.READ),
        ("fs.write", RiskLevel.WRITE),
        ("fs.delete", RiskLevel.WRITE),
        ("process.kill", RiskLevel.PRIVILEGED),
    ],
)
def test_risk_floors_are_declared_as_documented(
    tool_name: str, expected: RiskLevel
) -> None:
    assert build_default_registry().get(tool_name).risk_floor is expected


def test_no_tool_declares_a_floor_above_its_ceiling() -> None:
    """A floor above the ceiling would make the tool unreachable and the audit lie."""
    for tool in build_default_registry().all():
        assert tool.risk_floor.rank <= tool.risk.rank, tool.name


def test_every_tool_declares_a_description_and_permissions() -> None:
    """A tool with no description is a tool an agent cannot use correctly."""
    for tool in build_default_registry().all():
        assert tool.description, f"{tool.name} has no description"
        assert tool.required_permissions, f"{tool.name} declares no permissions"


def test_mutating_tools_declare_rollback_metadata() -> None:
    """Mahesh needs to know what can be undone - including honest 'nothing'."""
    registry = build_default_registry()
    for name in ("fs.write", "fs.delete", "fs.move", "shell.run", "process.kill"):
        tool = registry.get(name)
        assert tool.rollback is not None, f"{name} does not say whether it can be undone"
        assert tool.rollback.description
