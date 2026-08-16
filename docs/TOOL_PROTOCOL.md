# Tool protocol

How to add a machine capability safely.

A tool is the only way Scrappy OS touches the machine. Adding one is
deliberately a small, reviewable act - and deliberately the *only* way to add
capability. If you find yourself reaching for `shell.run` routinely for
something, that thing wants a tool.

## The contract

```python
class Tool(ABC):
    name: ClassVar[str]                          # dotted, stable
    description: ClassVar[str]                   # one line, for the planner
    input_model: ClassVar[type[BaseModel]]       # typed, extra="forbid"
    risk: ClassVar[RiskLevel]                    # ceiling, not expectation
    required_permissions: ClassVar[tuple[str, ...]]
    rollback: ClassVar[RollbackSpec | None]

    def classify(self, args, ctx) -> tuple[RiskLevel, str]: ...   # optional
    def affected_paths(self, args) -> Sequence[Path]: ...          # optional
    async def run(self, args, ctx) -> dict[str, Any]: ...          # required
```

What a tool does **not** do: policy, approval, audit, timing, retries. The
executor handles all of that, so a tool author cannot forget to.

## A worked example

```python
from typing import Any

from pydantic import BaseModel, Field

from scrappy_os.core.enums import RiskLevel
from scrappy_os.core.errors import ToolError
from scrappy_os.tools.base import Tool, ToolContext


class ServiceStatusArgs(BaseModel):
    """Typed arguments. `extra="forbid"` is not optional."""

    model_config = {"extra": "forbid"}

    unit: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-zA-Z0-9@._-]+$",   # constrain at the schema
        description="systemd unit name, e.g. nginx.service",
    )


class ServiceStatusTool(Tool):
    """Read one systemd unit's state."""

    name = "service.status"
    description = "Active state, sub-state and recent log lines for a systemd unit."
    input_model = ServiceStatusArgs
    risk = RiskLevel.READ
    required_permissions = ("service:read",)

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, ServiceStatusArgs)
        ...
        if failed:
            raise ToolError(f"Cannot read {args.unit}: {reason}", tool_name=self.name)
        return {"unit": args.unit, "active_state": state, "since": since}
```

Register it:

```python
# scrappy_os/tools/__init__.py
registry.register(ServiceStatusTool())
```

A tool that is not registered does not exist: the policy engine denies unknown
names outright rather than searching for something close.

## The eight rules

### 1. Declare the honest ceiling

`risk` is the worst thing the tool can do with **any** arguments, not the
typical case. `fs.delete` is DESTRUCTIVE even though most deletions are
harmless, because one of them will not be.

### 2. Classify arguments when danger depends on them

```python
def classify(self, args: BaseModel, ctx: ToolContext) -> tuple[RiskLevel, str]:
    assert isinstance(args, ServiceControlArgs)
    if args.action in {"status", "show"}:
        return RiskLevel.READ, f"{args.action} only reads state"
    return RiskLevel.PRIVILEGED, f"{args.action} changes the state of {args.unit}"
```

The executor takes the worse of static and dynamic risk. `ctx` is passed in
rather than read from a global, so classification is a pure function of
(arguments, configuration) and stays testable.

### 3. Validate paths through the security helpers

Never open a path a caller gave you. Resolve it first, and use the *resolved*
result:

```python
from scrappy_os.security.paths import validate_read_path, validate_write_path

resolved = validate_read_path(args.path, allowed_roots=ctx.read_roots,
                              workspace=ctx.workspace)
# use `resolved` from here on - never `args.path`
```

Validating one string and opening another is how containment checks get
defeated. Also implement `affected_paths` so the policy engine can do its
workspace containment check.

### 4. Bound everything

Output size, entry counts, timeouts, recursion depth. Any of these can reach a
prompt, and an unbounded one becomes a context-window denial of service.

```python
MAX_ENTRIES = 1000
raw = handle.read(max_bytes + 1)          # read one extra to detect truncation
truncated = len(raw) > max_bytes
return {"content": text, "truncated": truncated}
```

Report truncation in the result. Silent truncation makes a model reason about
data it thinks is complete.

### 5. Raise on failure; never return a success-shaped failure

```python
raise ToolError(f"{resolved} does not exist", tool_name=self.name)
```

The executor distinguishes an error from a result and records which happened. A
dict saying `{"ok": false}` looks like success to everything upstream.

Catch narrow exceptions and re-raise as `ToolError` with context. Never
`except Exception: pass`.

### 6. Do not block the event loop

Any filesystem or CPU work goes to a thread; any subprocess uses asyncio:

```python
return await asyncio.to_thread(self._read, resolved, args.max_bytes)
```

Blocking the loop stalls the heartbeat and every other task.

### 7. Declare rollback honestly

```python
rollback = RollbackSpec(
    supported=False,
    description="A terminated process cannot be resumed; its manager must restart it.",
)
```

Mahesh reads this. "Cannot be undone" is more useful than an optimistic claim
that leads to a recovery plan which does not recover anything. Where undo *is*
possible, preserve the before-state - `fs.write` keeps a `.scrappy-bak` copy.

### 8. Return JSON-serialisable, prompt-friendly output

Include a human-readable summary alongside raw numbers. A model reading
`{"percent_used": 92.3}` has to do arithmetic; one reading
`"fullest_summary": "/opt at 92.3% used (307.6MiB of 340.0MiB)"` does not.

## Tests a new tool needs

Put boundary tests in `tests/security/`, behaviour tests in `tests/unit/`.

```python
async def test_rejects_unknown_arguments(settings):
    """extra=forbid, so an invented option fails at validation."""
    with pytest.raises(ValidationFailed):
        ServiceStatusTool().parse_arguments({"unit": "nginx", "force": True})


async def test_path_cannot_escape_the_workspace(settings):
    ctx = ToolContext(settings=settings, task_id="t", actor="test")
    with pytest.raises(PathNotAllowed):
        await MyTool().run(MyArgs(path="../../../etc/shadow"), ctx)


def test_mutating_arguments_classify_as_privileged(settings):
    ctx = ToolContext(settings=settings, task_id="t", actor="test")
    risk, _ = ServiceControlTool().classify(ServiceControlArgs(action="restart"), ctx)
    assert risk is RiskLevel.PRIVILEGED


async def test_output_is_bounded(settings):
    result = await MyTool().run(MyArgs(...), ctx)
    assert result["truncated"] is True
```

Tests must never perform a destructive operation on the host. Use `tmp_path`,
the `workspace` fixture, and read-only operations against the real system.

## Review checklist

Before merging a tool:

- [ ] `risk` is the honest ceiling, not the typical case
- [ ] `classify` implemented if danger depends on arguments
- [ ] All paths go through `validate_read_path` / `validate_write_path`, and the
      **resolved** path is what gets used
- [ ] `affected_paths` returns everything the tool touches
- [ ] Output, entries, recursion and time are all bounded, and truncation is reported
- [ ] Failures raise `ToolError`; no success-shaped failures; no bare `except`
- [ ] Blocking work is in a thread
- [ ] `rollback` declared, including an honest "not supported"
- [ ] `description` reads well in a planning prompt
- [ ] `required_permissions` declared
- [ ] Boundary tests in `tests/security/`
- [ ] Registered in `build_default_registry`, and disable-able if it is dangerous

## Anti-patterns

| Do not | Because |
|---|---|
| Take a raw command string | That is `shell.run`, which exists and is gated |
| Use `shell=True` | Shell injection; there is no reason to |
| Return `{"error": "..."}` on failure | The executor cannot tell it from success |
| `except Exception: pass` | Errors are reported, never hidden |
| Read `get_settings()` inside a tool | Hidden global state; use `ctx.settings` |
| Skip validation "because the model is careful" | The model is the untrusted input |
| Classify below what the arguments justify | The executor takes the worse value anyway; you have only made the audit dishonest |
| Add a `force` flag that skips checks | The approval gate is the place to make an exception |
