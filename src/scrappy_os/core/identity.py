"""Who is asking.

v0.1 had a single string, ``actor``, filled in by whoever happened to be
constructing the object - including, over the API, the client itself. That is
fine as a label and useless as an identity: a caller that can name itself can
name itself anything.

This module introduces the typed alternative. An :class:`Actor` is produced by
the authentication layer and by nothing else. It travels with the request that
created it, through the task, into policy evaluation, tool calls and the audit
log, so "who asked for this" has exactly one answer at every hop.

The distinction that matters downstream:

* :attr:`Actor.id` is the *principal* - the human, service or node whose
  credential was verified. Only authentication sets it.
* ``ToolCall.actor`` remains the *proximate* requester, which is usually an
  agent (``agent:brahma``). An agent is not a principal and never becomes one;
  it acts under the identity that started the task.

Both are recorded. A tool call is interesting because an agent asked for it,
and accountable because a person did.

This module lives in ``core`` rather than ``security`` because
:class:`~scrappy_os.core.models.Objective` and
:class:`~scrappy_os.core.models.ToolCall` embed an :class:`Actor` directly.
Identity is vocabulary; :mod:`scrappy_os.security.authn` and
:mod:`scrappy_os.security.authz` are the mechanisms that establish and consult
it, and they depend on this module rather than the other way round.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ActorType(StrEnum):
    """What kind of thing holds an identity.

    The type is descriptive, never decisive: authorization reads
    :attr:`Actor.scopes`, so adding a type here cannot silently widen access.
    """

    HUMAN = "human"
    """A person, authenticated at a terminal or through the API."""

    SERVICE = "service"
    """A non-interactive client: CI, a script, another daemon."""

    NODE = "node"
    """Another Scrappy OS instance. Reserved; no node may authenticate in v0.2."""

    SYSTEM = "system"
    """Scrappy OS acting on its own behalf - heartbeats, startup, internal work."""


class AuthMethod(StrEnum):
    """How an identity was established.

    Recorded on every audit row so an operator can tell a token-bearing API
    caller from someone with shell access to the host, which are very different
    kinds of trust even when they carry the same scopes.
    """

    NONE = "none"
    """Unauthenticated. Carries no scopes and can reach nothing privileged."""

    BEARER_TOKEN = "bearer_token"  # noqa: S105 - a method name, not a credential
    """A shared secret presented in an Authorization header."""

    LOCAL_PROCESS = "local_process"
    """Invoked in-process by someone who already had the host's file permissions."""

    INTERNAL = "internal"
    """The runtime itself. Never reachable from outside the process."""


class Scope(StrEnum):
    """A capability that may be granted to an actor.

    Scopes are the *only* vocabulary of authorization. Endpoints declare the
    scope they need; nothing compares actor ids, names or types to decide
    access. Adding a capability means adding a member here and declaring it at
    the one place that guards it.
    """

    TASK_CREATE = "task:create"
    """Submit an objective for autonomous execution."""

    TASK_READ = "task:read"
    """Read task state, results and event streams."""

    APPROVAL_READ = "approval:read"
    """List operations waiting at the approval gate."""

    APPROVAL_GRANT = "approval:grant"
    """Approve or deny a held operation. The most dangerous scope in the set."""

    AUDIT_READ = "audit:read"
    """Read the audit trail, including what other actors did."""

    SYSTEM_READ = "system:read"
    """Read runtime state, component health and configuration summaries."""


#: Every scope, for identities that are already unconstrained by construction
#: (the local CLI, the runtime itself). Written as a function rather than a
#: module constant so a caller cannot mutate the shared set.
def all_scopes() -> frozenset[Scope]:
    """The full scope set. Grant deliberately; this is not a default."""
    return frozenset(Scope)


#: Scopes that only observe. A credential limited to these cannot start work,
#: approve anything, or change the machine.
def read_only_scopes() -> frozenset[Scope]:
    """The observation-only subset: task, audit and system reads."""
    return frozenset({Scope.TASK_READ, Scope.AUDIT_READ, Scope.SYSTEM_READ, Scope.APPROVAL_READ})


class Actor(BaseModel):
    """An authenticated principal.

    Frozen on purpose. An actor is a statement about a completed authentication,
    and a component that could edit one could privilege-escalate by assignment.
    Deriving a narrower actor is done with :meth:`with_scopes`, which can only
    remove.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)

    id: str = Field(min_length=1, max_length=128, description="Stable principal identifier.")
    actor_type: ActorType
    display_name: str | None = Field(default=None, max_length=128)
    scopes: frozenset[Scope] = Field(default_factory=frozenset)
    auth_method: AuthMethod = AuthMethod.NONE
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Non-sensitive provenance only. Never a credential, never a header.",
    )

    @model_validator(mode="after")
    def _unauthenticated_actors_hold_no_scopes(self) -> Self:
        """An identity nobody proved cannot carry capabilities.

        Without this, a caller that constructs ``Actor(auth_method=NONE,
        scopes={...})`` anywhere in the codebase would produce something that
        authorizes. Making it unrepresentable is cheaper than auditing for it.
        """
        if self.auth_method is AuthMethod.NONE and self.scopes:
            raise ValueError("an actor with auth_method=none cannot hold scopes")
        return self

    def has_scope(self, scope: Scope) -> bool:
        """Whether this actor holds ``scope``. The only authorization question."""
        return scope in self.scopes

    def with_scopes(self, scopes: frozenset[Scope]) -> Actor:
        """A copy narrowed to ``scopes``.

        Intersects rather than replaces: delegation may only ever attenuate, so
        a caller cannot hand out more than it holds. This is the seam that
        short-lived capability tokens will use.
        """
        return self.model_copy(update={"scopes": self.scopes & scopes})

    @property
    def label(self) -> str:
        """Compact ``type:id`` rendering for the legacy string ``actor`` fields."""
        return f"{self.actor_type}:{self.id}"

    def audit_fields(self) -> dict[str, Any]:
        """The identity columns to attach to an event or audit row.

        Deliberately excludes :attr:`metadata`: it is the one field an
        authenticator may populate from its own configuration, and audit records
        should carry identity, not commentary.
        """
        return {
            "actor_id": self.id,
            "actor_type": str(self.actor_type),
            "auth_method": str(self.auth_method),
            "actor_scopes": sorted(str(scope) for scope in self.scopes),
        }


# ---------------------------------------------------------------------------
# Well-known identities
# ---------------------------------------------------------------------------

#: The runtime acting on its own behalf: startup, shutdown, heartbeats. Holds no
#: scopes because nothing internal consults them - it is a label for the audit
#: trail, not a key.
SYSTEM_ACTOR: Actor = Actor(
    id="scrappy",
    actor_type=ActorType.SYSTEM,
    display_name="Scrappy OS runtime",
    auth_method=AuthMethod.INTERNAL,
)

#: The absence of an identity. Every unauthenticated request carries this, and
#: because it holds no scopes it cannot pass a single scope check.
ANONYMOUS_ACTOR: Actor = Actor(
    id="anonymous",
    actor_type=ActorType.SERVICE,
    display_name="unauthenticated",
    auth_method=AuthMethod.NONE,
)


def local_cli_actor(*, username: str | None = None) -> Actor:
    """The identity used by ``scrappy`` commands run on the host.

    The CLI holds every scope, and that is not a shortcut. It runs in-process
    with the invoking user's file permissions: that user can already read the
    SQLite audit trail, edit ``.env`` and restart the service. Making the CLI
    authenticate to itself would check a credential the holder could simply
    read off disk - a boundary that looks like security and enforces nothing.
    See ``docs/SECURITY.md``.
    """
    import getpass

    resolved = username
    if resolved is None:
        try:
            resolved = getpass.getuser()
        except (OSError, KeyError):  # pragma: no cover - no passwd entry
            resolved = "unknown"
    return Actor(
        id=resolved,
        actor_type=ActorType.HUMAN,
        display_name=f"local user {resolved}",
        scopes=all_scopes(),
        auth_method=AuthMethod.LOCAL_PROCESS,
    )


def agent_actor(role: str, *, on_behalf_of: Actor | None = None) -> Actor:
    """The identity of a reasoning agent proposing an action.

    An agent is never a principal: it holds no scopes, and the principal that
    started the task is recorded in ``on_behalf_of`` so the audit trail keeps
    the chain intact. A model that decides to run ``systemctl restart`` did so
    inside somebody's task, and that somebody is who answers for it.
    """
    return Actor(
        id=f"agent:{role}",
        actor_type=ActorType.SYSTEM,
        display_name=f"{role} agent",
        auth_method=AuthMethod.INTERNAL,
        metadata={"on_behalf_of": on_behalf_of.id} if on_behalf_of else {},
    )


__all__ = [
    "ANONYMOUS_ACTOR",
    "SYSTEM_ACTOR",
    "Actor",
    "ActorType",
    "AuthMethod",
    "Scope",
    "agent_actor",
    "all_scopes",
    "local_cli_actor",
    "read_only_scopes",
]
