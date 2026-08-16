"""Authorization: does this actor hold the capability this operation needs.

One function decides, and every caller routes through it. That is the whole
design. The alternative - each endpoint comparing strings - is how a system ends
up with seven subtly different notions of "admin", one of which is wrong.

The rules, in order:

1. The required capability is not a known :class:`~scrappy_os.core.identity.Scope`  -> DENY
2. The actor is unauthenticated                                                         -> DENY
3. The actor does not hold the scope                                                    -> DENY
4. The actor holds the scope                                                            -> ALLOW

Rule 1 is the load-bearing one. Asking for a capability that does not exist is a
bug, and the safe answer to a bug in a security check is no. A typo in a scope
name must never be indistinguishable from a granted permission.

This layer intentionally knows nothing about HTTP. It answers a question about
an actor and a capability; :mod:`scrappy_os.interface.security` translates the
answer into a status code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from scrappy_os.core.errors import ScrappyError
from scrappy_os.core.identity import Actor, AuthMethod, Scope


class AuthorizationDenied(ScrappyError):
    """An identified actor lacked the capability an operation required.

    Distinct from an authentication failure: the caller is known, and telling
    them so is not a leak. What they may not learn is anything about the
    resource they were refused.
    """

    def __init__(self, message: str, *, actor_id: str, scope: str) -> None:
        super().__init__(message, actor_id=actor_id, scope=scope)
        self.actor_id = actor_id
        self.scope = scope


@dataclass(frozen=True, slots=True)
class AuthorizationVerdict:
    """The answer about one actor and one capability."""

    allowed: bool
    actor_id: str
    scope: str
    reason: str
    rule: str

    def to_dict(self) -> dict[str, Any]:
        """Audit-safe rendering. Contains no credential and no request body."""
        return {
            "allowed": self.allowed,
            "actor_id": self.actor_id,
            "scope": self.scope,
            "reason": self.reason,
            "rule": self.rule,
        }


def is_known_scope(scope: object) -> bool:
    """Whether ``scope`` names a capability this build understands."""
    if isinstance(scope, Scope):
        return True
    if isinstance(scope, str):
        return scope in {member.value for member in Scope}
    return False


def parse_scopes(raw: str) -> frozenset[Scope]:
    """Parse a comma-separated scope list from configuration.

    Unknown names raise rather than being dropped. A deployment that asks for
    ``task:crate`` has a typo, and silently granting the four scopes that *did*
    parse would hand out a credential nobody reviewed.
    """
    parsed: set[Scope] = set()
    unknown: list[str] = []
    for chunk in raw.split(","):
        item = chunk.strip()
        if not item:
            continue
        if not is_known_scope(item):
            unknown.append(item)
            continue
        parsed.add(Scope(item))
    if unknown:
        known = ", ".join(sorted(member.value for member in Scope))
        raise AuthorizationDenied(
            f"unknown scope(s): {', '.join(sorted(unknown))}; known scopes are {known}",
            actor_id="<configuration>",
            scope=",".join(sorted(unknown)),
        )
    return frozenset(parsed)


class Authorizer:
    """Decides whether an actor may perform a scoped operation.

    Stateless and cheap to construct. It is a class rather than a bare function
    so that a future deployment can substitute a policy-backed implementation
    (roles, per-resource rules, delegation chains) without every call site
    changing shape.
    """

    def evaluate(self, actor: Actor, scope: object) -> AuthorizationVerdict:
        """Decide, and explain. Never raises."""
        rendered = str(scope)

        if not is_known_scope(scope):
            return AuthorizationVerdict(
                allowed=False,
                actor_id=actor.id,
                scope=rendered,
                reason=(
                    f"{rendered!r} is not a capability this build defines; "
                    "unknown permissions are denied"
                ),
                rule="unknown-scope",
            )

        required = scope if isinstance(scope, Scope) else Scope(str(scope))

        if actor.auth_method is AuthMethod.NONE:
            return AuthorizationVerdict(
                allowed=False,
                actor_id=actor.id,
                scope=rendered,
                reason="the request carried no verified identity",
                rule="unauthenticated",
            )

        if not actor.has_scope(required):
            return AuthorizationVerdict(
                allowed=False,
                actor_id=actor.id,
                scope=rendered,
                reason=f"actor does not hold {rendered}",
                rule="missing-scope",
            )

        return AuthorizationVerdict(
            allowed=True,
            actor_id=actor.id,
            scope=rendered,
            reason=f"actor holds {rendered}",
            rule="scope-granted",
        )

    def authorize(self, actor: Actor, scope: object) -> AuthorizationVerdict:
        """Decide, or raise :class:`AuthorizationDenied`."""
        verdict = self.evaluate(actor, scope)
        if not verdict.allowed:
            raise AuthorizationDenied(
                verdict.reason, actor_id=verdict.actor_id, scope=verdict.scope
            )
        return verdict


#: The process-wide authorizer. Stateless, so sharing one is safe.
AUTHORIZER = Authorizer()


__all__ = [
    "AUTHORIZER",
    "AuthorizationDenied",
    "AuthorizationVerdict",
    "Authorizer",
    "is_known_scope",
    "parse_scopes",
]
