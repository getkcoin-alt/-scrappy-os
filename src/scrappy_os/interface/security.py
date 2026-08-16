"""The HTTP authentication and authorization boundary.

This is the only place in Scrappy OS that converts a credential into an
identity, and the only place that turns an authorization answer into a status
code. Endpoints declare what they need and receive a
:class:`RequestSecurityContext`; they never read the ``Authorization`` header,
never compare a scope string, and cannot forget to.

Status codes, and why:

* **401** - we do not know who you are. Missing header, wrong scheme, unknown
  token, or a deployment with no credentials configured. All four are the same
  answer to the client, because distinguishing them tells an attacker which of
  their guesses was closer.
* **403** - we know who you are and you may not do this. Safe to be specific:
  the caller already authenticated, and naming the missing scope is how a
  legitimate integration gets fixed.

Both are audited. Neither ever carries the presented credential: the header is
consumed here and does not travel further into the process.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from fastapi import HTTPException, Request

from scrappy_os.core.enums import EventType
from scrappy_os.core.identity import ANONYMOUS_ACTOR, Actor, Scope
from scrappy_os.core.models import AuditEvent, new_id
from scrappy_os.observability.logging import get_logger
from scrappy_os.security.audit import AuditLog
from scrappy_os.security.authn import (
    AuthenticationFailed,
    Authenticator,
)
from scrappy_os.security.authz import AUTHORIZER, AuthorizationVerdict

logger = get_logger("api.security")

#: Sent with every 401 so a compliant client knows what to present next.
WWW_AUTHENTICATE = 'Bearer realm="scrappy-os"'


@dataclass(frozen=True, slots=True)
class RequestSecurityContext:
    """The trusted facts about one authenticated request.

    Constructed by the dependency below from a verified credential, attached to
    ``request.state``, and passed explicitly from there. There is no module-level
    "current actor" - a global would be wrong under concurrency and worse under
    an ``asyncio`` task that outlives its request, which is exactly what
    ``POST /tasks`` creates.
    """

    actor: Actor
    request_id: str = field(default_factory=new_id)
    granted_scope: str | None = None

    def audit_fields(self) -> dict[str, Any]:
        """Identity columns for an event emitted on behalf of this request."""
        fields = self.actor.audit_fields()
        fields["request_id"] = self.request_id
        if self.granted_scope:
            fields["granted_scope"] = self.granted_scope
        return fields


def _authenticator(request: Request) -> Authenticator:
    authenticator: Authenticator | None = getattr(request.app.state, "authenticator", None)
    if authenticator is None:  # pragma: no cover - create_app always sets one
        raise HTTPException(status_code=503, detail="authentication is not configured")
    return authenticator


def _audit_log(request: Request) -> AuditLog | None:
    """The audit log, when the runtime is up.

    A rejected request during startup or shutdown still gets the right status
    code; it just cannot be recorded, and a missing audit row is preferable to a
    500 that hides an authentication failure.
    """
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None:
        return None
    audit: AuditLog | None = getattr(runtime, "audit", None)
    return audit


async def _record(
    request: Request,
    event_type: EventType,
    *,
    actor: Actor,
    payload: dict[str, Any],
) -> None:
    """Write one security event, best effort.

    Auditing must never convert a clean 401 into a 500, so a failure to record
    is logged and swallowed. The status code is the security control; the audit
    row is the evidence, and losing evidence is not a reason to lose the control.
    """
    audit = _audit_log(request)
    if audit is None:
        return
    try:
        await audit.record(
            AuditEvent(
                event_type=event_type,
                component="api.security",
                actor=actor.label,
                # Promoted to their own columns, not left in the payload: these
                # are what an operator filters and joins on when answering "what
                # did this principal do", and a JSON blob is not queryable.
                actor_id=actor.id,
                actor_type=str(actor.actor_type),
                auth_method=str(actor.auth_method),
                success=event_type is EventType.AUTH_SUCCEEDED,
                payload=payload,
            )
        )
    except Exception:  # noqa: BLE001 - evidence is best-effort; the refusal is not
        logger.warning("security_audit_write_failed", event_type=str(event_type))


def _request_facts(request: Request) -> dict[str, Any]:
    """Non-sensitive request provenance for an audit payload.

    Method, path and peer address only. Explicitly *not* headers: the
    ``Authorization`` header is the one thing that must never reach a durable
    record, and the safe way to guarantee that is to never build a structure
    that contains it.
    """
    client = request.client
    return {
        "method": request.method,
        "path": request.url.path,
        "peer": client.host if client else None,
    }


async def authenticate_request(request: Request) -> RequestSecurityContext:
    """Resolve the caller's identity, or refuse with 401.

    Cached on ``request.state`` so that an endpoint depending on several scoped
    dependencies authenticates once and audits one success, not three.
    """
    cached: RequestSecurityContext | None = getattr(request.state, "security", None)
    if cached is not None:
        return cached

    authenticator = _authenticator(request)
    header = request.headers.get("Authorization")

    try:
        actor = await authenticator.authenticate(header)
    except AuthenticationFailed as exc:
        await _record(
            request,
            EventType.AUTH_FAILED,
            actor=ANONYMOUS_ACTOR,
            payload={"reason": str(exc.reason), **_request_facts(request)},
        )
        logger.warning(
            "authentication_failed",
            reason=str(exc.reason),
            path=request.url.path,
            outcome="denied",
        )
        raise HTTPException(
            status_code=401,
            detail="authentication required",
            headers={"WWW-Authenticate": WWW_AUTHENTICATE},
        ) from exc

    context = RequestSecurityContext(actor=actor)
    request.state.security = context
    await _record(
        request,
        EventType.AUTH_SUCCEEDED,
        actor=actor,
        payload={
            **actor.audit_fields(),
            "request_id": context.request_id,
            **_request_facts(request),
        },
    )
    return context


def require_scope(scope: Scope) -> Callable[[Request], Awaitable[RequestSecurityContext]]:
    """A dependency that authenticates, then demands one capability.

    Used as ``Depends(require_scope(Scope.TASK_CREATE))``. The scope an endpoint
    needs is declared in its signature, which means the requirement is visible
    in the generated OpenAPI document and cannot drift from what is enforced.
    """

    async def dependency(request: Request) -> RequestSecurityContext:
        context = await authenticate_request(request)
        verdict: AuthorizationVerdict = AUTHORIZER.evaluate(context.actor, scope)

        if not verdict.allowed:
            await _record(
                request,
                EventType.AUTHZ_DENIED,
                actor=context.actor,
                payload={
                    **context.audit_fields(),
                    **verdict.to_dict(),
                    **_request_facts(request),
                },
            )
            logger.warning(
                "authorization_denied",
                actor_id=context.actor.id,
                scope=str(scope),
                rule=verdict.rule,
                path=request.url.path,
                outcome="denied",
            )
            raise HTTPException(
                status_code=403,
                detail=f"this action requires the {scope} scope",
            )

        granted = RequestSecurityContext(
            actor=context.actor,
            request_id=context.request_id,
            granted_scope=str(scope),
        )
        return granted

    return dependency


async def optional_identity(request: Request) -> RequestSecurityContext:
    """Identify the caller if they offered a credential; never refuse.

    For endpoints with a deliberately public floor and a richer authenticated
    view - ``GET /health`` is the only one. A bad credential here yields the
    anonymous actor rather than a 401, because a liveness probe must not start
    failing because someone else's token expired.
    """
    if request.headers.get("Authorization") is None:
        return RequestSecurityContext(actor=ANONYMOUS_ACTOR)
    try:
        return await authenticate_request(request)
    except HTTPException:
        return RequestSecurityContext(actor=ANONYMOUS_ACTOR)


__all__ = [
    "WWW_AUTHENTICATE",
    "RequestSecurityContext",
    "authenticate_request",
    "optional_identity",
    "require_scope",
]
