"""Outbound HTTP - controlled, GET only in v0.1.

An agent that can fetch a URL can be pointed at ``169.254.169.254`` and asked
to read cloud instance credentials. That is the single most common way an
LLM-driven system leaks its own infrastructure, so this tool is built around
preventing it rather than around fetching efficiently.

How SSRF is actually blocked:

* Only ``http`` and ``https``. No ``file:``, ``gopher:``, ``ftp:``, no
  userinfo in the authority.
* The hostname is **resolved to IP addresses before connecting**, and every
  resolved address is checked. Blocking by hostname alone is defeated by DNS
  that resolves to a private address (and by rebinding).
* Redirects are followed **manually, one at a time**, with the full check
  re-run on each hop. ``follow_redirects=True`` would let hop two land
  somewhere hop one was not allowed to.
* Responses are read in chunks against a byte budget, so a stream that never
  ends cannot exhaust memory.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field, field_validator

from scrappy_os.core.enums import RiskLevel
from scrappy_os.core.errors import ToolError
from scrappy_os.observability.logging import get_logger
from scrappy_os.tools.base import Tool, ToolContext

logger = get_logger("tool.http")

ALLOWED_SCHEMES = frozenset({"http", "https"})

#: Endpoints that hand out credentials to anything that can reach them.
BLOCKED_HOSTNAMES = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "instance-data.ec2.internal",
    }
)

#: Text content types worth returning to a model. Anything else returns metadata only.
TEXTUAL_PREFIXES = ("text/", "application/json", "application/xml", "application/xhtml")


class HTTPGetArgs(BaseModel):
    model_config = {"extra": "forbid"}

    url: str = Field(min_length=1, max_length=2048)
    headers: dict[str, str] = Field(default_factory=dict, max_length=20)
    timeout_seconds: float | None = Field(default=None, gt=0, le=120)
    max_bytes: int | None = Field(default=None, ge=256, le=32 * 1024 * 1024)

    @field_validator("headers")
    @classmethod
    def _reject_credential_headers(cls, value: dict[str, str]) -> dict[str, str]:
        """Refuse to let a plan attach credentials to an outbound request.

        If Scrappy OS needs to authenticate somewhere, that belongs in a
        purpose-built tool with its own risk classification - not in a generic
        fetch that a prompt-injected plan could aim anywhere.
        """
        forbidden = {"authorization", "cookie", "proxy-authorization"}
        offending = [key for key in value if key.lower() in forbidden]
        if offending:
            raise ValueError(f"headers {offending} are not permitted on generic outbound requests")
        return value


class HTTPGetTool(Tool):
    """Fetch a URL with GET.

    Classified WRITE rather than READ: it reads nothing local, but it *sends*
    data off this machine, and where a request goes is a decision worth
    auditing. Reading a public page and exfiltrating to an attacker-supplied
    URL look identical at the transport layer.
    """

    name = "http.get"
    description = "Fetch a public URL over HTTP GET, with size, redirect and timeout limits."
    input_model = HTTPGetArgs
    risk = RiskLevel.WRITE
    required_permissions = ("net:outbound",)

    def classify(self, args: BaseModel, ctx: ToolContext) -> tuple[RiskLevel, str]:
        assert isinstance(args, HTTPGetArgs)
        parsed = urlparse(args.url)
        return RiskLevel.WRITE, f"outbound request to {parsed.hostname or '?'}"

    async def run(self, args: BaseModel, ctx: ToolContext) -> dict[str, Any]:
        assert isinstance(args, HTTPGetArgs)
        settings = ctx.settings
        if not settings.http_enabled:
            raise ToolError("Outbound HTTP is disabled by configuration", tool_name=self.name)

        timeout = args.timeout_seconds or settings.http_timeout_seconds
        max_bytes = args.max_bytes or settings.http_max_bytes
        allow_private = settings.http_allow_private_networks

        url = args.url
        hops: list[str] = []
        started = time.perf_counter()

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            for hop in range(settings.http_max_redirects + 1):
                self._validate_url(url, allow_private=allow_private)
                hops.append(url)
                try:
                    async with client.stream(
                        "GET", url, headers={"User-Agent": "scrappy-os/0.1", **args.headers}
                    ) as response:
                        if response.is_redirect:
                            location = response.headers.get("location")
                            if not location:
                                raise ToolError(
                                    f"HTTP {response.status_code} redirect without a Location",
                                    tool_name=self.name,
                                )
                            url = str(response.url.join(location))
                            if hop == settings.http_max_redirects:
                                raise ToolError(
                                    f"Exceeded {settings.http_max_redirects} redirects",
                                    tool_name=self.name,
                                )
                            continue
                        return await self._read_response(
                            response, hops=hops, max_bytes=max_bytes, started=started
                        )
                except httpx.TimeoutException as exc:
                    raise ToolError(f"Request to {url} timed out", tool_name=self.name) from exc
                except httpx.HTTPError as exc:
                    raise ToolError(f"Request to {url} failed: {exc}", tool_name=self.name) from exc

        raise ToolError("Redirect loop was not resolved", tool_name=self.name)

    async def _read_response(
        self, response: httpx.Response, *, hops: list[str], max_bytes: int, started: float
    ) -> dict[str, Any]:
        body = bytearray()
        truncated = False
        async for chunk in response.aiter_bytes():
            remaining = max_bytes - len(body)
            if remaining <= 0:
                truncated = True
                break
            body.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True
                break

        content_type = response.headers.get("content-type", "")
        is_text = any(content_type.startswith(prefix) for prefix in TEXTUAL_PREFIXES)
        duration_ms = (time.perf_counter() - started) * 1000

        result: dict[str, Any] = {
            "url": str(response.url),
            "redirect_chain": hops,
            "status_code": response.status_code,
            "content_type": content_type,
            "bytes_received": len(body),
            "truncated": truncated,
            "duration_ms": round(duration_ms, 1),
        }
        if is_text:
            result["body"] = bytes(body).decode(response.encoding or "utf-8", errors="replace")
        else:
            result["body"] = None
            result["note"] = f"binary content ({content_type}) not decoded"
        return result

    def _validate_url(self, url: str, *, allow_private: bool) -> None:
        """Full scheme, host and address check. Run on every redirect hop."""
        parsed = urlparse(url)

        if parsed.scheme not in ALLOWED_SCHEMES:
            raise ToolError(
                f"Scheme {parsed.scheme!r} is not permitted; only http and https",
                tool_name=self.name,
            )
        if parsed.username or parsed.password:
            raise ToolError("Credentials in URLs are not permitted", tool_name=self.name)

        hostname = parsed.hostname
        if not hostname:
            raise ToolError(f"URL {url!r} has no hostname", tool_name=self.name)

        if hostname.lower() in BLOCKED_HOSTNAMES:
            raise ToolError(
                f"{hostname} is a cloud metadata endpoint and is always blocked",
                tool_name=self.name,
            )

        if allow_private:
            return

        for address in resolve_all(hostname, tool_name=self.name):
            if is_private_address(address):
                raise ToolError(
                    f"{hostname} resolves to {address}, which is a private, loopback or "
                    "link-local address. Set SCRAPPY_HTTP_ALLOW_PRIVATE_NETWORKS=true only "
                    "if you intend the agent to reach internal services.",
                    tool_name=self.name,
                )


def resolve_all(
    hostname: str, *, tool_name: str = "http.get"
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Every address a hostname resolves to.

    All of them are checked, not just the first: a host with one public and one
    private A record must not be reachable.
    """
    try:
        parsed = ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        return [parsed]

    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ToolError(f"Cannot resolve {hostname}: {exc}", tool_name=tool_name) from exc

    addresses = []
    for info in infos:
        raw = info[4][0]
        try:
            addresses.append(ipaddress.ip_address(raw))
        except ValueError:  # pragma: no cover - getaddrinfo returns valid addresses
            continue
    if not addresses:
        raise ToolError(f"{hostname} resolved to no usable address", tool_name=tool_name)
    return addresses


def is_private_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Whether an address is on this machine, this network, or otherwise not public.

    Deliberately broad: unspecified, loopback, link-local (which covers
    169.254.169.254), private, reserved, and multicast all count.
    """
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


HTTP_TOOLS: tuple[Tool, ...] = (HTTPGetTool(),)

__all__ = [
    "ALLOWED_SCHEMES",
    "BLOCKED_HOSTNAMES",
    "HTTP_TOOLS",
    "HTTPGetArgs",
    "HTTPGetTool",
    "is_private_address",
    "resolve_all",
]
