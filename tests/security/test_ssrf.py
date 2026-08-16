"""Outbound HTTP must not become a door into the private network.

The attack these tests defend against: an agent that can fetch a URL is asked -
by an objective, or by text it read from a log file - to fetch
``http://169.254.169.254/latest/meta-data/iam/security-credentials/``, and hands
back the instance's credentials.
"""

from __future__ import annotations

import ipaddress

import pytest

from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.errors import ToolError
from scrappy_os.tools.base import ToolContext
from scrappy_os.tools.http import HTTPGetArgs, HTTPGetTool, is_private_address

pytestmark = pytest.mark.security


PRIVATE_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS/Azure IMDS
    "http://127.0.0.1:8787/status",  # this control plane's own API
    "http://localhost/admin",
    "http://10.0.0.5/internal",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://metadata.google.internal/computeMetadata/v1/",
]

BAD_SCHEMES = [
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_FLUSHALL",
    "ftp://internal/secrets",
    "dict://127.0.0.1:11211/stats",
]


@pytest.mark.parametrize(
    "address",
    [
        "169.254.169.254",
        "127.0.0.1",
        "10.1.2.3",
        "192.168.0.1",
        "172.20.0.1",
        "::1",
        "fd00::1",
        "0.0.0.0",
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
    ],
)
def test_private_addresses_are_recognised(address: str) -> None:
    assert is_private_address(ipaddress.ip_address(address))


@pytest.mark.parametrize("address", ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700::1111"])
def test_public_addresses_are_not_flagged(address: str) -> None:
    assert not is_private_address(ipaddress.ip_address(address))


@pytest.mark.parametrize("url", PRIVATE_TARGETS)
async def test_private_network_targets_are_refused(settings: ScrappySettings, url: str) -> None:
    """No request is made at all - the check happens before connecting."""
    ctx = ToolContext(settings=settings, task_id="t", actor="test")
    with pytest.raises(ToolError) as excinfo:
        await HTTPGetTool().run(HTTPGetArgs(url=url), ctx)
    assert "private" in str(excinfo.value).lower() or "metadata" in str(excinfo.value).lower()


@pytest.mark.parametrize("url", BAD_SCHEMES)
async def test_non_http_schemes_are_refused(settings: ScrappySettings, url: str) -> None:
    ctx = ToolContext(settings=settings, task_id="t", actor="test")
    with pytest.raises(ToolError, match=r"not permitted|no hostname"):
        await HTTPGetTool().run(HTTPGetArgs(url=url), ctx)


async def test_credentials_in_the_url_are_refused(settings: ScrappySettings) -> None:
    ctx = ToolContext(settings=settings, task_id="t", actor="test")
    with pytest.raises(ToolError, match="Credentials"):
        await HTTPGetTool().run(HTTPGetArgs(url="http://user:password@example.com/"), ctx)


def test_credential_headers_are_rejected_at_validation() -> None:
    """A plan cannot attach an Authorization header to an arbitrary outbound request."""
    for header in ("Authorization", "cookie", "Proxy-Authorization"):
        with pytest.raises(ValueError, match="not permitted"):
            HTTPGetArgs(url="https://example.com", headers={header: "secret"})


async def test_http_can_be_disabled_entirely(settings: ScrappySettings) -> None:
    settings.http_enabled = False
    ctx = ToolContext(settings=settings, task_id="t", actor="test")
    with pytest.raises(ToolError, match="disabled"):
        await HTTPGetTool().run(HTTPGetArgs(url="https://example.com"), ctx)


async def test_private_networks_reachable_only_when_explicitly_enabled(
    settings: ScrappySettings,
) -> None:
    """The escape hatch exists, but it is opt-in and named for what it does.

    With the flag on, validation passes and the request is attempted; it then
    fails at the transport layer because nothing is listening. Reaching the
    connection attempt is the observable difference.
    """
    settings.http_allow_private_networks = True
    settings.http_timeout_seconds = 1.0
    ctx = ToolContext(settings=settings, task_id="t", actor="test")

    with pytest.raises(ToolError) as excinfo:
        await HTTPGetTool().run(HTTPGetArgs(url="http://127.0.0.1:1/nothing-here"), ctx)
    message = str(excinfo.value).lower()
    assert "private" not in message, "validation should have passed; this is a transport error"


async def test_metadata_hostname_blocked_even_with_private_networks_enabled(
    settings: ScrappySettings,
) -> None:
    """Cloud metadata endpoints are blocked unconditionally, flag or no flag."""
    settings.http_allow_private_networks = True
    ctx = ToolContext(settings=settings, task_id="t", actor="test")
    with pytest.raises(ToolError, match="metadata"):
        await HTTPGetTool().run(
            HTTPGetArgs(url="http://metadata.google.internal/computeMetadata/v1/"), ctx
        )
