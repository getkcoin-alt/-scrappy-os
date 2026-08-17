"""Secrets must not reach logs, audit rows or prompts.

A credential written into an audit database is a credential in a file that
outlives the process that leaked it, so redaction is tested at every sink.
"""

from __future__ import annotations

import io
import json

import pytest

from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.enums import EventType, RiskLevel
from scrappy_os.core.models import AuditEvent, ToolCall
from scrappy_os.observability.logging import configure_logging, get_logger
from scrappy_os.observability.redaction import (
    NON_SECRET_KEYS,
    REDACTED,
    SENSITIVE_KEY_PARTS,
    is_sensitive_key,
    redact,
    redact_text,
)
from scrappy_os.security.audit import AuditLog

pytestmark = pytest.mark.security

CANARY = "sk-live-abcdefghijklmnopqrstuvwxyz012345"


@pytest.mark.parametrize(
    "key",
    [
        "api_key",
        "API_KEY",
        "openai_api_key",
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "authorization",
        "Cookie",
        "private_key",
        "aws_secret_access_key",
        "session_id",
    ],
)
def test_secret_bearing_keys_are_masked(key: str) -> None:
    assert redact({key: "hunter2"})[key] == REDACTED


def test_innocent_keys_survive() -> None:
    """Redaction must not destroy the information the audit log exists for."""
    payload = {"path": "/etc/nginx/nginx.conf", "exit_code": 0, "duration_ms": 12.5}
    assert redact(payload) == payload


@pytest.mark.parametrize(
    "value",
    [
        CANARY,
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "xoxb-1234567890-abcdefghijklm",
        "AKIAIOSFODNN7EXAMPLE",
        "Bearer abcdefghijklmnopqrstuvwxyz",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g",
    ],
)
def test_credential_shaped_values_are_masked_whatever_the_key(value: str) -> None:
    """`{"note": "sk-live-..."}` is still a leak."""
    assert REDACTED in redact({"note": value})["note"]


def test_private_keys_are_masked() -> None:
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890\n-----END RSA PRIVATE KEY-----"
    )
    assert REDACTED in redact_text(pem)


def test_redaction_reaches_into_nested_structures() -> None:
    payload = {
        "config": {"providers": [{"name": "openai", "api_key": "sk-nested"}]},
        "env": {"HOME": "/root", "OPENAI_API_KEY": CANARY},
    }
    result = redact(payload)
    assert result["config"]["providers"][0]["api_key"] == REDACTED
    assert result["env"]["OPENAI_API_KEY"] == REDACTED
    assert result["env"]["HOME"] == "/root"


def test_redaction_does_not_mutate_the_input() -> None:
    """Audit records and live objects must never share state."""
    payload = {"api_key": "sk-original"}
    redact(payload)
    assert payload["api_key"] == "sk-original"


def test_self_referential_structure_does_not_hang() -> None:
    payload: dict[str, object] = {"name": "loop"}
    payload["self"] = payload
    assert "TRUNCATED" in json.dumps(redact(payload), default=str)


def test_log_output_is_redacted() -> None:
    """The logging path scrubs even when a caller passes a secret by mistake."""
    stream = io.StringIO()
    configure_logging(level="INFO", fmt="json", stream=stream)
    get_logger("test").info("provider_configured", api_key=CANARY, note=f"key is {CANARY}")

    output = stream.getvalue()
    assert CANARY not in output
    assert REDACTED in output


async def test_audit_event_payloads_are_redacted(audit: AuditLog) -> None:
    await audit.record(
        AuditEvent(
            event_type=EventType.TOOL_COMPLETED,
            task_id="secret-task",
            payload={"api_key": CANARY, "stdout": f"exported OPENAI_API_KEY={CANARY}"},
        )
    )
    events = await audit.for_task("secret-task")
    serialised = json.dumps(events, default=str)
    assert CANARY not in serialised
    assert REDACTED in serialised


async def test_tool_call_arguments_are_redacted_in_audit(audit: AuditLog) -> None:
    await audit.record_call(
        ToolCall(
            task_id="secret-task-2",
            tool_name="http.get",
            arguments={"url": "https://example.com", "token": CANARY},
            risk_level=RiskLevel.WRITE,
        )
    )
    calls = await audit.calls_for_task("secret-task-2")
    assert CANARY not in json.dumps(calls, default=str)
    assert calls[0]["arguments"]["url"] == "https://example.com"


def test_settings_never_serialise_the_api_key(settings: ScrappySettings) -> None:
    """`scrappy config show` and GET /status both go through this."""
    from pydantic import SecretStr

    settings.openai_api_key = SecretStr(CANARY)
    rendered = json.dumps(settings.redacted_dict(), default=str)
    assert CANARY not in rendered
    assert '"openai_api_key": "<set>"' in rendered


def test_settings_distinguish_set_from_unset(settings: ScrappySettings) -> None:
    assert settings.redacted_dict()["openai_api_key"] == "<unset>"


def test_process_command_lines_are_redacted() -> None:
    """`mysql -psecret` in a process list is a real leak path."""
    assert REDACTED in redact_text(f"mysql --token={CANARY}")


def test_oversized_strings_are_truncated_not_dropped() -> None:
    """Bounding a value must still say that bounding happened."""
    result = redact({"body": "x" * 20000})["body"]
    assert len(result) < 20000
    assert "truncated" in result


# --- The identity allowlist -------------------------------------------------
#
# The key heuristic is a substring match, so it catches names that merely
# contain a secret-sounding word while holding an identifier: credential_id
# contains "credential", auth_method contains "auth". Those two are exactly what
# the audit trail must record - which credential, and how the principal proved
# itself - so an allowlist carves them back out. An allowlist on a redaction
# sweep is a hole by construction, so what is tested here is mostly its edges.


@pytest.mark.parametrize("key", sorted(NON_SECRET_KEYS))
def test_identity_keys_survive_redaction(key: str) -> None:
    """A trail that says [REDACTED] cannot say which credential was revoked."""
    assert redact({key: "cred_a8f13e9c2b41"})[key] == "cred_a8f13e9c2b41"


def test_the_allowlist_holds_no_genuinely_secret_name() -> None:
    """The regression that matters: adding "token" here would open a leak.

    Every entry must be a name that carries an identifier. This asserts the
    property rather than the current contents, so it fails on the *addition*
    rather than years later on the leak.
    """
    for key in NON_SECRET_KEYS:
        assert not key.endswith(("_token", "_secret", "_key", "_password")), key
        assert key not in SENSITIVE_KEY_PARTS, key


def test_the_allowlist_is_exact_match_not_substring() -> None:
    """Otherwise "credential_id" would also unmask "credential_id_secret"."""
    assert is_sensitive_key("credential_id_secret")
    assert is_sensitive_key("x_credential_id")
    assert not is_sensitive_key("credential_id")


def test_the_allowlist_ignores_case_like_the_sweep_it_amends() -> None:
    assert redact({"Credential_ID": "cred_a8f13e9c2b41"})["Credential_ID"] != REDACTED


def test_a_secret_beside_an_identity_key_is_still_masked() -> None:
    """The allowlist exempts a name, never the payload it appears in."""
    result = redact(
        {
            "credential_id": "cred_a8f13e9c2b41",
            "auth_method": "bearer_token",
            "token": CANARY,
            "note": f"issued {CANARY}",
        }
    )
    assert result["credential_id"] == "cred_a8f13e9c2b41"
    assert result["auth_method"] == "bearer_token"
    assert result["token"] == REDACTED
    assert CANARY not in json.dumps(result)
