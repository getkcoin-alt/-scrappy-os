"""The model provider contract.

One interface covers a hosted API, a local Ollama daemon and the deterministic
development provider. Nothing above this layer knows which is in use - agents
ask for structured output and get a validated Pydantic object or an exception.

Structured output is the important half. Free text from a model is treated as
untrusted input everywhere in this codebase; the only way it becomes an action
is by validating into a typed schema first, and even then the policy engine
still gets a veto.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any, Literal, TypeVar

from pydantic import BaseModel, Field, ValidationError

from scrappy_os.core.errors import StructuredOutputError
from scrappy_os.core.models import ScrappyModel, utc_now

Role = Literal["system", "user", "assistant"]
SchemaT = TypeVar("SchemaT", bound=BaseModel)


class ChatMessage(ScrappyModel):
    """One turn of a conversation with a model."""

    role: Role
    content: str

    @classmethod
    def system(cls, content: str) -> ChatMessage:
        return cls(role="system", content=content)

    @classmethod
    def user(cls, content: str) -> ChatMessage:
        return cls(role="user", content=content)

    @classmethod
    def assistant(cls, content: str) -> ChatMessage:
        return cls(role="assistant", content=content)

    def to_wire(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


class GenerationResult(ScrappyModel):
    """Raw model output plus the accounting we care about."""

    text: str
    model: str
    provider: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    duration_ms: float = 0.0
    finish_reason: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict, repr=False)


class ProviderInfo(ScrappyModel):
    """Static description of a provider, surfaced by ``scrappy doctor``."""

    name: str
    kind: Literal["mock", "openai", "ollama"]
    model: str
    base_url: str | None = None
    supports_structured_output: bool = True
    requires_network: bool = True
    requires_credentials: bool = False


class ProviderHealth(ScrappyModel):
    """Result of a liveness probe against a provider."""

    healthy: bool
    detail: str
    latency_ms: float | None = None
    checked_at: Any = Field(default_factory=utc_now)


class ModelProvider(ABC):
    """Base class every provider implements.

    Subclasses implement :meth:`generate` and :meth:`health_check`;
    :meth:`generate_structured` is provided here so that JSON extraction,
    schema validation and repair behave identically no matter who is serving
    the tokens.
    """

    @property
    @abstractmethod
    def info(self) -> ProviderInfo:
        """Static metadata about this provider."""

    @abstractmethod
    async def generate(
        self,
        messages: Sequence[ChatMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        stop: Sequence[str] | None = None,
    ) -> GenerationResult:
        """Produce free text."""

    @abstractmethod
    async def health_check(self) -> ProviderHealth:
        """Probe reachability. Must never raise; report unhealthy instead."""

    async def generate_structured(
        self,
        messages: Sequence[ChatMessage],
        schema: type[SchemaT],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        max_repairs: int = 1,
    ) -> SchemaT:
        """Produce output validated against ``schema``.

        One repair round is allowed: models routinely emit prose around JSON or
        miss a required field, and re-prompting with the validation error is
        cheaper and more honest than a lenient parser. After that we fail loudly
        rather than hand a half-understood object to the orchestrator.
        """
        instruction = _schema_instruction(schema)
        conversation = [*messages, ChatMessage.system(instruction)]
        last_error: str | None = None

        for attempt in range(max_repairs + 1):
            result = await self.generate(
                conversation, temperature=temperature, max_tokens=max_tokens
            )
            try:
                payload = extract_json(result.text)
                return schema.model_validate(payload)
            except (StructuredOutputError, ValidationError) as exc:
                last_error = _format_error(exc)
                if attempt >= max_repairs:
                    break
                conversation = [
                    *messages,
                    ChatMessage.system(instruction),
                    ChatMessage.assistant(result.text[:2000]),
                    ChatMessage.user(
                        "That response was rejected: "
                        f"{last_error}\n"
                        "Reply with corrected JSON only. No prose, no code fences."
                    ),
                ]

        raise StructuredOutputError(
            f"Model did not return valid {schema.__name__} after {max_repairs + 1} attempts",
            provider=self.info.name,
            schema=schema.__name__,
            detail=last_error or "unknown",
        )

    async def aclose(self) -> None:
        """Release transport resources. Default is a no-op."""
        return None


_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def extract_json(text: str) -> Any:
    """Pull a JSON document out of model output.

    Handles the three things models actually do: clean JSON, JSON in a code
    fence, and JSON with a sentence bolted on either side. Anything else is an
    error - this function never guesses at a partial structure.
    """
    stripped = text.strip()
    if not stripped:
        raise StructuredOutputError("Model returned an empty response", provider="unknown")

    for candidate in _json_candidates(stripped):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue

    raise StructuredOutputError(
        "No JSON object found in model output",
        provider="unknown",
        preview=stripped[:300],
    )


def _json_candidates(text: str) -> list[str]:
    candidates = [text]
    fenced = _FENCE_RE.search(text)
    if fenced:
        candidates.append(fenced.group(1).strip())
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end > start:
            candidates.append(text[start : end + 1])
    return candidates


def _schema_instruction(schema: type[BaseModel]) -> str:
    rendered = json.dumps(schema.model_json_schema(), indent=2, sort_keys=True)
    return (
        "Respond with a single JSON object and nothing else. No prose, no code "
        "fences, no explanation outside the JSON. It must validate against this "
        f"JSON Schema:\n{rendered}"
    )


def _format_error(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        problems = [
            f"{'.'.join(str(part) for part in err['loc'])}: {err['msg']}"
            for err in exc.errors()[:5]
        ]
        return "; ".join(problems)
    return str(exc)


__all__ = [
    "ChatMessage",
    "GenerationResult",
    "ModelProvider",
    "ProviderHealth",
    "ProviderInfo",
    "Role",
    "extract_json",
]
