"""Ollama provider - local inference over HTTP.

The point of supporting Ollama in v0.1 is not benchmark parity. It is that an
operator can run Scrappy OS against a model on the same machine, with no
outbound network and no API key, and get the same typed behaviour. Anything
that only works with a hosted model has been designed wrong.

Uses ``/api/chat`` with ``stream: false`` and asks for ``format: json`` when
structured output is wanted, which materially improves small local models.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from contextvars import ContextVar
from typing import Any

import httpx

from scrappy_os.core.errors import ProviderError, ProviderUnavailable
from scrappy_os.models.base import (
    ChatMessage,
    GenerationResult,
    ModelProvider,
    ProviderHealth,
    ProviderInfo,
    SchemaT,
)
from scrappy_os.observability.logging import get_logger

logger = get_logger("provider.ollama")

#: Whether the in-flight request should ask Ollama for JSON mode.
#:
#: This is a ContextVar rather than an attribute on the provider because one
#: provider instance is deliberately shared by the whole runtime (ModelRouter
#: keeps a single instance so the HTTP connection pool is shared) while the API
#: runs objectives concurrently via ``Runtime.spawn``. An instance attribute
#: set around an ``await`` leaks across those tasks in both directions: a plain
#: ``generate`` gets forced into JSON mode and returns mangled prose, or a
#: structured call silently loses JSON mode and its schema failure rate goes
#: up. asyncio copies the context per Task, so a ContextVar cannot leak.
_JSON_MODE: ContextVar[bool] = ContextVar("ollama_json_mode", default=False)


class OllamaProvider(ModelProvider):
    """Talks to a local (or LAN) Ollama daemon."""

    def __init__(
        self,
        *,
        model: str,
        base_url: str = "http://127.0.0.1:11434",
        timeout: float = 120.0,
        temperature: float = 0.1,
        max_tokens: int = 2048,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._client = client
        self._owns_client = client is None

    @property
    def info(self) -> ProviderInfo:
        return ProviderInfo(
            name="ollama",
            kind="ollama",
            model=self._model,
            base_url=self._base_url,
            supports_structured_output=True,
            requires_network=False,
            requires_credentials=False,
        )

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
            self._owns_client = True
        return self._client

    async def generate(
        self,
        messages: Sequence[ChatMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        stop: Sequence[str] | None = None,
    ) -> GenerationResult:
        options: dict[str, Any] = {
            "temperature": self._temperature if temperature is None else temperature,
            "num_predict": self._max_tokens if max_tokens is None else max_tokens,
        }
        if stop:
            options["stop"] = list(stop)

        body: dict[str, Any] = {
            "model": self._model,
            "messages": [message.to_wire() for message in messages],
            "stream": False,
            "options": options,
        }
        if _JSON_MODE.get():
            body["format"] = "json"

        started = time.perf_counter()
        try:
            response = await self._http().post(
                f"{self._base_url}/api/chat", json=body, timeout=self._timeout
            )
        except httpx.TimeoutException as exc:
            raise ProviderUnavailable(
                f"Ollama at {self._base_url} timed out after {self._timeout}s", provider="ollama"
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderUnavailable(
                f"Cannot reach Ollama at {self._base_url}: {exc}. Is `ollama serve` running?",
                provider="ollama",
            ) from exc

        duration_ms = (time.perf_counter() - started) * 1000

        if response.status_code >= 400:
            raise ProviderError(
                f"Ollama returned HTTP {response.status_code}",
                provider="ollama",
                status_code=response.status_code,
                detail=response.text[:300],
            )

        try:
            payload = response.json()
            text = payload["message"]["content"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ProviderError(f"Malformed Ollama response: {exc}", provider="ollama") from exc

        logger.debug("generation_complete", model=self._model, duration_ms=round(duration_ms, 1))
        return GenerationResult(
            text=text,
            model=payload.get("model", self._model),
            provider="ollama",
            prompt_tokens=payload.get("prompt_eval_count"),
            completion_tokens=payload.get("eval_count"),
            duration_ms=duration_ms,
            finish_reason=payload.get("done_reason"),
        )

    async def generate_structured(
        self,
        messages: Sequence[ChatMessage],
        schema: type[SchemaT],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        max_repairs: int = 1,
    ) -> SchemaT:
        """Same contract as the base class, with Ollama's JSON mode enabled."""
        token = _JSON_MODE.set(True)
        try:
            return await super().generate_structured(
                messages,
                schema,
                temperature=temperature,
                max_tokens=max_tokens,
                max_repairs=max_repairs,
            )
        finally:
            _JSON_MODE.reset(token)

    async def health_check(self) -> ProviderHealth:
        started = time.perf_counter()
        try:
            response = await self._http().get(f"{self._base_url}/api/tags", timeout=10)
        except httpx.HTTPError as exc:
            return ProviderHealth(
                healthy=False,
                detail=f"cannot reach {self._base_url}: {exc}. Is `ollama serve` running?",
            )
        latency_ms = (time.perf_counter() - started) * 1000
        if response.status_code >= 400:
            return ProviderHealth(healthy=False, detail=f"HTTP {response.status_code}")

        try:
            models = [entry["name"] for entry in response.json().get("models", [])]
        except (ValueError, KeyError, TypeError):
            models = []

        # Ollama reports "llama3:latest"; a configured "llama3" should match.
        installed = any(
            name == self._model or name.split(":", 1)[0] == self._model.split(":", 1)[0]
            for name in models
        )
        if not installed:
            return ProviderHealth(
                healthy=False,
                detail=f"{self._model} is not pulled. Run: ollama pull {self._model}",
                latency_ms=latency_ms,
            )
        return ProviderHealth(
            healthy=True,
            detail=f"{self._base_url} reachable, model={self._model}",
            latency_ms=latency_ms,
        )

    async def aclose(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None


__all__ = ["OllamaProvider"]
