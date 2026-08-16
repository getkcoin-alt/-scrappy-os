"""OpenAI-compatible chat-completions provider.

Deliberately speaks raw HTTP rather than depending on a vendor SDK: the same
code then works against OpenAI, vLLM, LiteLLM, Together, Groq, OpenRouter and
anything else that implements ``POST /chat/completions``. Point
``SCRAPPY_OPENAI_BASE_URL`` at the endpoint and set the key.

The API key is held as a :class:`~pydantic.SecretStr` and only unwrapped when
building the Authorization header, so it cannot reach a log line or an audit
row by accident.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Any

import httpx
from pydantic import SecretStr

from scrappy_os.core.errors import ProviderError, ProviderUnavailable
from scrappy_os.models.base import (
    ChatMessage,
    GenerationResult,
    ModelProvider,
    ProviderHealth,
    ProviderInfo,
)
from scrappy_os.observability.logging import get_logger

logger = get_logger("provider.openai")


class OpenAICompatibleProvider(ModelProvider):
    """Chat completions over the OpenAI wire format."""

    def __init__(
        self,
        *,
        model: str,
        api_key: SecretStr | None,
        base_url: str = "https://api.openai.com/v1",
        timeout: float = 60.0,
        temperature: float = 0.1,
        max_tokens: int = 2048,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._model = model
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._client = client
        self._owns_client = client is None

    @property
    def info(self) -> ProviderInfo:
        return ProviderInfo(
            name="openai",
            kind="openai",
            model=self._model,
            base_url=self._base_url,
            supports_structured_output=True,
            requires_network=True,
            requires_credentials=True,
        )

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
            self._owns_client = True
        return self._client

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._api_key is not None:
            headers["Authorization"] = f"Bearer {self._api_key.get_secret_value()}"
        return headers

    async def generate(
        self,
        messages: Sequence[ChatMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        stop: Sequence[str] | None = None,
    ) -> GenerationResult:
        if self._api_key is None:
            raise ProviderError(
                "OPENAI_API_KEY is not set; configure it or switch SCRAPPY_MODEL_PROVIDER",
                provider="openai",
            )

        body: dict[str, Any] = {
            "model": self._model,
            "messages": [message.to_wire() for message in messages],
            "temperature": self._temperature if temperature is None else temperature,
            "max_tokens": self._max_tokens if max_tokens is None else max_tokens,
        }
        if stop:
            body["stop"] = list(stop)

        started = time.perf_counter()
        try:
            response = await self._http().post(
                f"{self._base_url}/chat/completions",
                json=body,
                headers=self._headers(),
                timeout=self._timeout,
            )
        except httpx.TimeoutException as exc:
            raise ProviderUnavailable(
                f"Request to {self._base_url} timed out after {self._timeout}s",
                provider="openai",
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderUnavailable(
                f"Cannot reach {self._base_url}: {exc}", provider="openai"
            ) from exc

        duration_ms = (time.perf_counter() - started) * 1000

        if response.status_code >= 400:
            # Body may echo the request; never log it verbatim.
            raise ProviderError(
                f"Provider returned HTTP {response.status_code}",
                provider="openai",
                status_code=response.status_code,
                detail=response.text[:300],
            )

        try:
            payload = response.json()
            choice = payload["choices"][0]
            text = choice["message"]["content"] or ""
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ProviderError(
                f"Malformed chat-completions response: {exc}", provider="openai"
            ) from exc

        usage = payload.get("usage") or {}
        logger.debug(
            "generation_complete",
            model=self._model,
            duration_ms=round(duration_ms, 1),
            completion_tokens=usage.get("completion_tokens"),
        )
        return GenerationResult(
            text=text,
            model=payload.get("model", self._model),
            provider="openai",
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            duration_ms=duration_ms,
            finish_reason=choice.get("finish_reason"),
        )

    async def health_check(self) -> ProviderHealth:
        if self._api_key is None:
            return ProviderHealth(healthy=False, detail="OPENAI_API_KEY is not set")
        started = time.perf_counter()
        try:
            response = await self._http().get(
                f"{self._base_url}/models", headers=self._headers(), timeout=min(self._timeout, 10)
            )
        except httpx.HTTPError as exc:
            return ProviderHealth(healthy=False, detail=f"unreachable: {exc}")
        latency_ms = (time.perf_counter() - started) * 1000
        if response.status_code == 401:
            return ProviderHealth(healthy=False, detail="credentials rejected (HTTP 401)")
        if response.status_code >= 400:
            return ProviderHealth(
                healthy=False, detail=f"HTTP {response.status_code} from {self._base_url}"
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


__all__ = ["OpenAICompatibleProvider"]
