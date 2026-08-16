"""Provider registry and router.

The rest of Scrappy OS asks the registry for "the provider" and never learns
which one it got. Adding a provider means registering a factory here; it does
not mean touching an agent.

v0.1 routes by configuration only. The seam for real routing - per-role models,
cost tiers, local-first with hosted fallback - is :meth:`ModelRouter.for_role`,
which already takes a role and today returns the same provider for all of them.
"""

from __future__ import annotations

from collections.abc import Callable

from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.enums import AgentRole
from scrappy_os.core.errors import ConfigurationError
from scrappy_os.models.base import ModelProvider, ProviderHealth
from scrappy_os.models.mock import MockProvider
from scrappy_os.models.ollama import OllamaProvider
from scrappy_os.models.openai_compat import OpenAICompatibleProvider
from scrappy_os.observability.logging import get_logger

logger = get_logger("model_registry")

ProviderFactory = Callable[[ScrappySettings], ModelProvider]


def _build_mock(settings: ScrappySettings) -> ModelProvider:
    return MockProvider()


def _build_openai(settings: ScrappySettings) -> ModelProvider:
    return OpenAICompatibleProvider(
        model=settings.model_name,
        api_key=settings.openai_api_key,
        base_url=settings.openai_base_url,
        timeout=settings.model_timeout_seconds,
        temperature=settings.model_temperature,
        max_tokens=settings.model_max_tokens,
    )


def _build_ollama(settings: ScrappySettings) -> ModelProvider:
    return OllamaProvider(
        model=settings.model_name,
        base_url=settings.ollama_base_url,
        timeout=settings.model_timeout_seconds,
        temperature=settings.model_temperature,
        max_tokens=settings.model_max_tokens,
    )


PROVIDER_FACTORIES: dict[str, ProviderFactory] = {
    "mock": _build_mock,
    "openai": _build_openai,
    "ollama": _build_ollama,
}


def register_provider(name: str, factory: ProviderFactory) -> None:
    """Add a provider factory. Intended for plugins and tests."""
    PROVIDER_FACTORIES[name] = factory


def build_provider(settings: ScrappySettings) -> ModelProvider:
    """Construct the configured provider.

    Construction never performs I/O, so a misconfigured endpoint surfaces at
    ``scrappy doctor`` or first use - not as an import-time crash.
    """
    factory = PROVIDER_FACTORIES.get(settings.model_provider)
    if factory is None:
        raise ConfigurationError(
            f"Unknown model provider {settings.model_provider!r}. "
            f"Known: {', '.join(sorted(PROVIDER_FACTORIES))}",
            provider=settings.model_provider,
        )
    provider = factory(settings)
    logger.debug("provider_built", provider=provider.info.name, model=provider.info.model)
    return provider


class ModelRouter:
    """Hands out providers to agents.

    Holds one provider instance so HTTP connection pools are shared. An
    explicit provider can be injected, which is how tests and the integration
    suite pin behaviour.
    """

    def __init__(self, settings: ScrappySettings, *, provider: ModelProvider | None = None) -> None:
        self._settings = settings
        self._provider = provider or build_provider(settings)

    @property
    def provider(self) -> ModelProvider:
        return self._provider

    def for_role(self, role: AgentRole) -> ModelProvider:
        """The provider a given agent role should use.

        Single-provider today. When per-role routing arrives (a cheap local
        model for Vishnu's verification, a stronger one for Brahma's planning),
        it lands here and nothing above changes.
        """
        return self._provider

    @property
    def is_development_provider(self) -> bool:
        """True when inference is the deterministic stub, not a model.

        Surfaced by ``doctor``, ``status`` and the API so nobody mistakes a
        rule table for reasoning.
        """
        return self._provider.info.kind == "mock"

    async def health_check(self) -> ProviderHealth:
        try:
            return await self._provider.health_check()
        except Exception as exc:  # noqa: BLE001 - health checks report, never raise
            return ProviderHealth(healthy=False, detail=f"{type(exc).__name__}: {exc}")

    async def aclose(self) -> None:
        await self._provider.aclose()


__all__ = [
    "PROVIDER_FACTORIES",
    "ModelRouter",
    "ProviderFactory",
    "build_provider",
    "register_provider",
]
