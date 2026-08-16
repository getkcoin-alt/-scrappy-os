"""Model providers and routing.

Import from here rather than from the concrete modules, so that swapping a
provider implementation stays an internal change.
"""

from __future__ import annotations

from scrappy_os.models.base import (
    ChatMessage,
    GenerationResult,
    ModelProvider,
    ProviderHealth,
    ProviderInfo,
)
from scrappy_os.models.mock import MockProvider
from scrappy_os.models.ollama import OllamaProvider
from scrappy_os.models.openai_compat import OpenAICompatibleProvider
from scrappy_os.models.registry import ModelRouter, build_provider, register_provider

__all__ = [
    "ChatMessage",
    "GenerationResult",
    "MockProvider",
    "ModelProvider",
    "ModelRouter",
    "OllamaProvider",
    "OpenAICompatibleProvider",
    "ProviderHealth",
    "ProviderInfo",
    "build_provider",
    "register_provider",
]
