"""Provider abstraction, structured output and routing."""

from __future__ import annotations

from collections.abc import Sequence

import pytest
from pydantic import BaseModel, Field

from scrappy_os.agents.schemas import PlanProposal, Verification
from scrappy_os.core.config import ScrappySettings
from scrappy_os.core.enums import AgentRole
from scrappy_os.core.errors import ConfigurationError, StructuredOutputError
from scrappy_os.models.base import (
    ChatMessage,
    GenerationResult,
    ModelProvider,
    ProviderHealth,
    ProviderInfo,
    extract_json,
)
from scrappy_os.models.mock import MockProvider
from scrappy_os.models.ollama import OllamaProvider
from scrappy_os.models.openai_compat import OpenAICompatibleProvider
from scrappy_os.models.registry import ModelRouter, build_provider, register_provider


class _Answer(BaseModel):
    model_config = {"extra": "forbid"}

    verdict: str
    score: int = Field(ge=0, le=10)


class _ScriptedProvider(ModelProvider):
    """Returns canned text, so structured-output handling can be tested exactly."""

    def __init__(self, *responses: str) -> None:
        self._responses = list(responses)
        self.prompts: list[list[ChatMessage]] = []

    @property
    def info(self) -> ProviderInfo:
        return ProviderInfo(name="scripted", kind="mock", model="scripted-1")

    async def generate(
        self,
        messages: Sequence[ChatMessage],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        stop: Sequence[str] | None = None,
    ) -> GenerationResult:
        self.prompts.append(list(messages))
        text = self._responses.pop(0) if self._responses else "{}"
        return GenerationResult(text=text, model="scripted-1", provider="scripted")

    async def health_check(self) -> ProviderHealth:
        return ProviderHealth(healthy=True, detail="scripted")


# ---------------------------------------------------------------------------
# JSON extraction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        '{"verdict": "ok", "score": 7}',
        '```json\n{"verdict": "ok", "score": 7}\n```',
        '```\n{"verdict": "ok", "score": 7}\n```',
        'Here is my answer:\n{"verdict": "ok", "score": 7}\nHope that helps!',
        '   {"verdict": "ok", "score": 7}   ',
    ],
)
def test_json_is_extracted_from_the_shapes_models_actually_emit(text: str) -> None:
    assert extract_json(text) == {"verdict": "ok", "score": 7}


@pytest.mark.parametrize("text", ["", "   ", "I cannot help with that.", "{ not json at all"])
def test_unparseable_output_raises_rather_than_guessing(text: str) -> None:
    with pytest.raises(StructuredOutputError):
        extract_json(text)


# ---------------------------------------------------------------------------
# structured generation
# ---------------------------------------------------------------------------


async def test_structured_output_validates_into_the_schema() -> None:
    provider = _ScriptedProvider('{"verdict": "healthy", "score": 9}')
    answer = await provider.generate_structured([ChatMessage.user("judge")], _Answer)
    assert answer.verdict == "healthy"
    assert answer.score == 9


async def test_one_repair_round_is_attempted_with_the_validation_error() -> None:
    """Models miss fields; re-prompting with the error beats a lenient parser."""
    provider = _ScriptedProvider(
        '{"verdict": "healthy"}',  # missing score
        '{"verdict": "healthy", "score": 5}',
    )
    answer = await provider.generate_structured([ChatMessage.user("judge")], _Answer)
    assert answer.score == 5

    repair_prompt = provider.prompts[-1][-1].content
    assert "rejected" in repair_prompt
    assert "score" in repair_prompt


async def test_persistent_invalid_output_fails_loudly() -> None:
    """After the repair budget, we fail rather than hand over a half-understood object."""
    provider = _ScriptedProvider("nope", "still nope")
    with pytest.raises(StructuredOutputError, match="did not return valid"):
        await provider.generate_structured([ChatMessage.user("judge")], _Answer)


async def test_out_of_range_values_are_rejected() -> None:
    provider = _ScriptedProvider('{"verdict": "x", "score": 99}', '{"verdict": "x", "score": 99}')
    with pytest.raises(StructuredOutputError):
        await provider.generate_structured([ChatMessage.user("judge")], _Answer)


async def test_schema_instruction_includes_the_json_schema() -> None:
    provider = _ScriptedProvider('{"verdict": "ok", "score": 1}')
    await provider.generate_structured([ChatMessage.user("judge")], _Answer)
    instruction = provider.prompts[0][-1].content
    assert "JSON Schema" in instruction
    assert "verdict" in instruction


# ---------------------------------------------------------------------------
# the development provider
# ---------------------------------------------------------------------------


async def test_mock_provider_proposes_only_read_only_steps() -> None:
    """The rule table contains no mutating step, by construction."""
    provider = MockProvider()
    for objective in (
        "check disk usage",
        "why is memory high",
        "nginx is failing",
        "list processes",
        "what is the network configuration",
        "something entirely unrecognised",
    ):
        proposal = await provider.generate_structured(
            [ChatMessage.user(f"OBJECTIVE\n{objective}")], PlanProposal
        )
        assert proposal.steps
        for step in proposal.steps:
            assert str(step.expected_risk) == "read", f"{step.tool} is not read-only"


async def test_mock_provider_is_deterministic() -> None:
    first = await MockProvider().generate_structured(
        [ChatMessage.user("OBJECTIVE\ncheck disk usage")], PlanProposal
    )
    second = await MockProvider().generate_structured(
        [ChatMessage.user("OBJECTIVE\ncheck disk usage")], PlanProposal
    )
    assert [step.tool for step in first.steps] == [step.tool for step in second.steps]


async def test_mock_provider_reports_itself_as_a_development_stub() -> None:
    health = await MockProvider().health_check()
    assert health.healthy
    assert "development" in health.detail
    assert MockProvider().info.kind == "mock"


async def test_mock_verification_without_observations_does_not_claim_success() -> None:
    """No data means no conclusion - never a confident empty answer."""
    verification = await MockProvider().generate_structured(
        [ChatMessage.user("OBJECTIVE\ncheck disk usage")], Verification
    )
    assert not verification.objective_satisfied
    assert verification.decision == "abort"


async def test_mock_provider_refuses_unknown_schemas() -> None:
    """An unhandled schema is a programming error, not something to improvise."""
    with pytest.raises(NotImplementedError, match="no rule"):
        await MockProvider().generate_structured([ChatMessage.user("x")], _Answer)


# ---------------------------------------------------------------------------
# routing
# ---------------------------------------------------------------------------


def test_router_hands_the_same_provider_to_every_role(router: ModelRouter) -> None:
    """v0.1 routes by configuration only; per-role routing is a later seam."""
    providers = {router.for_role(role) for role in AgentRole}
    assert len(providers) == 1


def test_router_flags_the_development_provider(router: ModelRouter) -> None:
    assert router.is_development_provider


async def test_router_health_check_never_raises(settings: ScrappySettings) -> None:
    class _Exploding(MockProvider):
        async def health_check(self) -> ProviderHealth:
            raise RuntimeError("provider is on fire")

    router = ModelRouter(settings, provider=_Exploding())
    health = await router.health_check()
    assert not health.healthy
    assert "on fire" in health.detail


def test_provider_is_built_from_configuration(settings: ScrappySettings) -> None:
    settings.model_provider = "ollama"
    assert isinstance(build_provider(settings), OllamaProvider)

    settings.model_provider = "openai"
    assert isinstance(build_provider(settings), OpenAICompatibleProvider)

    settings.model_provider = "mock"
    assert isinstance(build_provider(settings), MockProvider)


def test_unknown_provider_is_a_configuration_error(settings: ScrappySettings) -> None:
    settings.model_provider = "telepathy"  # type: ignore[assignment]
    with pytest.raises(ConfigurationError, match="Unknown model provider"):
        build_provider(settings)


def test_new_providers_can_be_registered(settings: ScrappySettings) -> None:
    """Adding a provider is a registration, not a change to any agent."""
    register_provider("scripted", lambda _: _ScriptedProvider())
    settings.model_provider = "scripted"  # type: ignore[assignment]
    assert isinstance(build_provider(settings), _ScriptedProvider)


def test_building_a_provider_performs_no_io(settings: ScrappySettings) -> None:
    """A wrong endpoint surfaces at doctor or first use, not at import."""
    settings.model_provider = "openai"
    settings.openai_base_url = "https://unreachable.invalid/v1"
    provider = build_provider(settings)
    assert provider.info.base_url == "https://unreachable.invalid/v1"


async def test_openai_provider_reports_a_missing_key_clearly(
    settings: ScrappySettings,
) -> None:
    settings.model_provider = "openai"
    settings.openai_api_key = None
    provider = build_provider(settings)
    health = await provider.health_check()
    assert not health.healthy
    assert "OPENAI_API_KEY" in health.detail
