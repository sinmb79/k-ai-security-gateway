"""Provider adapter layer for chat completion providers.

The registry resolves model-route providers into concrete adapters.
"""

from __future__ import annotations

from math import isfinite
from dataclasses import dataclass
from os import getenv
from typing import Iterable, Protocol

from kai_security.model_router import ModelRoute


class ChatCompletionProvider(Protocol):
    def complete(
        self,
        *,
        request_id: str,
        model: str,
        messages: list[dict[str, object]],
        effective_prompt: str,
        gateway_security: dict[str, object],
    ) -> dict[str, object]:
        """Complete a chat request and return an OpenAI-like response payload."""


@dataclass(frozen=True)
class ProviderConfig:
    provider_name: str
    endpoint_env: str
    api_key_env: str


def _provider_env_variables(provider: str) -> ProviderConfig:
    key = provider.upper().replace("-", "_")
    return ProviderConfig(
        provider_name=provider,
        endpoint_env=f"KAI_SECURITY_{key}_ENDPOINT",
        api_key_env=f"KAI_SECURITY_{key}_API_KEY",
    )


def resolve_provider_adapter(route: ModelRoute) -> ChatCompletionProvider:
    """Resolve the provider adapter for a model route.

    For known providers, fallback to :class:`EchoChatCompletionAdapter` unless an
    endpoint environment variable is defined. Unknown providers also use the echo
    adapter by default.
    """

    from kai_security.providers.echo import EchoChatCompletionAdapter
    from kai_security.providers.openai_compatible import OpenAICompatibleHTTPAdapter

    known_providers = {
        "external-openai-compatible",
        "private-llm",
        "domestic-saas",
        "on-prem-llm",
    }

    config = _provider_env_variables(route.provider)
    endpoint = getenv(config.endpoint_env, "").strip()
    if route.provider in known_providers and endpoint:
        api_key = getenv(config.api_key_env, "").strip()
        timeout_raw = getenv("KAI_SECURITY_PROVIDER_REQUEST_TIMEOUT_SECONDS", "").strip()
        timeout = _coerce_timeout_seconds(timeout_raw)
        return OpenAICompatibleHTTPAdapter(
            endpoint=endpoint,
            api_key=api_key or None,
            timeout_seconds=timeout,
        )

    return EchoChatCompletionAdapter()


def _coerce_timeout_seconds(raw: str) -> float:
    if not raw:
        return 5.0
    try:
        timeout = float(raw)
    except ValueError:
        return 5.0
    if timeout <= 0 or not isfinite(timeout):
        return 5.0
    return timeout


def iterate_provider_env_names(providers: Iterable[str] = ()) -> dict[str, ProviderConfig]:
    return {provider: _provider_env_variables(provider) for provider in providers}
