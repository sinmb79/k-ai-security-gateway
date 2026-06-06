"""Echo/mock provider adapter."""

from __future__ import annotations

from kai_security.openai_compat import build_gateway_chat_response


class EchoChatCompletionAdapter:
    """Local/mock provider that returns the effective prompt as assistant content."""

    def complete(
        self,
        *,
        request_id: str,
        model: str,
        messages: list[dict[str, object]],
        effective_prompt: str,
        gateway_security: dict[str, object],
        provider_options: dict[str, object] | None = None,
    ) -> dict[str, object]:
        _ = messages
        _ = gateway_security
        _ = provider_options
        return build_gateway_chat_response(request_id=request_id, effective_prompt=effective_prompt, model=model)
