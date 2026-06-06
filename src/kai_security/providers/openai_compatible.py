"""OpenAI-compatible HTTP provider adapter."""

from __future__ import annotations

import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class OpenAICompatibleHTTPAdapter:
    """Adapter that sends chat/completion payloads to OpenAI-compatible endpoints."""

    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

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
        _ = request_id
        _ = effective_prompt
        payload = {"model": model, "messages": messages}
        if provider_options:
            payload.update(provider_options)
        return _post_chat_completion(
            endpoint=self.endpoint,
            payload=payload,
            api_key=self.api_key,
            gateway_security=gateway_security,
            timeout_seconds=self.timeout_seconds,
        )


def _build_completion_url(base_endpoint: str) -> str:
    normalized = base_endpoint.rstrip("/")
    if normalized.endswith("/v1/chat/completions"):
        return normalized
    if normalized.endswith("/v1"):
        return f"{normalized}/chat/completions"
    return f"{normalized}/v1/chat/completions"


def _post_chat_completion(
    *,
    endpoint: str,
    payload: dict[str, object],
    api_key: str | None,
    gateway_security: dict[str, object],
    timeout_seconds: float,
) -> dict[str, object]:
    url = _build_completion_url(endpoint)
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    if _send_upstream_metadata_enabled():
        headers["X-KAI-Security"] = json.dumps(
            _upstream_gateway_security(gateway_security),
            ensure_ascii=False,
        )

    request = Request(
        url=url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            raw = response.read().decode("utf-8")
    except HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="ignore") if getattr(exc, "read", None) else ""
        raise RuntimeError(f"provider request failed: {exc.code} {error_body}") from exc
    except (URLError, TimeoutError) as exc:
        raise RuntimeError(f"provider request failed: {exc}") from exc

    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("provider response has invalid JSON shape") from exc
    if not isinstance(body, dict):
        raise RuntimeError("provider response has invalid JSON shape")
    return body


def _send_upstream_metadata_enabled() -> bool:
    raw = os.environ.get("KAI_SECURITY_SEND_UPSTREAM_METADATA", "")
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _upstream_gateway_security(gateway_security: dict[str, object]) -> dict[str, object]:
    return {
        key: gateway_security[key]
        for key in ("request_id", "action", "policy_id")
        if key in gateway_security
    }
