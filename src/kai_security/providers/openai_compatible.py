"""OpenAI-compatible HTTP provider adapter."""

from __future__ import annotations

import json
import os
from hashlib import sha256
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from kai_security.providers.errors import ProviderError, retryable_for_status

_MAX_ERROR_BODY_BYTES = 64 * 1024


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

    idempotency_key = _header_safe_value(gateway_security.get("idempotency_key"))
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key

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
        error_body, error_body_truncated = _read_capped_error_body(exc)
        raise ProviderError(
            error_type="provider_http_error",
            status_code=exc.code,
            retryable=retryable_for_status(exc.code),
            safe_message=f"provider request failed with HTTP {exc.code}",
            body_sha256=sha256(error_body).hexdigest() if error_body else None,
            body_truncated=error_body_truncated,
        ) from exc
    except (URLError, TimeoutError) as exc:
        message = str(exc).lower()
        error_type = "provider_timeout" if "timed out" in message or "timeout" in message else "provider_network_error"
        raise ProviderError(
            error_type=error_type,
            retryable=True,
            safe_message=f"provider request failed: {error_type}",
        ) from exc

    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProviderError(
            error_type="provider_invalid_response",
            retryable=False,
            safe_message="provider response has invalid JSON shape",
        ) from exc
    if not isinstance(body, dict):
        raise ProviderError(
            error_type="provider_invalid_response",
            retryable=False,
            safe_message="provider response has invalid JSON shape",
        )
    return body


def _send_upstream_metadata_enabled() -> bool:
    raw = os.environ.get("KAI_SECURITY_SEND_UPSTREAM_METADATA", "")
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _read_capped_error_body(error: HTTPError) -> tuple[bytes, bool]:
    if not getattr(error, "read", None):
        return b"", False
    raw = error.read(_MAX_ERROR_BODY_BYTES + 1)
    if len(raw) <= _MAX_ERROR_BODY_BYTES:
        return raw, False
    return raw[:_MAX_ERROR_BODY_BYTES], True


def _header_safe_value(value: object) -> str:
    text = str(value or "").strip()
    if "\r" in text or "\n" in text:
        return ""
    return text[:200]


def _upstream_gateway_security(gateway_security: dict[str, object]) -> dict[str, object]:
    return {
        key: gateway_security[key]
        for key in ("request_id", "action", "policy_id")
        if key in gateway_security
    }
