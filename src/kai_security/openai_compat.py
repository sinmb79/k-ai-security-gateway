"""Utilities for OpenAI-compatible request/response adaptation."""

from __future__ import annotations

from time import time


def _extract_message_text(content: object) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        texts = []
        for part in content:
            if not isinstance(part, dict):
                continue
            part_text = part.get("text")
            if isinstance(part_text, str):
                texts.append(part_text)
        return "".join(texts)
    raise ValueError("Each message content must be a string or list of text parts.")


def extract_chat_prompt(payload: dict[str, object]) -> str:
    """Flatten OpenAI-style chat messages into a single concatenated prompt."""
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ValueError("Request payload must contain a non-empty messages list.")

    chunks: list[str] = []
    for message in messages:
        if not isinstance(message, dict):
            raise ValueError("Each messages item must be a dict.")
        role = message.get("role")
        if not isinstance(role, str):
            raise ValueError("Each message must have a role string.")
        if "content" not in message:
            raise ValueError("Each message must include content.")
        content = _extract_message_text(message.get("content"))
        if content == "":
            raise ValueError("Each message content must include text content.")
        chunks.append(f"{role}: {content}")

    return " ".join(chunks)


def build_blocked_chat_response(request_id: str, reason: str) -> dict[str, object]:
    """Build a safe OpenAI-like chat completion for blocked or approval-required requests."""
    _ = reason
    safe_message = (
        "요청이 보안 정책에 의해 처리되지 못했습니다. "
        "민감한 내용은 표시되지 않습니다."
    )
    return {
        "id": request_id,
        "object": "chat.completion",
        "created": int(time()),
        "model": "gateway-mock",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": safe_message},
                "finish_reason": "stop",
            }
        ],
    }


def build_gateway_chat_response(
    request_id: str, effective_prompt: str, model: str = "gateway-mock"
) -> dict[str, object]:
    """Build a minimal OpenAI-like chat completion response from an effective prompt."""
    return {
        "id": request_id,
        "object": "chat.completion",
        "created": int(time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": effective_prompt},
                "finish_reason": "stop",
            }
        ],
    }
