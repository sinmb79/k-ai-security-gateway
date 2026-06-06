"""Provider error types with audit-safe metadata."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderError(RuntimeError):
    error_type: str
    safe_message: str
    status_code: int | None = None
    retryable: bool = True
    body_sha256: str | None = None

    def __str__(self) -> str:
        return self.safe_message


def retryable_for_status(status_code: int | None) -> bool:
    if status_code is None:
        return True
    if status_code in {408, 409, 425, 429}:
        return True
    if 500 <= status_code <= 599:
        return True
    return False
