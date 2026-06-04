"""Korean PII detector.

This detector focuses on deterministic rules with strict check-digit validation where
available.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from kai_security.models import DetectionFinding, DetectionResult, RiskKind


_TOKEN_BY_LABEL = {
    "rrn": "[RRN]",
    "foreigner_rrn": "[RRN]",
    "phone": "[PHONE]",
    "email": "[EMAIL]",
    "card": "[CARD]",
    "business_no": "[BUSINESS_NO]",
}


@dataclass(frozen=True)
class _PatternSpec:
    label: str
    pattern: re.Pattern[str]
    validator: Callable[[str], bool] | None = None


def _digits_only(value: str) -> str:
    return "".join(ch for ch in value if ch.isdigit())


def _is_valid_rrn(value: str) -> bool:
    digits = _digits_only(value)
    if len(digits) != 13 or digits[6] not in "1234":
        return False
    yy = int(digits[:2])
    mm = int(digits[2:4])
    dd = int(digits[4:6])
    if not (1 <= mm <= 12):
        return False
    if dd < 1 or dd > 31:
        return False
    # Simple month-day validity check
    leap = yy % 4 == 0
    month_day_max = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if dd > month_day_max[mm - 1]:
        return False
    weights = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)
    checksum = sum(int(d) * w for d, w in zip(digits[:12], weights))
    expected = (11 - (checksum % 11)) % 10
    return expected == int(digits[-1])


def _is_valid_foreigner_rrn(value: str) -> bool:
    digits = _digits_only(value)
    if len(digits) != 13 or digits[6] not in "56789":
        return False
    weights = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5, 6)
    checksum = sum(int(d) * w for d, w in zip(digits[:12], weights))
    expected = (11 - (checksum % 11)) % 10
    return expected == int(digits[-1])


def _is_valid_business_no(value: str) -> bool:
    digits = _digits_only(value)
    if len(digits) != 10:
        return False
    weights = (1, 3, 7, 1, 3, 7, 1, 3)
    base = sum(int(d) * w for d, w in zip(digits[:8], weights))
    split_last = (int(digits[8]) * 5) // 10 + (int(digits[8]) * 5) % 10
    expected = (10 - ((base + split_last) % 10)) % 10
    return expected == int(digits[9])


def _is_valid_luhn(value: str) -> bool:
    digits = _digits_only(value)
    if len(digits) < 15 or len(digits) > 19:
        return False
    total = 0
    reverse = list(reversed(digits))
    for idx, ch in enumerate(reverse):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _is_valid_phone(value: str) -> bool:
    digits = _digits_only(value)
    if len(digits) not in (9, 10, 11):
        return False
    if digits.startswith("02"):
        return len(digits) in (9, 10)
    if any(digits.startswith(code) for code in ("010", "011", "016", "017", "018", "019")):
        return len(digits) in (10, 11)
    if digits.startswith(("03", "04", "05", "06", "07", "08", "09")):
        return len(digits) in (10, 11)
    return False


_RRN_PATTERN = re.compile(r"\b\d{6}-[1-4]\d{6}\b")
_RRN_PATTERN_NO_DASH = re.compile(r"\b\d{6}[1-4]\d{6}\b")
_FOREIGNER_PATTERN = re.compile(r"\b\d{6}-[5-9]\d{6}\b")
_EMAIL_PATTERN = re.compile(
    r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:\.[A-Za-z]{2,})?)\b",
    re.IGNORECASE,
)
_BUSINESS_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{5}\b")
_BUSINESS_PATTERN_NO_DASH = re.compile(r"\b\d{10}\b")
_PHONE_PATTERN = re.compile(r"(?<!\d)(?:\d{2,3}[- ]?\d{3,4}[- ]?\d{4})(?!\d)")
_CARD_PATTERN = re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b")
_CARD_PATTERN_ALT = re.compile(r"\b(?:\d{4}[- ]?\d{6}[- ]?\d{5})\b")
_CARD_PATTERN_NO_SEP = re.compile(r"\b\d{15,16}\b")

_PATTERNS = (
    _PatternSpec("rrn", _RRN_PATTERN, _is_valid_rrn),
    _PatternSpec("rrn", _RRN_PATTERN_NO_DASH, _is_valid_rrn),
    _PatternSpec("foreigner_rrn", _FOREIGNER_PATTERN, _is_valid_foreigner_rrn),
    _PatternSpec("phone", _PHONE_PATTERN, _is_valid_phone),
    _PatternSpec("email", _EMAIL_PATTERN),
    _PatternSpec("business_no", _BUSINESS_PATTERN, _is_valid_business_no),
    _PatternSpec("business_no", _BUSINESS_PATTERN_NO_DASH, _is_valid_business_no),
    _PatternSpec("card", _CARD_PATTERN, _is_valid_luhn),
    _PatternSpec("card", _CARD_PATTERN_ALT, _is_valid_luhn),
    _PatternSpec("card", _CARD_PATTERN_NO_SEP, _is_valid_luhn),
)


def _normalize_matches(text: str) -> list[tuple[int, int, str, str]]:
    matches: list[tuple[int, int, str, str]] = []
    for spec in _PATTERNS:
        for match in spec.pattern.finditer(text):
            value = match.group(0)
            digits_or_text = _digits_only(value) if spec.label != "email" else value
            if spec.validator and not spec.validator(value):
                continue
            if spec.label == "card" and spec.validator and not _is_valid_luhn(digits_or_text):
                continue
            if spec.label == "email" and "@" not in value:
                continue
            matches.append((match.start(), match.end(), spec.label, value))
    # Resolve overlaps by longest span to avoid duplicate masking/reports.
    matches.sort(key=lambda item: (item[0], -(item[1] - item[0])))
    filtered: list[tuple[int, int, str, str]] = []
    last_end = -1
    for start, end, label, value in matches:
        if start < last_end:
            continue
        filtered.append((start, end, label, value))
        last_end = end
    return filtered


def detect_korean_pii(text: str) -> DetectionResult:
    """Return Korean PII findings and a masked text variant."""
    matches = _normalize_matches(text)
    findings = []
    masked_text = text
    for start, end, label, value in reversed(matches):
        token = _TOKEN_BY_LABEL.get(label, f"[{label.upper()}]")
        masked_text = f"{masked_text[:start]}{token}{masked_text[end:]}"
        confidence = 0.98 if label in {"rrn", "foreigner_rrn", "card", "business_no"} else 0.9
        severity = "high" if label in {"rrn", "foreigner_rrn", "card", "business_no"} else "medium"
        findings.append(
            DetectionFinding(
                kind=RiskKind.KOREAN_PII,
                label=label,
                value=value,
                start=start,
                end=end,
                confidence=confidence,
                severity=severity,
            )
        )

    findings_tuple = tuple(findings)
    risk_score = min(1.0, len(findings_tuple) * 0.2)
    return DetectionResult(
        findings=findings_tuple,
        risk_score=risk_score,
        masked_text=masked_text,
    )
