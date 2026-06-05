"""Post-model response safety guard."""

from __future__ import annotations

import re
from dataclasses import dataclass

from kai_security.detectors.document_risk import detect_document_risk
from kai_security.detectors.pii import detect_korean_pii
from kai_security.detectors.prompt_risk import detect_prompt_risk
from kai_security.models import DetectionResult, RiskKind

_SAFE_BLOCKED_RESPONSE = (
    "\ubaa8\ub378 \uc751\ub2f5\uc740 \ubcf4\uc548 \uc815\ucc45\uc5d0 \uc758\ud574 "
    "\ud45c\uc2dc\ub418\uc9c0 \uc54a\uc2b5\ub2c8\ub2e4. \ubbfc\uac10\ud55c "
    "\ub0b4\uc6a9\uc740 \uad00\ub9ac\uc790 \uac80\ud1a0\uac00 \ud544\uc694\ud569\ub2c8\ub2e4."
)
_BLOCKING_RISK_THRESHOLD = 0.7
_KOREAN_SECRET_TERMS = (
    "(?:\ube44\ubc00\ubc88\ud638|\uc778\uc99d\ud1a0\ud070|\ube44\ubc00\ud0a4)"
)
_KOREAN_SECRET_CONNECTORS = "(?:\uc740|\ub294|=|:)"
_SECRET_VALUE_PATTERNS = (
    re.compile(
        r"(?i)\b(?:api[_\-\s]?key|secret|token|password|passwd|pwd)\s*(?:is|=|:)\s*"
        r"['\"]?[A-Za-z0-9_./+=:@\-]{8,}['\"]?"
    ),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:ghp|github_pat|xox[baprs])_[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(
        _KOREAN_SECRET_TERMS
        + r"\s*"
        + _KOREAN_SECRET_CONNECTORS
        + r"\s*[A-Za-z0-9_./+=:@\-]{8,}"
    ),
)


@dataclass(frozen=True)
class ResponseGuardResult:
    action: str
    content: str
    response_changed: bool
    detection: DetectionResult


def guard_response_text(text: str) -> ResponseGuardResult:
    """Mask or block unsafe assistant response text without retaining the raw text."""
    pii = detect_korean_pii(text)
    prompt_risk = detect_prompt_risk(text)
    document_risk = detect_document_risk(text)
    detection = _combine_detection_results(pii, prompt_risk, document_risk)

    if _requires_block(text, detection):
        return ResponseGuardResult(
            action="block",
            content=_SAFE_BLOCKED_RESPONSE,
            response_changed=True,
            detection=detection,
        )
    if pii.has_findings and pii.masked_text is not None and pii.masked_text != text:
        return ResponseGuardResult(
            action="mask",
            content=pii.masked_text,
            response_changed=True,
            detection=detection,
        )
    return ResponseGuardResult(
        action="allow",
        content=text,
        response_changed=False,
        detection=detection,
    )


def response_guard_event_payload(result: ResponseGuardResult) -> dict[str, object]:
    """Return audit-safe response guard metadata."""
    return {
        "action": result.action,
        "risk_score": result.detection.risk_score,
        "finding_count": len(result.detection.findings),
        "findings": [
            {
                "kind": finding.kind.value,
                "label": finding.label,
                "severity": finding.severity,
                "confidence": finding.confidence,
            }
            for finding in result.detection.findings
        ],
        "response_changed": result.response_changed,
    }


def _combine_detection_results(*results: DetectionResult) -> DetectionResult:
    findings = tuple(finding for result in results for finding in result.findings)
    risk_score = min(1.0, sum(result.risk_score for result in results))
    return DetectionResult(findings=findings, risk_score=risk_score)


def _requires_block(text: str, detection: DetectionResult) -> bool:
    if _contains_secret_value(text):
        return True
    instruction_kinds = {RiskKind.PROMPT_INJECTION, RiskKind.DOCUMENT_RISK}
    has_instruction_risk = any(finding.kind in instruction_kinds for finding in detection.findings)
    return has_instruction_risk and detection.risk_score >= _BLOCKING_RISK_THRESHOLD


def _contains_secret_value(text: str) -> bool:
    return any(pattern.search(text) for pattern in _SECRET_VALUE_PATTERNS)
