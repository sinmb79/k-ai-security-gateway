"""Prompt-injection and data-exfiltration risk detector."""

from __future__ import annotations

import re

from kai_security.models import DetectionFinding, DetectionResult, RiskKind

_PROMPT_INJECTION_PATTERNS = [
    (re.compile(r"(?i)ignore\s+(all\s+)?previous\s+instructions"), "ignore_previous"),
    (re.compile(r"(?i)system\s+prompt"), "system_prompt_request"),
    (re.compile(r"이전\s*지시.*무시"), "ignore_previous_ko"),
    (re.compile(r"시스템\s*프롬프트"), "system_prompt_request_ko"),
    (re.compile(r"보안\s*정책.*우회"), "bypass_policy_ko"),
]

_EXFILTRATION_PATTERNS = [
    (re.compile(r"(?i)api[_\-\s]?key|secret|token|password"), "secret_request"),
    (re.compile(r"비밀키|인증토큰|접속정보|고객명단|내부문서"), "sensitive_export_ko"),
]


def detect_prompt_risk(text: str) -> DetectionResult:
    findings: list[DetectionFinding] = []
    for pattern, label in _PROMPT_INJECTION_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                DetectionFinding(
                    kind=RiskKind.PROMPT_INJECTION,
                    label=label,
                    value=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.8,
                    severity="high",
                )
            )
    for pattern, label in _EXFILTRATION_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                DetectionFinding(
                    kind=RiskKind.DATA_EXFILTRATION,
                    label=label,
                    value=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.75,
                    severity="high",
                )
            )
    risk_score = min(1.0, sum(0.35 for _ in findings))
    return DetectionResult(findings=tuple(findings), risk_score=risk_score, masked_text=text)

