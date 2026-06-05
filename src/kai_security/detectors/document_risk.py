"""Document/RAG risk detector for hidden instructions and tool exfiltration cues."""

from __future__ import annotations

import re

from kai_security.models import DetectionFinding, DetectionResult, RiskKind


_DOCUMENT_RISK_PATTERNS: tuple[tuple[re.Pattern[str], str, float, str], ...] = (
    (
        re.compile(
            r"(?i)\b(ignore|override|bypass)\s+"
            r"(previous|prior|above|user|system|developer|security)\s+"
            r"(instructions?|polic(?:y|ies)|rules?)\b"
        ),
        "embedded_instruction",
        0.82,
        "high",
    ),
    (
        re.compile(
            r"(AI|모델|에이전트|LLM|챗봇)[\s\S]{0,20}"
            r"(이전|사용자|시스템|보안)\s*(지시|정책|규칙)[\s\S]{0,24}"
            r"(무시|우회|덮어써)"
        ),
        "embedded_instruction_ko",
        0.82,
        "high",
    ),
    (
        re.compile(
            r"(?i)((reveal|print|show|expose|leak|return|display)\s+(the\s+)?"
            r"(system\s+prompt|developer\s+message|hidden\s+instruction)|"
            r"(system\s+prompt|developer\s+message|hidden\s+instruction).{0,32}"
            r"(reveal|print|show|expose|leak|return|display))"
        ),
        "system_prompt_exposure",
        0.78,
        "high",
    ),
    (
        re.compile(
            r"((시스템\s*프롬프트|개발자\s*메시지|숨겨진\s*지시)[\s\S]{0,32}"
            r"(출력|공개|노출|보여|반환)|"
            r"(출력|공개|노출|보여|반환)[\s\S]{0,32}"
            r"(시스템\s*프롬프트|개발자\s*메시지|숨겨진\s*지시))"
        ),
        "system_prompt_exposure_ko",
        0.78,
        "high",
    ),
    (
        re.compile(
            r"(?i)(call|invoke|run|execute)\s+[\w.-]*(export|dump|send|exfil|upload)[\w.-]*"
            r"[\w\s,.:;/-]{0,80}\b(customer|records?|database|secrets?|tokens?|credentials?)\b"
        ),
        "tool_exfiltration",
        0.86,
        "high",
    ),
    (
        re.compile(r"(도구|함수|플러그인)[\s\S]{0,18}(호출|실행)[\s\S]{0,28}(내보내|전송|업로드|추출)"),
        "tool_exfiltration_ko",
        0.86,
        "high",
    ),
    (
        re.compile(r"(?i)(rag|retrieval|document)\s+(poison|override|instruction|payload)"),
        "rag_poisoning",
        0.72,
        "medium",
    ),
    (
        re.compile(r"(문서|검색|RAG|검색증강)[\s\S]{0,18}(오염|페이로드|숨겨진\s*지시|간접\s*지시)"),
        "rag_poisoning_ko",
        0.72,
        "medium",
    ),
)


def detect_document_risk(text: str) -> DetectionResult:
    """Return document/RAG hidden-instruction risk findings."""
    findings: list[DetectionFinding] = []
    for pattern, label, confidence, severity in _DOCUMENT_RISK_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                DetectionFinding(
                    kind=RiskKind.DOCUMENT_RISK,
                    label=label,
                    value=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    confidence=confidence,
                    severity=severity,
                )
            )

    deduped = _dedupe_findings(findings)
    risk_score = _risk_score(deduped)
    return DetectionResult(findings=tuple(deduped), risk_score=risk_score, masked_text=text)


def _dedupe_findings(findings: list[DetectionFinding]) -> list[DetectionFinding]:
    seen: set[tuple[str, int, int, str]] = set()
    deduped: list[DetectionFinding] = []
    for finding in findings:
        key = (finding.label, finding.start, finding.end, finding.value.lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _risk_score(findings: list[DetectionFinding]) -> float:
    if not findings:
        return 0.0
    high_count = sum(1 for finding in findings if finding.severity == "high")
    medium_count = len(findings) - high_count
    return min(1.0, high_count * 0.4 + medium_count * 0.2)
