"""Korean PII detector.

Worker-owned implementation target.
"""

from __future__ import annotations

from kai_security.models import DetectionResult


def detect_korean_pii(text: str) -> DetectionResult:
    """Return Korean PII findings and a masked text variant."""
    return DetectionResult(findings=(), risk_score=0.0, masked_text=text)

