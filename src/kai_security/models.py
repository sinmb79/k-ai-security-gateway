"""Shared data contracts for gateway, detectors, policy, and evidence modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4


class DataGrade(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ModelZone(StrEnum):
    EXTERNAL = "external"
    DOMESTIC_SAAS = "domestic_saas"
    PRIVATE = "private"
    ON_PREM = "on_prem"


class PolicyAction(StrEnum):
    ALLOW = "allow"
    MASK = "mask"
    ROUTE_PRIVATE = "route_private"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"
    LOG_ONLY = "log_only"


class RiskKind(StrEnum):
    KOREAN_PII = "korean_pii"
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    DOCUMENT_RISK = "document_risk"


@dataclass(frozen=True)
class GatewayRequest:
    prompt: str
    user_id: str
    department: str = "unknown"
    role: str = "user"
    requested_model: str = "default"
    model_zone: ModelZone = ModelZone.EXTERNAL
    data_grade: DataGrade = DataGrade.INTERNAL
    metadata: dict[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class DetectionFinding:
    kind: RiskKind
    label: str
    value: str
    start: int
    end: int
    confidence: float
    severity: str = "medium"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DetectionResult:
    findings: tuple[DetectionFinding, ...] = ()
    risk_score: float = 0.0
    masked_text: str | None = None

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


@dataclass(frozen=True)
class PolicyDecision:
    action: PolicyAction
    reason: str
    policy_id: str
    policy_version: str
    risk_score: float
    route_model_zone: ModelZone | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GatewayEvaluation:
    request: GatewayRequest
    detection: DetectionResult
    decision: PolicyDecision
    effective_prompt: str
    approval_id: str | None = None

    @property
    def prompt_changed(self) -> bool:
        return self.effective_prompt != self.request.prompt


@dataclass(frozen=True)
class AuditEvent:
    event_type: str
    request_id: str
    timestamp: datetime
    payload: dict[str, Any]
    event_id: str = field(default_factory=lambda: str(uuid4()))
    previous_hash: str = ""
    event_hash: str = ""
