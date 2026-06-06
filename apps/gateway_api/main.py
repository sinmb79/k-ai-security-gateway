"""Optional FastAPI adapter for the gateway service.

The core MVP is dependency-free. If FastAPI is installed, run:

    uvicorn apps.gateway_api.main:app --reload
"""

from __future__ import annotations

import csv
import json
import os
import re
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from enum import Enum
from copy import deepcopy

from kai_security.approval.queue import (
    APPROVAL_STATUS_APPROVED,
    APPROVAL_STATUS_EXECUTING,
    APPROVAL_STATUS_INVALID_CONTEXT,
    ApprovalRequest,
)
from kai_security.detectors.pii import mask_token_for_label
from kai_security.evidence.sqlite_store import SQLiteEvidenceStore
from kai_security.gateway.service import GatewayService
from kai_security.model_router import ModelRoute, choose_approved_route, choose_route
from kai_security.models import AuditEvent, DataGrade, GatewayRequest, ModelZone, PolicyAction, RiskKind
from kai_security.openai_compat import (
    build_blocked_chat_response,
    extract_chat_prompt,
)
from kai_security.providers import resolve_provider_adapter
from kai_security.providers.errors import ProviderError, retryable_for_status
from kai_security.response_guard import guard_response_text, response_guard_event_payload
from kai_security.reports.generator import (
    generate_policy_report,
    generate_privacy_export_check,
    generate_request_evidence_package,
    summarize_audit_event,
)

try:
    from fastapi import FastAPI, Header, HTTPException
    from fastapi.responses import FileResponse, Response
    from fastapi.staticfiles import StaticFiles
except ModuleNotFoundError:  # pragma: no cover - import guard for dependency-free tests
    FastAPI = None  # type: ignore[assignment]
    Header = None  # type: ignore[assignment]
    HTTPException = None  # type: ignore[assignment]
    FileResponse = None  # type: ignore[assignment]
    Response = None  # type: ignore[assignment]
    StaticFiles = None  # type: ignore[assignment]


def create_gateway_service() -> GatewayService:
    db_path = os.environ.get("KAI_SECURITY_DB_PATH", "").strip()
    policy_path = os.environ.get("KAI_SECURITY_POLICY_PATH", "").strip() or None
    if db_path:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        return GatewayService(
            evidence_store=SQLiteEvidenceStore(db_path),
            policy_path=policy_path,
        )
    return GatewayService(policy_path=policy_path)


gateway = create_gateway_service()
_APPROVER_ROLES = {"admin", "security_manager", "approver"}
_PROVIDER_REQUEST_OPTION_KEYS = ("temperature", "max_tokens", "top_p", "response_format")
_MAX_AUDIT_EVENT_LIMIT = 1000
_MAX_AUDIT_EVENT_EXPORT_LIMIT = 5000
_DEFAULT_CHAIN_VERIFY_MAX_EVENTS = 50000
_DEFAULT_STALE_EXECUTION_TIMEOUT_SECONDS = 300.0
_MIN_STALE_EXECUTION_TIMEOUT_SECONDS = 60.0
_MAX_STALE_EXECUTION_RECOVERIES = 100
_STALE_EXECUTION_RECOVERY_REASONS = frozenset(
    {"execution_timeout", "process_restart", "operator_recovery"}
)
_STORED_CONTEXT_ERROR_KINDS = frozenset(
    {
        "missing_context",
        "unsupported_context_type",
        "invalid_route",
        "invalid_messages",
        "invalid_provider_options",
        "invalid_gateway_metadata",
        "invalid_prompt",
        "unknown_context_error",
    }
)
_APP_DIR = Path(__file__).resolve().parent
_STATIC_DIR = _APP_DIR / "static"
_PROVIDER_STATUS_RE = re.compile(r"provider request failed:\s+(?P<status>\d{3})")


def build_gateway_request(payload: dict[str, object]) -> GatewayRequest:
    raw_prompt = payload.get("prompt")
    if raw_prompt is None:
        raw_messages = payload.get("messages")
        if raw_messages is None:
            raise ValueError("Request payload must contain a prompt or messages field.")
        messages = _extract_messages(raw_messages)
        canonical_prompt = _extract_user_visible_prompt(messages)
        prompt = canonical_prompt
    else:
        prompt = str(raw_prompt)

    return GatewayRequest(
        prompt=prompt,
        user_id=str(payload.get("user_id", "anonymous")),
        department=str(payload.get("department", "unknown")),
        role=str(payload.get("role", "user")),
        requested_model=str(payload.get("requested_model", "default")),
        data_grade=_coerce_enum(DataGrade, payload.get("data_grade"), DataGrade.INTERNAL),
        model_zone=_coerce_enum(ModelZone, payload.get("model_zone"), ModelZone.EXTERNAL),
        metadata=dict(payload.get("metadata") or {}),
    )


def evaluate_chat_completion_payload(
    payload: dict[str, object],
    service: GatewayService | None = None,
) -> dict[str, object]:
    service = service or gateway
    model = str(payload.get("model", "gateway-mock"))
    messages = _extract_messages(payload)
    canonical_prompt = _extract_user_visible_prompt(messages)
    request_payload = dict(payload)
    request_payload["prompt"] = canonical_prompt
    request_payload["requested_model"] = model
    request = build_gateway_request(request_payload)
    evaluation = service.evaluate(request)
    route = choose_route(evaluation.decision, request.requested_model)
    gateway_security = {
        "request_id": request.request_id,
        "action": evaluation.decision.action.value,
        "policy_id": evaluation.decision.policy_id,
        "approval_id": evaluation.approval_id,
        "prompt_changed": evaluation.prompt_changed,
        "route": _route_payload(route),
    }
    safe_messages = _build_safe_provider_messages(
        action=evaluation.decision.action.value,
        canonical_prompt=canonical_prompt,
        effective_prompt=evaluation.effective_prompt,
    )
    provider_options = _extract_provider_request_options(payload)

    if evaluation.decision.action in {PolicyAction.BLOCK, PolicyAction.REQUIRE_APPROVAL}:
        if evaluation.decision.action == PolicyAction.REQUIRE_APPROVAL and evaluation.approval_id:
            approved_route = choose_approved_route(
                requested_model=request.requested_model,
                model_zone=request.model_zone,
                reason=f"approval:{evaluation.decision.policy_id}",
            )
            service.approval_queue.attach_context(
                evaluation.approval_id,
                {
                    "type": "chat_completion",
                    "request_id": request.request_id,
                    "model": approved_route.model,
                    "route": _route_payload(approved_route),
                    "messages": safe_messages,
                    "effective_prompt": evaluation.effective_prompt,
                    "provider_options": provider_options,
                    "gateway_security": {
                        **gateway_security,
                        "route": _route_payload(approved_route),
                        "approved_execution": True,
                    },
                },
            )
        response = build_blocked_chat_response(request.request_id, evaluation.decision.reason)
    else:
        if route is None:
            raise RuntimeError("expected route for non-blocking decision")
        adapter = resolve_provider_adapter(route)
        response = _validate_chat_completion_response(
            adapter.complete(
                request_id=request.request_id,
                model=route.model,
                messages=safe_messages,
                effective_prompt=evaluation.effective_prompt,
                gateway_security=gateway_security,
                provider_options=provider_options,
            )
        )
        response = _guard_chat_completion_response(
            response=response,
            request_id=request.request_id,
            service=service,
            gateway_security=gateway_security,
        )
    response["gateway_security"] = gateway_security
    return response


def evaluate_policy_simulation_payload(
    payload: dict[str, object],
    service: GatewayService | None = None,
) -> dict[str, object]:
    service = service or gateway
    request = build_gateway_request(payload)
    detection, decision, _effective_prompt, route = service.simulate(request)
    findings = [
        {
            "kind": finding.kind.value,
            "label": finding.label,
            "value": _safe_finding_value(finding),
            "start": finding.start,
            "end": finding.end,
            "confidence": finding.confidence,
            "severity": finding.severity,
        }
        for finding in detection.findings
    ]
    return {
        "request_id": request.request_id,
        "action": decision.action.value,
        "reason": decision.reason,
        "policy_id": decision.policy_id,
        "policy_version": decision.policy_version,
        "risk_score": decision.risk_score,
        "route": _route_payload(route),
        "finding_count": len(detection.findings),
        "findings": findings,
    }


def _safe_finding_value(finding) -> str:
    if getattr(finding, "kind", None) == RiskKind.KOREAN_PII:
        return mask_token_for_label(finding.label)
    return str(finding.value)


def _coerce_enum(enum_type, value: object, default):
    if value is None:
        return default
    return enum_type(str(value))


def _route_payload(route) -> dict[str, object] | None:
    if route is None:
        return None
    return {
        "provider": route.provider,
        "model": route.model,
        "zone": route.zone.value,
        "reason": route.reason,
    }


def _route_from_payload(payload: object) -> ModelRoute:
    if not isinstance(payload, dict):
        raise RuntimeError("stored approval route is invalid")
    try:
        provider = str(payload["provider"])
        model = str(payload["model"])
        zone = ModelZone(str(payload["zone"]))
        reason = str(payload["reason"])
    except (KeyError, ValueError) as exc:
        raise RuntimeError("stored approval route is invalid") from exc
    if not provider or not model or not reason:
        raise RuntimeError("stored approval route is invalid")
    return ModelRoute(provider=provider, model=model, zone=zone, reason=reason)


def _build_safe_provider_messages(
    *,
    action: str,
    canonical_prompt: str,
    effective_prompt: str,
) -> list[dict[str, object]]:
    if action == "mask":
        return [{"role": "user", "content": effective_prompt}]
    return [{"role": "user", "content": canonical_prompt}]


def _extract_provider_request_options(payload: dict[str, object]) -> dict[str, object]:
    return {
        key: deepcopy(payload[key])
        for key in _PROVIDER_REQUEST_OPTION_KEYS
        if key in payload
    }


def _validate_chat_completion_response(response: object) -> dict[str, object]:
    if not isinstance(response, dict):
        raise ProviderError(
            error_type="provider_invalid_response",
            retryable=False,
            safe_message="provider response has invalid JSON shape",
        )

    choices = response.get("choices")
    if not isinstance(choices, list) or len(choices) == 0:
        raise ProviderError(
            error_type="provider_invalid_response",
            retryable=False,
            safe_message="provider response has invalid JSON shape",
        )

    for choice in choices:
        if not isinstance(choice, dict):
            raise ProviderError(
                error_type="provider_invalid_response",
                retryable=False,
                safe_message="provider response has invalid JSON shape",
            )

        message = choice.get("message")
        if not isinstance(message, dict):
            raise ProviderError(
                error_type="provider_invalid_response",
                retryable=False,
                safe_message="provider response has invalid JSON shape",
            )

        if "tool_calls" in message or "function_call" in message:
            raise ProviderError(
                error_type="provider_invalid_response",
                retryable=False,
                safe_message="provider response has invalid JSON shape",
            )

        content = message.get("content")
        if not isinstance(content, str):
            raise ProviderError(
                error_type="provider_invalid_response",
                retryable=False,
                safe_message="provider response has invalid JSON shape",
            )

    return response


def _guard_chat_completion_response(
    *,
    response: dict[str, object],
    request_id: str,
    service: GatewayService,
    gateway_security: dict[str, object],
) -> dict[str, object]:
    guarded_response = deepcopy(response)
    aggregate_action = "allow"
    response_changed = False
    max_risk_score = 0.0
    finding_count = 0
    findings: list[object] = []
    choice_summaries: list[dict[str, object]] = []

    choices = guarded_response.get("choices")
    if not isinstance(choices, list):
        raise RuntimeError("provider response has invalid JSON shape")
    for choice in choices:
        if not isinstance(choice, dict):
            raise RuntimeError("provider response has invalid JSON shape")
        message = choice.get("message")
        if not isinstance(message, dict):
            raise RuntimeError("provider response has invalid JSON shape")
        content = message.get("content")
        if not isinstance(content, str):
            raise RuntimeError("provider response has invalid JSON shape")

        guard_result = guard_response_text(content)
        if guard_result.response_changed:
            message["content"] = guard_result.content
            response_changed = True
        if guard_result.action == "block":
            aggregate_action = "block"
        elif guard_result.action == "mask" and aggregate_action != "block":
            aggregate_action = "mask"
        max_risk_score = max(max_risk_score, guard_result.detection.risk_score)
        guard_payload = response_guard_event_payload(guard_result)
        finding_count += int(guard_payload["finding_count"])
        findings.extend(guard_payload["findings"])
        choice_summaries.append(
            {
                "index": choice.get("index"),
                "action": guard_result.action,
                "risk_score": guard_result.detection.risk_score,
                "finding_count": len(guard_result.detection.findings),
                "response_changed": guard_result.response_changed,
            }
        )

    payload = {
        "action": aggregate_action,
        "risk_score": max_risk_score,
        "finding_count": finding_count,
        "findings": findings,
        "choices": choice_summaries,
        "response_changed": response_changed,
    }
    gateway_security["response_guard"] = payload
    service.evidence_store.append(
        AuditEvent(
            event_type="response_analyzed",
            request_id=request_id,
            timestamp=datetime.now(UTC),
            payload=payload,
        )
    )
    return guarded_response


def _execute_approved_context(
    approval: ApprovalRequest,
    service: GatewayService,
    *,
    allow_executing: bool = False,
) -> dict[str, object] | None:
    if approval.context is None:
        raise _stored_approval_context_error("missing_context")
    if approval.status != APPROVAL_STATUS_APPROVED:
        if not (allow_executing and approval.status == APPROVAL_STATUS_EXECUTING):
            return None
    context = approval.context
    context_type = context.get("type")
    if context_type == "policy_evaluation":
        return None
    if context_type != "chat_completion":
        raise _stored_approval_context_error("unsupported_context_type")

    try:
        route = _route_from_payload(context.get("route"))
    except RuntimeError as exc:
        raise _stored_approval_context_error("invalid_route") from exc

    messages = context.get("messages")
    provider_options = context.get("provider_options")
    gateway_security = context.get("gateway_security")
    effective_prompt = context.get("effective_prompt")
    if not isinstance(messages, list):
        raise _stored_approval_context_error("invalid_messages")
    if not isinstance(provider_options, dict):
        raise _stored_approval_context_error("invalid_provider_options")
    if not isinstance(gateway_security, dict):
        raise _stored_approval_context_error("invalid_gateway_metadata")
    if not isinstance(effective_prompt, str):
        raise _stored_approval_context_error("invalid_prompt")

    execution_security = deepcopy(gateway_security)
    if approval.execution_attempt_id:
        execution_security["execution_attempt_id"] = approval.execution_attempt_id
        execution_security["idempotency_key"] = _approval_execution_idempotency_key(approval)
    adapter = resolve_provider_adapter(route)
    raw_response = adapter.complete(
        request_id=approval.request_id,
        model=route.model,
        messages=deepcopy(messages),
        effective_prompt=effective_prompt,
        gateway_security=execution_security,
        provider_options=deepcopy(provider_options),
    )
    if approval.execution_attempt_id:
        service.approval_queue.assert_execution_attempt(
            approval.approval_id,
            expected_execution_attempt_id=approval.execution_attempt_id,
        )
    response = _validate_chat_completion_response(raw_response)
    response = _guard_chat_completion_response(
        response=response,
        request_id=approval.request_id,
        service=service,
        gateway_security=execution_security,
    )

    response["gateway_security"] = execution_security
    return response


def _stored_approval_context_error(kind: str = "missing_context") -> ProviderError:
    normalized_kind = kind if kind in _STORED_CONTEXT_ERROR_KINDS else "unknown_context_error"
    return ProviderError(
        error_type="stored_approval_context_error",
        retryable=False,
        safe_message="stored approval context is invalid",
        metadata={"stored_context_error_kind": normalized_kind},
    )


def _approval_execution_idempotency_key(approval: ApprovalRequest) -> str:
    attempt_id = approval.execution_attempt_id or "manual"
    return f"kai-approval-{approval.approval_id}-{attempt_id}"


def _approval_completion_delivery(
    approval: ApprovalRequest,
    completion: dict[str, object],
) -> dict[str, object]:
    return {
        "mode": "approval_resolve_response",
        "approval_id": approval.approval_id,
        "request_id": approval.request_id,
        "original_client_callback": False,
    }


def _route_payload_from_approval_context(approval: ApprovalRequest) -> dict[str, object] | None:
    context = approval.context
    if not isinstance(context, dict):
        return None
    try:
        return _route_payload(_route_from_payload(context.get("route")))
    except RuntimeError:
        return None


def _failure_domain_for_error_type(error_type: str) -> str:
    if error_type == "stored_approval_context_error":
        return "gateway_state"
    if error_type == "gateway_runtime_error":
        return "gateway_runtime"
    if error_type == "approval_backend_error":
        return "approval_backend"
    if error_type == "provider_invalid_response":
        return "provider_response"
    if error_type in {"provider_timeout", "provider_http_error", "provider_runtime_error"}:
        return "provider_transport"
    return "unknown"


def _provider_error_summary(error: RuntimeError) -> dict[str, object]:
    if isinstance(error, ProviderError):
        payload: dict[str, object] = {
            "error_type": error.error_type,
            "failure_domain": _failure_domain_for_error_type(error.error_type),
            "provider_status_code": error.status_code,
            "retryable": error.retryable,
            "provider_error_body_sha256": error.body_sha256,
            "provider_error_body_truncated": error.body_truncated,
        }
        if error.metadata:
            for key in ("stored_context_error_kind",):
                if key in error.metadata:
                    payload[key] = error.metadata[key]
        return payload
    message = str(error).lower()
    match = _PROVIDER_STATUS_RE.search(str(error))
    status_code = int(match.group("status")) if match else None
    if "timeout" in message:
        error_type = "provider_timeout"
    elif "invalid json shape" in message:
        error_type = "provider_invalid_response"
    elif status_code is not None:
        error_type = "provider_http_error"
    else:
        error_type = "provider_runtime_error"
    retryable = False if error_type == "provider_invalid_response" else retryable_for_status(status_code)
    payload: dict[str, object] = {
        "error_type": error_type,
        "failure_domain": _failure_domain_for_error_type(error_type),
        "provider_status_code": status_code,
        "retryable": retryable,
        "provider_error_body_sha256": None,
        "provider_error_body_truncated": False,
    }
    return payload


def _append_approval_execution_failed_event(
    *,
    approval: ApprovalRequest,
    error: RuntimeError,
    service: GatewayService,
) -> None:
    error_summary = _provider_error_summary(error)
    route = _route_payload_from_approval_context(approval)
    payload = {
        "approval_id": approval.approval_id,
        "route": route,
        "status": "failed",
        "approval_status": approval.status,
        "provider_name": route.get("provider") if isinstance(route, dict) else None,
        "attempt_count": approval.attempt_count,
        "execution_attempt_id": approval.execution_attempt_id,
        "first_failed_at": approval.first_failed_at.isoformat()
        if approval.first_failed_at
        else None,
        "last_failed_at": approval.last_failed_at.isoformat() if approval.last_failed_at else None,
        **error_summary,
    }
    service.evidence_store.append(
        AuditEvent(
            event_type="approval_execution_failed",
            request_id=approval.request_id,
            timestamp=datetime.now(UTC),
            payload=payload,
        )
    )


def _approval_execution_error_reset_reason(payload: dict[str, object]) -> str:
    reason = str(payload.get("reason", "")).strip()
    if not reason:
        raise ValueError("reason is required")
    return reason


def _append_approval_execution_error_reset_event(
    *,
    approval: ApprovalRequest,
    previous_error_type: str | None,
    previous_retryable: bool | None,
    reason: str,
    service: GatewayService,
    reset_by: str,
    reset_by_role: str,
) -> None:
    route = _route_payload_from_approval_context(approval)
    service.evidence_store.append(
        AuditEvent(
            event_type="approval_execution_error_reset",
            request_id=approval.request_id,
            timestamp=datetime.now(UTC),
            payload={
                "approval_id": approval.approval_id,
                "route": route,
                "status": approval.status,
                "provider_name": route.get("provider") if isinstance(route, dict) else None,
                "attempt_count": approval.attempt_count,
                "previous_error_type": previous_error_type,
                "previous_retryable": previous_retryable,
                "retryable": approval.last_execution_retryable,
                "failure_domain": _failure_domain_for_error_type(previous_error_type or ""),
                "first_failed_at": approval.first_failed_at.isoformat()
                if approval.first_failed_at
                else None,
                "last_failed_at": approval.last_failed_at.isoformat()
                if approval.last_failed_at
                else None,
                "reason": reason,
                "reset_by": reset_by,
                "reset_by_role": reset_by_role,
                "auth_method": "admin_bearer_token",
            },
        )
    )


def _approval_error_action_required(error_type: str | None, retryable: bool | None) -> str | None:
    if error_type == "stored_approval_context_error":
        return "operator_review"
    if retryable is False:
        return "operator_review"
    if retryable is True:
        return "retry"
    return None


def _approval_resolution_mode(context_type: object, status: str) -> str:
    if status == APPROVAL_STATUS_INVALID_CONTEXT:
        return "invalid_context"
    if context_type == "chat_completion":
        return "provider_execution"
    if context_type == "policy_evaluation":
        return "policy_evaluation"
    if context_type is None:
        return "missing_context"
    return "unsupported_context"


def _stored_approval_context_http_detail(
    *,
    approval: ApprovalRequest,
    error: RuntimeError,
) -> dict[str, object]:
    error_summary = _provider_error_summary(error)
    return {
        "error": "stored_approval_context_error",
        "approval_id": approval.approval_id,
        "current_status": approval.status,
        "retryable": False,
        "action_required": "operator_review",
        "failure_domain": error_summary.get("failure_domain"),
        "stored_context_error_kind": error_summary.get("stored_context_error_kind"),
    }


def _append_approval_stale_recovered_event(
    *,
    approval: ApprovalRequest,
    reason: str,
    service: GatewayService,
    recovered_by: str,
    recovered_by_role: str,
) -> None:
    route = _route_payload_from_approval_context(approval)
    service.evidence_store.append(
        AuditEvent(
            event_type="approval_execution_stale_recovered",
            request_id=approval.request_id,
            timestamp=datetime.now(UTC),
            payload={
                "approval_id": approval.approval_id,
                "route": route,
                "status": "pending",
                "provider_name": route.get("provider") if isinstance(route, dict) else None,
                "attempt_count": approval.attempt_count,
                "stale_execution_attempt_id": approval.execution_attempt_id,
                "execution_started_at": approval.last_execution_started_at.isoformat()
                if approval.last_execution_started_at
                else None,
                "recovered_at": approval.last_failed_at.isoformat()
                if approval.last_failed_at
                else None,
                "first_failed_at": approval.first_failed_at.isoformat()
                if approval.first_failed_at
                else None,
                "last_failed_at": approval.last_failed_at.isoformat()
                if approval.last_failed_at
                else None,
                "reason": reason,
                "retryable": True,
                "recovered_by": recovered_by,
                "recovered_by_role": recovered_by_role,
                "auth_method": "admin_bearer_token",
            },
        )
    )


def _append_approval_attempt_conflict_event(
    *,
    approval: ApprovalRequest,
    expected_execution_attempt_id: str,
    current_approval: ApprovalRequest | None,
    service: GatewayService,
) -> None:
    route = _route_payload_from_approval_context(approval)
    current_status = current_approval.status if current_approval is not None else "missing"
    current_attempt_id = (
        current_approval.execution_attempt_id if current_approval is not None else None
    )
    service.evidence_store.append(
        AuditEvent(
            event_type="approval_execution_attempt_conflict",
            request_id=approval.request_id,
            timestamp=datetime.now(UTC),
            payload={
                "approval_id": approval.approval_id,
                "route": route,
                "status": "conflict",
                "provider_name": route.get("provider") if isinstance(route, dict) else None,
                "expected_execution_attempt_id": expected_execution_attempt_id,
                "current_execution_attempt_id": current_attempt_id,
                "current_status": current_status,
                "attempt_count": current_approval.attempt_count
                if current_approval is not None
                else approval.attempt_count,
                "reason": "approval execution attempt changed",
                "failure_domain": "approval_state_conflict",
                "retryable": False,
            },
        )
    )


def _approval_attempt_conflict_detail(
    *,
    approval: ApprovalRequest,
    expected_execution_attempt_id: str,
    current_approval: ApprovalRequest | None,
) -> dict[str, object]:
    return {
        "error": "approval execution attempt changed",
        "approval_id": approval.approval_id,
        "expected_execution_attempt_id": expected_execution_attempt_id,
        "current_execution_attempt_id": current_approval.execution_attempt_id
        if current_approval is not None
        else None,
        "current_status": current_approval.status if current_approval is not None else "missing",
    }


def _approval_attempt_conflict_exception(
    *,
    approval: ApprovalRequest,
    expected_execution_attempt_id: str,
    service: GatewayService,
):
    current_approval = service.approval_queue.get(approval.approval_id)
    _append_approval_attempt_conflict_event(
        approval=approval,
        expected_execution_attempt_id=expected_execution_attempt_id,
        current_approval=current_approval,
        service=service,
    )
    return HTTPException(
        status_code=409,
        detail=_approval_attempt_conflict_detail(
            approval=approval,
            expected_execution_attempt_id=expected_execution_attempt_id,
            current_approval=current_approval,
        ),
    )


def _append_approval_executed_event(
    *,
    approval: ApprovalRequest,
    completion: dict[str, object],
    service: GatewayService,
) -> None:
    gateway_security = completion.get("gateway_security")
    route = None
    response_guard = None
    if isinstance(gateway_security, dict):
        route = gateway_security.get("route")
        response_guard = gateway_security.get("response_guard")
    service.evidence_store.append(
        AuditEvent(
            event_type="approval_executed",
            request_id=approval.request_id,
            timestamp=datetime.now(UTC),
            payload={
                "approval_id": approval.approval_id,
                "route": route,
                "status": "executed",
                "attempt_count": approval.attempt_count,
                "execution_attempt_id": approval.execution_attempt_id,
                "response_guard": response_guard,
                "delivery": _approval_completion_delivery(approval, completion),
            },
        )
    )


def _coerce_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "y"}:
            return True
        if normalized in {"false", "0", "no", "n"}:
            return False
    raise ValueError(f"Invalid boolean value: {value!r}")


def _extract_messages(payload: object) -> list[dict[str, object]]:
    if isinstance(payload, dict):
        raw_messages = payload.get("messages")
    else:
        raw_messages = payload
    if not isinstance(raw_messages, list):
        raise ValueError("Request payload must contain a messages list.")
    if not raw_messages:
        raise ValueError("Request payload must contain a non-empty messages list.")
    messages: list[dict[str, object]] = []
    for message in raw_messages:
        if not isinstance(message, dict):
            raise ValueError("Each messages item must be a dict.")
        messages.append(message)
    return messages


def _extract_user_visible_prompt(messages: list[dict[str, object]]) -> str:
    user_messages = [message for message in messages if message.get("role") == "user"]
    if not user_messages:
        raise ValueError("Request payload must contain at least one user message.")
    return extract_chat_prompt({"messages": user_messages})


def _serialize_policy_for_admin(policy) -> dict[str, object]:
    when: dict[str, object] = {}
    for condition_key, condition_value in policy.when.items():
        if isinstance(condition_value, Enum):
            when[condition_key] = condition_value.value
        elif isinstance(condition_value, (list, tuple)):
            when[condition_key] = [
                item.value if isinstance(item, Enum) else item for item in condition_value
            ]
        else:
            when[condition_key] = condition_value
    return {
        "id": policy.id,
        "priority": policy.priority,
        "action": policy.action.value,
        "reason": policy.reason,
        "when": when,
        "route_model_zone": policy.route_model_zone.value
        if policy.route_model_zone is not None
        else None,
    }


def _parse_identity_tokens(raw: str) -> dict[str, tuple[str, str]]:
    """Parse token registry: token=identity:scope;other=identity:scope."""
    registry: dict[str, tuple[str, str]] = {}
    for entry in raw.split(";"):
        entry = entry.strip()
        if not entry:
            continue
        token, separator, identity = entry.partition("=")
        identity_id, scope_separator, scope = identity.partition(":")
        scope = scope.strip()
        identity_id = identity_id.strip()
        if not separator or not scope_separator:
            continue
        if token and identity_id and scope:
            registry[token.strip()] = (identity_id, scope)
    return registry


def _parse_approver_tokens(raw: str) -> dict[str, tuple[str, str]]:
    """Parse token registry: token=approver_id:role;other=approver_id:role."""
    return {
        token: (approver_id, role.lower())
        for token, (approver_id, role) in _parse_identity_tokens(raw).items()
        if role.lower() in _APPROVER_ROLES
    }


def _admin_token_registry() -> dict[str, tuple[str, str]]:
    return _parse_approver_tokens(os.environ.get("KAI_SECURITY_ADMIN_TOKENS", ""))


def _client_token_registry() -> dict[str, tuple[str, str]]:
    return _parse_identity_tokens(os.environ.get("KAI_SECURITY_CLIENT_TOKENS", ""))


def _extract_bearer_token(authorization: str | None) -> str:
    scheme, separator, credentials = (authorization or "").partition(" ")
    if separator and scheme.lower() == "bearer":
        return credentials.strip()
    return ""


def _extract_token(token: str | None = None, authorization: str | None = None) -> str:
    if token:
        return token.strip()
    if authorization:
        return _extract_bearer_token(authorization)
    return ""


def _require_admin(token: str | None = None, authorization: str | None = None) -> tuple[str, str]:
    registry = _admin_token_registry()
    candidate = _extract_token(token=token, authorization=authorization)
    if not candidate:
        raise PermissionError("admin bearer token is required")
    admin = registry.get(candidate)
    if admin is None:
        raise PermissionError("admin bearer token is not authorized")
    return admin


def _require_client(token: str | None = None, authorization: str | None = None) -> tuple[str, str]:
    registry = _client_token_registry()
    candidate = _extract_token(token=token, authorization=authorization)
    if not candidate:
        raise PermissionError("client bearer token is required")
    client = registry.get(candidate)
    if client is None:
        raise PermissionError("client bearer token is not authorized")
    return client


def _with_client_context(payload: dict[str, object], client: tuple[str, str]) -> dict[str, object]:
    client_id, department = client
    enriched = dict(payload)
    metadata = dict(enriched.get("metadata") or {})
    if "user_id" in enriched:
        metadata["client_supplied_user_id"] = str(enriched["user_id"])
    if "department" in enriched:
        metadata["client_supplied_department"] = str(enriched["department"])
    metadata["authenticated_client_id"] = client_id
    metadata["authenticated_client_department"] = department
    enriched["user_id"] = client_id
    enriched["department"] = department
    enriched["metadata"] = metadata
    return enriched


def _require_approver(
    payload: dict[str, object],
    token_registry: dict[str, tuple[str, str]] | None = None,
) -> tuple[str, str]:
    registry = token_registry
    if registry is None:
        registry = _parse_approver_tokens(os.environ.get("KAI_SECURITY_APPROVER_TOKENS", ""))
    token = str(payload.get("approval_token", "")).strip()
    if not token:
        raise PermissionError("approval_token is required")
    approver = registry.get(token)
    if approver is None:
        raise PermissionError("approval_token is not authorized")
    approver_id, approver_role = approver
    if approver_role not in _APPROVER_ROLES:
        raise PermissionError("approver role is not allowed to resolve approvals")
    return approver_id, approver_role


def _approval_payload(approval: ApprovalRequest) -> dict[str, object]:
    context_type = approval.context.get("type") if isinstance(approval.context, dict) else None
    resolution_mode = _approval_resolution_mode(context_type, approval.status)
    can_resolve = (
        approval.status == "pending"
        and approval.last_execution_retryable is not False
        and resolution_mode in {"provider_execution", "policy_evaluation"}
    )
    can_execute_provider = can_resolve and resolution_mode == "provider_execution"
    can_reject = approval.status in {"pending", APPROVAL_STATUS_INVALID_CONTEXT}
    recommended_action = _approval_error_action_required(
        approval.last_execution_error,
        approval.last_execution_retryable,
    )
    return {
        "approval_id": approval.approval_id,
        "request_id": approval.request_id,
        "requested_by": approval.requested_by,
        "reason": approval.reason,
        "action": approval.action,
        "created_at": approval.created_at.isoformat(),
        "status": approval.status,
        "resolved_by": approval.resolved_by,
        "resolved_at": approval.resolved_at.isoformat() if approval.resolved_at else None,
        "resolution_comment": approval.resolution_comment,
        "execution_attempt_id": approval.execution_attempt_id,
        "attempt_count": approval.attempt_count,
        "execution_started_at": approval.execution_started_at.isoformat()
        if approval.execution_started_at
        else None,
        "last_execution_started_at": approval.last_execution_started_at.isoformat()
        if approval.last_execution_started_at
        else None,
        "first_failed_at": approval.first_failed_at.isoformat() if approval.first_failed_at else None,
        "last_failed_at": approval.last_failed_at.isoformat() if approval.last_failed_at else None,
        "last_execution_error": approval.last_execution_error,
        "last_execution_retryable": approval.last_execution_retryable,
        "retryable": approval.last_execution_retryable,
        "recommended_action": recommended_action,
        "can_resolve": can_resolve,
        "can_execute_provider": can_execute_provider,
        "can_reject": can_reject,
        "resolution_mode": resolution_mode,
        "can_execute": can_resolve,
        "approval_context_type": context_type,
        "has_execution_context": context_type == "chat_completion",
    }


def _event_payload(event: AuditEvent) -> dict[str, object]:
    return {
        "event_id": event.event_id,
        "request_id": event.request_id,
        "timestamp": event.timestamp.isoformat(),
        "event_type": event.event_type,
        "payload": event.payload,
        "previous_hash": event.previous_hash,
        "event_hash": event.event_hash,
    }


def _parse_audit_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    raw = value.strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _payload_value(event: AuditEvent, key: str) -> str:
    value = event.payload.get(key)
    if value is None:
        return ""
    return str(value)


def _csv_safe_value(value: object) -> str:
    text = str(value or "")
    if text.startswith(("=", "+", "-", "@")):
        return f"'{text}"
    return text


def _query_audit_events(
    *,
    request_id: str | None = None,
    event_type: str | None = None,
    action: str | None = None,
    policy_id: str | None = None,
    from_timestamp: str | None = None,
    to_timestamp: str | None = None,
    order: str = "asc",
    limit: int | None = None,
    evidence_store: object,
) -> list[AuditEvent]:
    from_dt = _parse_audit_timestamp(from_timestamp)
    to_dt = _parse_audit_timestamp(to_timestamp)
    if from_dt is not None and to_dt is not None and from_dt > to_dt:
        raise ValueError("from_timestamp must be earlier than or equal to to_timestamp")
    normalized_order = order.strip().lower()
    if normalized_order not in {"asc", "desc"}:
        raise ValueError("order must be 'asc' or 'desc'")

    list_events = getattr(evidence_store, "list_events")
    events = list_events(request_id=request_id or None, event_type=event_type or None)
    action_filter = action.strip() if action else ""
    policy_filter = policy_id.strip() if policy_id else ""
    filtered: list[AuditEvent] = []
    for event in events:
        event_time = event.timestamp
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=UTC)
        event_time = event_time.astimezone(UTC)
        if from_dt is not None and event_time < from_dt:
            continue
        if to_dt is not None and event_time > to_dt:
            continue
        if action_filter and _payload_value(event, "action") != action_filter:
            continue
        if policy_filter and _payload_value(event, "policy_id") != policy_filter:
            continue
        filtered.append(event)

    if normalized_order == "desc":
        filtered.reverse()
    if limit is not None:
        return filtered[:limit]
    return filtered


def _validate_audit_event_limit(limit: int | None, *, max_limit: int) -> None:
    if limit is not None and limit <= 0:
        raise ValueError("limit must be a positive integer")
    if limit is not None and limit > max_limit:
        raise ValueError(f"limit must be less than or equal to {max_limit}")


def _audit_event_csv(events: list[AuditEvent]) -> str:
    output = StringIO()
    fieldnames = [
        "event_id",
        "request_id",
        "timestamp",
        "event_type",
        "action",
        "status",
        "policy_id",
        "approval_id",
        "risk_score",
        "finding_count",
        "event_hash",
        "previous_hash",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for event in events:
        writer.writerow(
            {
                "event_id": _csv_safe_value(event.event_id),
                "request_id": _csv_safe_value(event.request_id),
                "timestamp": _csv_safe_value(event.timestamp.isoformat()),
                "event_type": _csv_safe_value(event.event_type),
                "action": _csv_safe_value(_payload_value(event, "action")),
                "status": _csv_safe_value(_payload_value(event, "status")),
                "policy_id": _csv_safe_value(_payload_value(event, "policy_id")),
                "approval_id": _csv_safe_value(_payload_value(event, "approval_id")),
                "risk_score": _csv_safe_value(_payload_value(event, "risk_score")),
                "finding_count": _csv_safe_value(_payload_value(event, "finding_count")),
                "event_hash": _csv_safe_value(event.event_hash),
                "previous_hash": _csv_safe_value(event.previous_hash),
            }
        )
    return output.getvalue()


def _audit_event_jsonl(events: list[AuditEvent]) -> str:
    rows = [
        json.dumps(summarize_audit_event(event), ensure_ascii=False, sort_keys=True)
        for event in events
    ]
    return "\n".join(rows) + ("\n" if rows else "")


def _report_chain_verify_max_events() -> int:
    raw = os.environ.get(
        "KAI_SECURITY_REPORT_CHAIN_VERIFY_MAX_EVENTS",
        str(_DEFAULT_CHAIN_VERIFY_MAX_EVENTS),
    ).strip()
    if not raw:
        return _DEFAULT_CHAIN_VERIFY_MAX_EVENTS
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_CHAIN_VERIFY_MAX_EVENTS
    return max(0, value)


def _count_evidence_events(evidence_store: object) -> int:
    count_events = getattr(evidence_store, "count_events", None)
    if callable(count_events):
        return int(count_events())
    list_events = getattr(evidence_store, "list_events")
    return len(list_events())


def _chain_verification_report(evidence_store: object) -> tuple[bool | None, dict[str, object]]:
    event_count = _count_evidence_events(evidence_store)
    max_event_count = _report_chain_verify_max_events()
    if event_count > max_event_count:
        return None, {
            "status": "skipped",
            "event_count": event_count,
            "max_event_count": max_event_count,
            "reason": "chain verification skipped because event count exceeds configured report limit",
        }

    verified = bool(evidence_store.verify_chain())
    return verified, {
        "status": "verified" if verified else "failed",
        "event_count": event_count,
        "max_event_count": max_event_count,
    }


if FastAPI is not None:
    app = FastAPI(title="K-AI Security Gateway", version="0.1.10")
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    @app.get("/")
    def root() -> dict[str, str]:
        return {"name": "K-AI Security Gateway", "admin": "/admin", "docs": "/docs"}

    @app.get("/admin")
    def admin_dashboard():
        return FileResponse(str(_STATIC_DIR / "admin.html"))

    @app.post("/v1/security/evaluate")
    def evaluate(
        payload: dict[str, object],
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        try:
            client = _require_client(authorization=authorization)
            payload = _with_client_context(payload, client)
            request = build_gateway_request(payload)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        evaluation = gateway.evaluate(request)
        decision = evaluation.decision
        route = choose_route(decision, request.requested_model)
        return {
            "request_id": request.request_id,
            "action": decision.action.value,
            "reason": decision.reason,
            "policy_id": decision.policy_id,
            "policy_version": decision.policy_version,
            "risk_score": decision.risk_score,
            "prompt_changed": evaluation.prompt_changed,
            "approval_id": evaluation.approval_id,
            "route": _route_payload(route),
        }

    @app.get("/v1/policies")
    def list_policies(authorization: str | None = Header(default=None)) -> dict[str, object]:
        try:
            _require_admin(authorization=authorization)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        policy_set = gateway.policy_set
        return {
            "version": policy_set.version,
            "source": policy_set.source,
            "policy_count": len(policy_set.policies),
            "policies": [_serialize_policy_for_admin(policy) for policy in policy_set.policies],
        }

    @app.post("/v1/policies/simulate")
    def simulate_policy(payload: dict[str, object], authorization: str | None = Header(default=None)) -> dict[str, object]:
        try:
            _require_admin(authorization=authorization)
            return evaluate_policy_simulation_payload(payload)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/v1/chat/completions")
    def chat_completions(
        payload: dict[str, object],
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        try:
            client = _require_client(authorization=authorization)
            payload = _with_client_context(payload, client)
            return evaluate_chat_completion_payload(payload)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=502, detail="provider request failed") from exc

    @app.get("/v1/approvals/pending")
    def list_pending_approvals(authorization: str | None = Header(default=None)) -> list[dict[str, object]]:
        try:
            _require_admin(authorization=authorization)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return [_approval_payload(approval) for approval in gateway.approval_queue.list_pending()]

    @app.post("/v1/approvals/recover-stale")
    def recover_stale_approvals(
        payload: dict[str, object],
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        try:
            admin_id, admin_role = _require_admin(authorization=authorization)
            timeout_seconds = float(
                payload.get("timeout_seconds", _DEFAULT_STALE_EXECUTION_TIMEOUT_SECONDS)
            )
            force = _coerce_bool(payload.get("force", False))
            dry_run = _coerce_bool(payload.get("dry_run", False))
            limit = int(payload.get("limit", _MAX_STALE_EXECUTION_RECOVERIES))
            if limit <= 0 or limit > _MAX_STALE_EXECUTION_RECOVERIES:
                raise ValueError(f"limit must be between 1 and {_MAX_STALE_EXECUTION_RECOVERIES}")
            if timeout_seconds < _MIN_STALE_EXECUTION_TIMEOUT_SECONDS:
                raise ValueError(
                    f"timeout_seconds must be at least {_MIN_STALE_EXECUTION_TIMEOUT_SECONDS:g}"
                )
            if timeout_seconds < _DEFAULT_STALE_EXECUTION_TIMEOUT_SECONDS and not force:
                raise ValueError(
                    "force=true is required when timeout_seconds is below the default"
                )
            reason = str(payload.get("reason", "execution_timeout")).strip() or "execution_timeout"
            if reason not in _STALE_EXECUTION_RECOVERY_REASONS:
                allowed = ", ".join(sorted(_STALE_EXECUTION_RECOVERY_REASONS))
                raise ValueError(f"reason must be one of: {allowed}")
            matched = gateway.approval_queue.list_stale_executions(
                timeout_seconds=timeout_seconds,
                limit=limit,
            )
            recovered = (
                []
                if dry_run
                else gateway.approval_queue.recover_stale_executions(
                    timeout_seconds=timeout_seconds,
                    reason=reason,
                    limit=limit,
                )
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        for approval in recovered:
            _append_approval_stale_recovered_event(
                approval=approval,
                reason=reason,
                service=gateway,
                recovered_by=admin_id,
                recovered_by_role=admin_role,
            )
        return {
            "dry_run": dry_run,
            "matched_count": len(matched),
            "recovered_count": len(recovered),
            "skipped_count": len(matched) if dry_run else max(len(matched) - len(recovered), 0),
            "limit": limit,
            "approvals": [_approval_payload(approval) for approval in recovered],
            "matched_approvals": [_approval_payload(approval) for approval in matched]
            if dry_run
            else [],
        }

    @app.post("/v1/approvals/{approval_id}/reset-execution-error")
    def reset_approval_execution_error(
        approval_id: str,
        payload: dict[str, object],
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        try:
            admin_id, admin_role = _require_admin(authorization=authorization)
            reason = _approval_execution_error_reset_reason(payload)
            previous = gateway.approval_queue.get(approval_id)
            if previous is None:
                raise KeyError(f"Approval request not found: {approval_id}")
            previous_error_type = previous.last_execution_error
            previous_retryable = previous.last_execution_retryable
            approval = gateway.approval_queue.reset_execution_error(approval_id)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            status_code = 400 if str(exc) == "reason is required" else 409
            raise HTTPException(status_code=status_code, detail=str(exc)) from exc
        _append_approval_execution_error_reset_event(
            approval=approval,
            previous_error_type=previous_error_type,
            previous_retryable=previous_retryable,
            reason=reason,
            service=gateway,
            reset_by=admin_id,
            reset_by_role=admin_role,
        )
        return _approval_payload(approval)

    @app.post("/v1/approvals/{approval_id}/resolve")
    def resolve_approval(
        approval_id: str,
        payload: dict[str, object],
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        completion: dict[str, object] | None = None
        executing_approval: ApprovalRequest | None = None
        approved = False
        try:
            _require_admin(authorization=authorization)
            approved = _coerce_bool(payload.get("approved", False))
            approver_id, approver_role = _require_approver(payload)
            if approved:
                executing_approval = gateway.approval_queue.begin_execution(
                    approval_id,
                    resolved_by=approver_id,
                    comment=str(payload.get("comment", "")),
                )
                completion = _execute_approved_context(
                    executing_approval,
                    gateway,
                    allow_executing=True,
                )
            if approved:
                approval = gateway.approval_queue.finish_execution_success(
                    approval_id,
                    expected_execution_attempt_id=executing_approval.execution_attempt_id or "",
                    resolved_by=approver_id,
                    comment=str(payload.get("comment", "")),
                )
            else:
                approval = gateway.approval_queue.reject_pending(
                    approval_id,
                    resolved_by=approver_id,
                    comment=str(payload.get("comment", "")),
                )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            if approved and executing_approval is not None:
                raise _approval_attempt_conflict_exception(
                    approval=executing_approval,
                    expected_execution_attempt_id=executing_approval.execution_attempt_id or "",
                    service=gateway,
                ) from exc
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except RuntimeError as exc:
            if executing_approval is not None:
                error_summary = _provider_error_summary(exc)
                error_type = str(error_summary["error_type"])
                try:
                    failed_approval = gateway.approval_queue.fail_execution(
                        approval_id,
                        expected_execution_attempt_id=executing_approval.execution_attempt_id or "",
                        error_type=error_type,
                        retryable=bool(error_summary["retryable"]),
                        final_status=APPROVAL_STATUS_INVALID_CONTEXT
                        if error_type == "stored_approval_context_error"
                        else None,
                    )
                except ValueError as state_exc:
                    raise _approval_attempt_conflict_exception(
                        approval=executing_approval,
                        expected_execution_attempt_id=executing_approval.execution_attempt_id or "",
                        service=gateway,
                    ) from state_exc
                _append_approval_execution_failed_event(
                    approval=failed_approval,
                    error=exc,
                    service=gateway,
                )
                if error_type == "stored_approval_context_error":
                    raise HTTPException(
                        status_code=409,
                        detail=_stored_approval_context_http_detail(
                            approval=failed_approval,
                            error=exc,
                        ),
                    ) from exc
            raise HTTPException(status_code=502, detail="approved provider request failed") from exc
        gateway.evidence_store.append(
            AuditEvent(
                event_type="approval_resolved",
                request_id=approval.request_id,
                timestamp=datetime.now(UTC),
                payload={**_approval_payload(approval), "approver_role": approver_role},
            )
        )
        result = _approval_payload(approval)
        if completion is not None:
            _append_approval_executed_event(approval=approval, completion=completion, service=gateway)
            result["completion"] = completion
            result["completion_delivery"] = _approval_completion_delivery(approval, completion)
        return result

    @app.get("/v1/audit/events")
    def list_audit_events(
        request_id: str | None = None,
        event_type: str | None = None,
        action: str | None = None,
        policy_id: str | None = None,
        from_timestamp: str | None = None,
        to_timestamp: str | None = None,
        order: str = "asc",
        limit: int | None = None,
        authorization: str | None = Header(default=None),
    ) -> list[dict[str, object]]:
        try:
            _require_admin(authorization=authorization)
            _validate_audit_event_limit(limit, max_limit=_MAX_AUDIT_EVENT_LIMIT)
            events = _query_audit_events(
                request_id=request_id,
                event_type=event_type,
                action=action,
                policy_id=policy_id,
                from_timestamp=from_timestamp,
                to_timestamp=to_timestamp,
                order=order,
                limit=limit,
                evidence_store=gateway.evidence_store,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return [_event_payload(event) for event in events]

    @app.get("/v1/audit/events/export")
    def export_audit_events(
        request_id: str | None = None,
        event_type: str | None = None,
        action: str | None = None,
        policy_id: str | None = None,
        from_timestamp: str | None = None,
        to_timestamp: str | None = None,
        order: str = "asc",
        limit: int | None = None,
        format: str = "csv",
        authorization: str | None = Header(default=None),
    ):
        try:
            _require_admin(authorization=authorization)
            _validate_audit_event_limit(limit, max_limit=_MAX_AUDIT_EVENT_EXPORT_LIMIT)
            events = _query_audit_events(
                request_id=request_id,
                event_type=event_type,
                action=action,
                policy_id=policy_id,
                from_timestamp=from_timestamp,
                to_timestamp=to_timestamp,
                order=order,
                limit=limit,
                evidence_store=gateway.evidence_store,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        export_format = format.strip().lower()
        if export_format == "csv":
            body = _audit_event_csv(events)
            return Response(
                content=body,
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": 'attachment; filename="kai-audit-events.csv"'},
            )
        if export_format == "jsonl":
            body = _audit_event_jsonl(events)
            return Response(
                content=body,
                media_type="application/x-ndjson; charset=utf-8",
                headers={"Content-Disposition": 'attachment; filename="kai-audit-events.jsonl"'},
            )
        raise HTTPException(status_code=400, detail="format must be 'csv' or 'jsonl'")

    @app.get("/v1/reports/policy")
    def policy_report(authorization: str | None = Header(default=None)) -> dict[str, object]:
        try:
            _require_admin(authorization=authorization)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return generate_policy_report(gateway.evidence_store.list_events())

    @app.get("/v1/reports/privacy-export")
    def privacy_export_report(authorization: str | None = Header(default=None)) -> dict[str, object]:
        try:
            _require_admin(authorization=authorization)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return generate_privacy_export_check(gateway.evidence_store.list_events())

    @app.get("/v1/reports/evidence-package/{request_id}")
    def request_evidence_package_report(
        request_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        try:
            _require_admin(authorization=authorization)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        events = gateway.evidence_store.list_events(request_id=request_id)
        if not events:
            raise HTTPException(
                status_code=404,
                detail=f"request_id not found: {request_id}",
            )
        chain_verified, chain_verification = _chain_verification_report(gateway.evidence_store)
        report = generate_request_evidence_package(
            events,
            request_id=request_id,
            chain_verified=chain_verified,
        )
        report["chain_verification"] = chain_verification
        return report
else:
    app = None
