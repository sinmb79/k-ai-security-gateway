"""Optional FastAPI adapter for the gateway service.

The core MVP is dependency-free. If FastAPI is installed, run:

    uvicorn apps.gateway_api.main:app --reload
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from enum import Enum
from copy import deepcopy

from kai_security.approval.queue import ApprovalRequest
from kai_security.evidence.sqlite_store import SQLiteEvidenceStore
from kai_security.gateway.service import GatewayService
from kai_security.model_router import choose_route
from kai_security.models import AuditEvent, DataGrade, GatewayRequest, ModelZone, PolicyAction
from kai_security.openai_compat import (
    build_blocked_chat_response,
    extract_chat_prompt,
)
from kai_security.providers import resolve_provider_adapter
from kai_security.response_guard import guard_response_text, response_guard_event_payload
from kai_security.reports.generator import (
    generate_policy_report,
    generate_privacy_export_check,
    generate_request_evidence_package,
)

try:
    from fastapi import FastAPI, Header, HTTPException
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles
except ModuleNotFoundError:  # pragma: no cover - import guard for dependency-free tests
    FastAPI = None  # type: ignore[assignment]
    Header = None  # type: ignore[assignment]
    HTTPException = None  # type: ignore[assignment]
    FileResponse = None  # type: ignore[assignment]
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
_MAX_AUDIT_EVENT_LIMIT = 1000
_DEFAULT_CHAIN_VERIFY_MAX_EVENTS = 50000
_APP_DIR = Path(__file__).resolve().parent
_STATIC_DIR = _APP_DIR / "static"


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

    if evaluation.decision.action in {PolicyAction.BLOCK, PolicyAction.REQUIRE_APPROVAL}:
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
            "value": finding.value,
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


def _build_safe_provider_messages(
    *,
    action: str,
    canonical_prompt: str,
    effective_prompt: str,
) -> list[dict[str, object]]:
    if action == "mask":
        return [{"role": "user", "content": effective_prompt}]
    return [{"role": "user", "content": canonical_prompt}]


def _validate_chat_completion_response(response: object) -> dict[str, object]:
    if not isinstance(response, dict):
        raise RuntimeError("provider response has invalid JSON shape")

    choices = response.get("choices")
    if not isinstance(choices, list) or len(choices) == 0:
        raise RuntimeError("provider response has invalid JSON shape")

    for choice in choices:
        if not isinstance(choice, dict):
            raise RuntimeError("provider response has invalid JSON shape")

        message = choice.get("message")
        if not isinstance(message, dict):
            raise RuntimeError("provider response has invalid JSON shape")

        if "tool_calls" in message or "function_call" in message:
            raise RuntimeError("provider response has invalid JSON shape")

        content = message.get("content")
        if not isinstance(content, str):
            raise RuntimeError("provider response has invalid JSON shape")

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


def _parse_approver_tokens(raw: str) -> dict[str, tuple[str, str]]:
    """Parse token registry: token=approver_id:role;other=approver_id:role."""
    registry: dict[str, tuple[str, str]] = {}
    for entry in raw.split(";"):
        entry = entry.strip()
        if not entry:
            continue
        token, separator, identity = entry.partition("=")
        approver_id, role_separator, approver_role = identity.partition(":")
        if not separator or not role_separator:
            continue
        approver_role = approver_role.strip().lower()
        if token and approver_id and approver_role in _APPROVER_ROLES:
            registry[token.strip()] = (approver_id.strip(), approver_role)
    return registry


def _admin_token_registry() -> dict[str, tuple[str, str]]:
    return _parse_approver_tokens(os.environ.get("KAI_SECURITY_ADMIN_TOKENS", ""))


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
    app = FastAPI(title="K-AI Security Gateway", version="0.1.0")
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    @app.get("/")
    def root() -> dict[str, str]:
        return {"name": "K-AI Security Gateway", "admin": "/admin", "docs": "/docs"}

    @app.get("/admin")
    def admin_dashboard():
        return FileResponse(str(_STATIC_DIR / "admin.html"))

    @app.post("/v1/security/evaluate")
    def evaluate(payload: dict[str, object]) -> dict[str, object]:
        try:
            request = build_gateway_request(payload)
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
    def chat_completions(payload: dict[str, object]) -> dict[str, object]:
        try:
            return evaluate_chat_completion_payload(payload)
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

    @app.post("/v1/approvals/{approval_id}/resolve")
    def resolve_approval(
        approval_id: str,
        payload: dict[str, object],
        authorization: str | None = Header(default=None),
    ) -> dict[str, object]:
        try:
            _require_admin(authorization=authorization)
            approved = _coerce_bool(payload.get("approved", False))
            approver_id, approver_role = _require_approver(payload)
            approval = gateway.approval_queue.resolve(
                approval_id=approval_id,
                approved=approved,
                resolved_by=approver_id,
                comment=str(payload.get("comment", "")),
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        gateway.evidence_store.append(
            AuditEvent(
                event_type="approval_resolved",
                request_id=approval.request_id,
                timestamp=datetime.now(UTC),
                payload={**_approval_payload(approval), "approver_role": approver_role},
            )
        )
        return _approval_payload(approval)

    @app.get("/v1/audit/events")
    def list_audit_events(
        request_id: str | None = None,
        event_type: str | None = None,
        limit: int | None = None,
        authorization: str | None = Header(default=None),
    ) -> list[dict[str, object]]:
        try:
            _require_admin(authorization=authorization)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        if limit is not None and limit <= 0:
            raise HTTPException(status_code=400, detail="limit must be a positive integer")
        if limit is not None and limit > _MAX_AUDIT_EVENT_LIMIT:
            raise HTTPException(
                status_code=400,
                detail=f"limit must be less than or equal to {_MAX_AUDIT_EVENT_LIMIT}",
            )
        return [
            _event_payload(event)
            for event in gateway.evidence_store.list_events(
                request_id=request_id, event_type=event_type, limit=limit
            )
        ]

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
