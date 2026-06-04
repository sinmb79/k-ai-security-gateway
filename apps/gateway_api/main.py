"""Optional FastAPI adapter for the gateway service.

The core MVP is dependency-free. If FastAPI is installed, run:

    uvicorn apps.gateway_api.main:app --reload
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

from kai_security.approval.queue import ApprovalRequest
from kai_security.evidence.sqlite_store import SQLiteEvidenceStore
from kai_security.gateway.service import GatewayService
from kai_security.model_router import choose_route
from kai_security.models import AuditEvent, DataGrade, GatewayRequest, ModelZone, PolicyAction
from kai_security.openai_compat import (
    build_blocked_chat_response,
    build_gateway_chat_response,
    extract_chat_prompt,
)
from kai_security.reports.generator import generate_policy_report, generate_privacy_export_check

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
    if db_path:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        return GatewayService(evidence_store=SQLiteEvidenceStore(db_path))
    return GatewayService()


gateway = create_gateway_service()
_APPROVER_ROLES = {"admin", "security_manager", "approver"}
_APP_DIR = Path(__file__).resolve().parent
_STATIC_DIR = _APP_DIR / "static"


def build_gateway_request(payload: dict[str, object]) -> GatewayRequest:
    return GatewayRequest(
        prompt=str(payload.get("prompt", "")),
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
    request_payload = dict(payload)
    request_payload["prompt"] = extract_chat_prompt(payload)
    request_payload["requested_model"] = model
    request = build_gateway_request(request_payload)
    evaluation = service.evaluate(request)
    route = choose_route(evaluation.decision, request.requested_model)
    if evaluation.decision.action in {PolicyAction.BLOCK, PolicyAction.REQUIRE_APPROVAL}:
        response = build_blocked_chat_response(request.request_id, evaluation.decision.reason)
    else:
        response = build_gateway_chat_response(
            request.request_id,
            evaluation.effective_prompt,
            model=model,
        )
    response["gateway_security"] = {
        "request_id": request.request_id,
        "action": evaluation.decision.action.value,
        "policy_id": evaluation.decision.policy_id,
        "approval_id": evaluation.approval_id,
        "prompt_changed": evaluation.prompt_changed,
        "route": _route_payload(route),
    }
    return response


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
            "effective_prompt": evaluation.effective_prompt,
            "prompt_changed": evaluation.prompt_changed,
            "approval_id": evaluation.approval_id,
            "route": _route_payload(route),
        }

    @app.post("/v1/chat/completions")
    def chat_completions(payload: dict[str, object]) -> dict[str, object]:
        try:
            return evaluate_chat_completion_payload(payload)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

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
        authorization: str | None = Header(default=None),
    ) -> list[dict[str, object]]:
        try:
            _require_admin(authorization=authorization)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return [_event_payload(event) for event in gateway.evidence_store.list_events(request_id)]

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
else:
    app = None
