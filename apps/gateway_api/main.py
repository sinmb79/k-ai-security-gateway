"""Optional FastAPI adapter for the gateway service.

The core MVP is dependency-free. If FastAPI is installed, run:

    uvicorn apps.gateway_api.main:app --reload
"""

from __future__ import annotations

from kai_security.gateway.service import GatewayService
from kai_security.model_router import choose_route
from kai_security.models import DataGrade, GatewayRequest, ModelZone

try:
    from fastapi import FastAPI, HTTPException
except ModuleNotFoundError:  # pragma: no cover - import guard for dependency-free tests
    FastAPI = None  # type: ignore[assignment]
    HTTPException = None  # type: ignore[assignment]


gateway = GatewayService()


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

if FastAPI is not None:
    app = FastAPI(title="K-AI Security Gateway", version="0.1.0")

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
            "route": _route_payload(route),
        }
else:
    app = None
