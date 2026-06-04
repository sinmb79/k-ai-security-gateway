"""Optional FastAPI adapter for the gateway service.

The core MVP is dependency-free. If FastAPI is installed, run:

    uvicorn apps.gateway_api.main:app --reload
"""

from __future__ import annotations

from kai_security.gateway.service import GatewayService
from kai_security.models import GatewayRequest

try:
    from fastapi import FastAPI
except ModuleNotFoundError:  # pragma: no cover - import guard for dependency-free tests
    FastAPI = None  # type: ignore[assignment]


gateway = GatewayService()

if FastAPI is not None:
    app = FastAPI(title="K-AI Security Gateway", version="0.1.0")

    @app.post("/v1/security/evaluate")
    def evaluate(payload: dict[str, object]) -> dict[str, object]:
        request = GatewayRequest(
            prompt=str(payload.get("prompt", "")),
            user_id=str(payload.get("user_id", "anonymous")),
            department=str(payload.get("department", "unknown")),
            requested_model=str(payload.get("requested_model", "default")),
        )
        decision = gateway.evaluate(request)
        return {
            "request_id": request.request_id,
            "action": decision.action.value,
            "reason": decision.reason,
            "policy_id": decision.policy_id,
            "policy_version": decision.policy_version,
            "risk_score": decision.risk_score,
        }
else:
    app = None

