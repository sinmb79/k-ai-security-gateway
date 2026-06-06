"""Model routing helpers for the MVP gateway."""

from __future__ import annotations

from dataclasses import dataclass

from kai_security.models import ModelZone, PolicyAction, PolicyDecision


@dataclass(frozen=True)
class ModelRoute:
    provider: str
    model: str
    zone: ModelZone
    reason: str


DEFAULT_MODEL_BY_ZONE = {
    ModelZone.EXTERNAL: ("external-openai-compatible", "gpt-compatible"),
    ModelZone.DOMESTIC_SAAS: ("domestic-saas", "korean-secure-model"),
    ModelZone.PRIVATE: ("private-llm", "private-default"),
    ModelZone.ON_PREM: ("on-prem-llm", "on-prem-default"),
}


def choose_route(decision: PolicyDecision, requested_model: str) -> ModelRoute | None:
    """Choose the model route after policy evaluation.

    `None` means the request must not be routed yet, such as block or approval.
    """
    if decision.action in {PolicyAction.BLOCK, PolicyAction.REQUIRE_APPROVAL}:
        return None
    zone = decision.route_model_zone or ModelZone.EXTERNAL
    return choose_approved_route(
        requested_model=requested_model,
        model_zone=zone,
        reason=f"policy:{decision.policy_id}",
    )


def choose_approved_route(
    *,
    requested_model: str,
    model_zone: ModelZone,
    reason: str,
) -> ModelRoute:
    """Choose a provider route after a human approval has released the request."""
    zone = model_zone
    provider, default_model = DEFAULT_MODEL_BY_ZONE[zone]
    return ModelRoute(
        provider=provider,
        model=requested_model if zone == ModelZone.EXTERNAL else default_model,
        zone=zone,
        reason=reason,
    )

