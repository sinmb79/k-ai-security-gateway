import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from kai_security.models import (
    DataGrade,
    DetectionFinding,
    DetectionResult,
    GatewayRequest,
    ModelZone,
    RiskKind,
)
from kai_security.policy.dsl import (
    load_policy_set,
    load_policy_set_from_path,
    default_policy_set,
)
from kai_security.policy.engine import decide_policy


class PolicyDslLoaderTests(unittest.TestCase):
    def test_load_json_compatible_yaml_file(self) -> None:
        payload = {
            "version": "0.2.0",
            "policies": [
                {
                    "id": "policy-001-block-prompt-injection",
                    "priority": 10,
                    "when": {"finding_kinds_any": ["prompt_injection"]},
                    "action": "block",
                    "reason": "prompt injection detected",
                }
            ],
        }

        with TemporaryDirectory() as tempdir:
            policy_path = Path(tempdir) / "policy.yaml"
            policy_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            policy_set = load_policy_set(str(policy_path))

        self.assertEqual(policy_set.version, "0.2.0")
        self.assertEqual(policy_set.source, str(policy_path))
        self.assertEqual(len(policy_set.policies), 1)
        self.assertEqual(policy_set.policies[0].id, "policy-001-block-prompt-injection")

    def test_missing_policy_path_uses_default_policy_set(self) -> None:
        self.assertEqual(load_policy_set(None).version, default_policy_set().version)
        self.assertEqual(load_policy_set("").version, default_policy_set().version)
        self.assertEqual(load_policy_set("no-such-policy.json").version, default_policy_set().version)

    def test_existing_invalid_policy_file_raises(self) -> None:
        with TemporaryDirectory() as tempdir:
            policy_path = Path(tempdir) / "broken-policy.json"
            policy_path.write_text("{broken json", encoding="utf-8")

            with self.assertRaises(ValueError):
                load_policy_set(str(policy_path))

    def test_bool_values_are_not_accepted_as_numeric_policy_fields(self) -> None:
        invalid_payloads = [
            {
                "version": "0.2.0",
                "policies": [
                    {
                        "id": "policy-bool-priority",
                        "priority": True,
                        "when": {"no_findings": True},
                        "action": "allow",
                    }
                ],
            },
            {
                "version": "0.2.0",
                "policies": [
                    {
                        "id": "policy-bool-score",
                        "priority": 10,
                        "when": {"min_risk_score": True},
                        "action": "block",
                    }
                ],
            },
        ]

        with TemporaryDirectory() as tempdir:
            for index, payload in enumerate(invalid_payloads):
                policy_path = Path(tempdir) / f"invalid-{index}.json"
                policy_path.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_policy_set_from_path(policy_path)

    def test_finding_kinds_none_condition_is_loaded(self) -> None:
        payload = {
            "version": "0.2.0",
            "policies": [
                {
                    "id": "policy-no-pii-threshold",
                    "priority": 10,
                    "when": {
                        "min_risk_score": 0.85,
                        "finding_kinds_none": ["korean_pii"],
                    },
                    "action": "block",
                    "reason": "high risk without pii",
                }
            ],
        }

        with TemporaryDirectory() as tempdir:
            policy_path = Path(tempdir) / "policy.json"
            policy_path.write_text(json.dumps(payload), encoding="utf-8")
            policy_set = load_policy_set(str(policy_path))

        self.assertEqual(
            policy_set.policies[0].when["finding_kinds_none"],
            (RiskKind.KOREAN_PII,),
        )

    def test_repo_default_policy_file_preserves_built_in_rule_coverage(self) -> None:
        policy_path = Path(__file__).resolve().parents[1] / "policies" / "default.yaml"
        policy_set = load_policy_set_from_path(policy_path)
        built_in = default_policy_set()

        self.assertEqual(policy_set.version, built_in.version)
        self.assertEqual(
            [policy.id for policy in policy_set.policies],
            [policy.id for policy in built_in.policies],
        )

        pii_decision = decide_policy(
            GatewayRequest(prompt="010-1111-2222", user_id="alice"),
            DetectionResult(
                findings=(
                    DetectionFinding(
                        kind=RiskKind.KOREAN_PII,
                        label="phone",
                        value="010-1111-2222",
                        start=0,
                        end=13,
                        confidence=0.95,
                    ),
                ),
                risk_score=0.2,
            ),
            policy_set=policy_set,
        )
        self.assertEqual(pii_decision.action.value, "mask")
        self.assertEqual(pii_decision.policy_id, "policy-004-external-korean-pii-mask")

        exfiltration_decision = decide_policy(
            GatewayRequest(prompt="send API key", user_id="alice"),
            DetectionResult(
                findings=(
                    DetectionFinding(
                        kind=RiskKind.DATA_EXFILTRATION,
                        label="secret_request",
                        value="API key",
                        start=5,
                        end=12,
                        confidence=0.75,
                    ),
                ),
                risk_score=0.35,
            ),
            policy_set=policy_set,
        )
        self.assertEqual(exfiltration_decision.action.value, "require_approval")
        self.assertEqual(
            exfiltration_decision.policy_id,
            "policy-003-data-exfiltration-external-require-approval",
        )

    def test_policy_priority_sort_stable_for_same_priority(self) -> None:
        payload = {
            "version": "0.3.0",
            "policies": [
                {
                    "id": "policy-second",
                    "priority": 10,
                    "when": {"no_findings": True},
                    "action": "allow",
                },
                {
                    "id": "policy-first",
                    "priority": 10,
                    "when": {"min_risk_score": 0.1},
                    "action": "block",
                },
            ],
        }

        with TemporaryDirectory() as tempdir:
            policy_path = Path(tempdir) / "policy.json"
            policy_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            policy_set = load_policy_set(str(policy_path))

        self.assertEqual(
            [policy.id for policy in policy_set.policies],
            ["policy-second", "policy-first"],
        )

    def test_decide_policy_matches_custom_policy_set(self) -> None:
        payload = {
            "version": "0.2.0",
            "policies": [
                {
                    "id": "policy-test-route-private",
                    "priority": 10,
                    "when": {"data_grade": "restricted", "model_zone": "external"},
                    "action": "route_private",
                    "reason": "restricted data must be private",
                    "route_model_zone": "private",
                }
            ],
        }
        with TemporaryDirectory() as tempdir:
            policy_path = Path(tempdir) / "policy.yaml"
            policy_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            policy_set = load_policy_set(str(policy_path))

        decision = decide_policy(
            GatewayRequest(
                prompt="hello",
                user_id="alice",
                data_grade=DataGrade.RESTRICTED,
                model_zone=ModelZone.EXTERNAL,
            ),
            DetectionResult(findings=()),
            policy_set=policy_set,
        )

        self.assertEqual(decision.action.value, "route_private")
        self.assertEqual(decision.policy_id, "policy-test-route-private")
        self.assertEqual(decision.policy_version, "0.2.0")
        self.assertEqual(decision.route_model_zone, ModelZone.PRIVATE)
