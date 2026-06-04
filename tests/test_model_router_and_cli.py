import contextlib
import io
import json
import unittest

from kai_security.cli import main
from kai_security.model_router import choose_route
from kai_security.models import ModelZone, PolicyAction, PolicyDecision


class ModelRouterTests(unittest.TestCase):
    def test_blocked_decision_has_no_route(self) -> None:
        decision = PolicyDecision(
            action=PolicyAction.BLOCK,
            reason="blocked",
            policy_id="x",
            policy_version="0.1.0",
            risk_score=1.0,
        )

        self.assertIsNone(choose_route(decision, "gpt-compatible"))

    def test_private_route_uses_private_default_model(self) -> None:
        decision = PolicyDecision(
            action=PolicyAction.ROUTE_PRIVATE,
            reason="route private",
            policy_id="x",
            policy_version="0.1.0",
            risk_score=0.3,
            route_model_zone=ModelZone.PRIVATE,
        )

        route = choose_route(decision, "external-model")

        self.assertIsNotNone(route)
        self.assertEqual(route.zone, ModelZone.PRIVATE)
        self.assertEqual(route.model, "private-default")


class CliTests(unittest.TestCase):
    def test_evaluate_prints_json(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(["evaluate", "--prompt", "일반 문서 요약", "--user-id", "alice"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertIn("request_id", payload)
        self.assertIn("decision", payload)
        self.assertIn("effective_prompt", payload)
        self.assertIn("prompt_changed", payload)
        self.assertIn("summary", payload)


if __name__ == "__main__":
    unittest.main()
