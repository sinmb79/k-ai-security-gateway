import json
import unittest
import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from apps.gateway_api.main import (
    _approval_payload,
    _build_safe_provider_messages,
    _coerce_bool,
    _event_payload,
    _extract_bearer_token,
    _parse_approver_tokens,
    _require_admin,
    _require_approver,
    _require_client,
    app,
    build_gateway_request,
    create_gateway_service,
    evaluate_chat_completion_payload,
)
from kai_security.approval.queue import InMemoryApprovalQueue
from kai_security.gateway.service import GatewayService
from kai_security.model_router import choose_route
from kai_security.models import AuditEvent, DataGrade, ModelZone

try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError:  # pragma: no cover - optional FastAPI test dependency
    TestClient = None


class GatewayApiContractTests(unittest.TestCase):
    def _set_env(self, key: str, value: str) -> None:
        old_value = os.environ.get(key)
        os.environ[key] = value

        def restore() -> None:
            if old_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old_value

        self.addCleanup(restore)

    def _client_headers(self, token: str = "client-token") -> dict[str, str]:
        self._set_env("KAI_SECURITY_CLIENT_TOKENS", "client-token=client-1:security")
        return {"Authorization": f"Bearer {token}"}

    def test_build_gateway_request_maps_policy_context(self) -> None:
        request = build_gateway_request(
            {
                "prompt": "내부 문서 요약",
                "user_id": "alice",
                "department": "audit",
                "role": "auditor",
                "requested_model": "gpt-compatible",
                "data_grade": "restricted",
                "model_zone": "external",
            }
        )

        self.assertEqual(request.data_grade, DataGrade.RESTRICTED)
        self.assertEqual(request.model_zone, ModelZone.EXTERNAL)
        self.assertEqual(request.role, "auditor")

    def test_route_private_decision_has_route_payload_source(self) -> None:
        request = build_gateway_request(
            {
                "prompt": "민감 문장",
                "user_id": "alice",
                "data_grade": "confidential",
                "model_zone": "external",
            }
        )
        evaluation = GatewayService().evaluate(request)
        route = choose_route(evaluation.decision, request.requested_model)

        self.assertEqual(evaluation.decision.action.value, "route_private")
        self.assertIsNotNone(route)
        self.assertEqual(route.zone, ModelZone.PRIVATE)

    def test_invalid_enum_value_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_gateway_request({"prompt": "x", "data_grade": "top-secret"})

    def test_approval_payload_is_json_ready(self) -> None:
        approval = InMemoryApprovalQueue().create(
            request_id="request-1",
            requested_by="alice",
            reason="review",
            action="require_approval",
        )

        payload = _approval_payload(approval)

        self.assertEqual(payload["request_id"], "request-1")
        self.assertEqual(payload["status"], "pending")
        self.assertIsInstance(payload["created_at"], str)

    def test_coerce_bool_rejects_ambiguous_values(self) -> None:
        self.assertTrue(_coerce_bool("true"))
        self.assertFalse(_coerce_bool("false"))
        with self.assertRaises(ValueError):
            _coerce_bool("definitely")

    def test_require_approver_allows_only_approval_roles(self) -> None:
        self.assertEqual(
            _require_approver(
                {"approval_token": "token-1"},
                {"token-1": ("manager-1", "security_manager")},
            ),
            ("manager-1", "security_manager"),
        )
        with self.assertRaises(PermissionError):
            _require_approver({"approval_token": "bad"}, {"token-1": ("manager-1", "admin")})
        with self.assertRaises(PermissionError):
            _require_approver({}, {"token-1": ("manager-1", "admin")})

    def test_require_admin_uses_server_token_registry(self) -> None:
        import os

        old_value = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:security_manager"
        try:
            self.assertEqual(
                _require_admin(authorization="Bearer admin-token"),
                ("manager-1", "security_manager"),
            )
            with self.assertRaises(PermissionError):
                _require_admin(authorization="Bearer bad-token")
            with self.assertRaises(PermissionError):
                _require_admin()
        finally:
            if old_value is None:
                os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
            else:
                os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_value

    def test_require_client_uses_server_token_registry(self) -> None:
        self._set_env("KAI_SECURITY_CLIENT_TOKENS", "client-token=client-1:security")

        self.assertEqual(
            _require_client(authorization="Bearer client-token"),
            ("client-1", "security"),
        )
        with self.assertRaises(PermissionError):
            _require_client(authorization="Bearer bad-token")
        with self.assertRaises(PermissionError):
            _require_client()

    def test_admin_token_does_not_substitute_for_client_token(self) -> None:
        self._set_env("KAI_SECURITY_ADMIN_TOKENS", "admin-token=manager-1:admin")
        self._set_env("KAI_SECURITY_CLIENT_TOKENS", "client-token=client-1:security")

        with self.assertRaises(PermissionError):
            _require_client(authorization="Bearer admin-token")

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_security_evaluate_audit_uses_authenticated_client_identity(self) -> None:
        service = GatewayService()
        client = TestClient(app)

        with patch("apps.gateway_api.main.gateway", service):
            response = client.post(
                "/v1/security/evaluate",
                headers=self._client_headers(),
                json={
                    "prompt": "safe prompt",
                    "user_id": "attacker",
                    "department": "finance",
                },
            )

        self.assertEqual(response.status_code, 200)
        events = service.evidence_store.list_events(
            request_id=response.json()["request_id"],
            event_type="request_received",
        )
        self.assertEqual(len(events), 1)
        payload = events[0].payload
        self.assertEqual(payload["user_id"], "client-1")
        self.assertEqual(payload["department"], "security")
        self.assertEqual(payload["metadata"]["authenticated_client_id"], "client-1")
        self.assertEqual(payload["metadata"]["authenticated_client_department"], "security")
        self.assertEqual(payload["metadata"]["client_supplied_user_id"], "attacker")
        self.assertEqual(payload["metadata"]["client_supplied_department"], "finance")

    def test_extract_bearer_token_rejects_non_bearer_values(self) -> None:
        self.assertEqual(_extract_bearer_token("Bearer admin-token"), "admin-token")
        self.assertEqual(_extract_bearer_token("bearer admin-token"), "admin-token")
        self.assertEqual(_extract_bearer_token("admin-token"), "")
        self.assertEqual(_extract_bearer_token(None), "")

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_admin_api_uses_authorization_header_not_query_token(self) -> None:
        import os

        old_value = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:security_manager"
        try:
            client = TestClient(app)

            self.assertEqual(client.get("/admin").status_code, 200)
            self.assertEqual(client.get("/v1/reports/policy?admin_token=admin-token").status_code, 403)
            self.assertEqual(
                client.get("/v1/reports/policy", headers={"Authorization": "Bearer admin-token"}).status_code,
                200,
            )
        finally:
            if old_value is None:
                os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
            else:
                os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_value

    def test_parse_approver_tokens_ignores_invalid_roles(self) -> None:
        registry = _parse_approver_tokens(
            "a=manager-1:security_manager;b=user-1:viewer;c=admin-1:admin"
        )

        self.assertEqual(registry, {"a": ("manager-1", "security_manager"), "c": ("admin-1", "admin")})

    def test_event_payload_is_json_ready(self) -> None:
        event = AuditEvent(
            event_type="policy_decided",
            request_id="request-1",
            timestamp=datetime(2026, 6, 5, 1, 2, 3, tzinfo=UTC),
            payload={"action": "mask"},
            previous_hash="prev",
            event_hash="hash",
        )

        payload = _event_payload(event)

        self.assertEqual(payload["event_type"], "policy_decided")
        self.assertIsInstance(payload["timestamp"], str)
        self.assertEqual(payload["payload"], {"action": "mask"})

    def test_create_gateway_service_uses_sqlite_when_db_path_is_set(self) -> None:
        import os

        with TemporaryDirectory() as tempdir:
            db_path = Path(tempdir) / "audit" / "evidence.sqlite3"
            old_value = os.environ.get("KAI_SECURITY_DB_PATH")
            os.environ["KAI_SECURITY_DB_PATH"] = str(db_path)
            try:
                service = create_gateway_service()
                service.evaluate(
                    build_gateway_request(
                        {"prompt": "연락처는 010-1234-5678 입니다.", "user_id": "alice"}
                    )
                )

                self.assertTrue(db_path.exists())
                self.assertTrue(service.evidence_store.verify_chain())
                service.evidence_store.close()
            finally:
                if old_value is None:
                    os.environ.pop("KAI_SECURITY_DB_PATH", None)
                else:
                    os.environ["KAI_SECURITY_DB_PATH"] = old_value

    def test_build_safe_provider_messages_uses_effective_prompt_for_mask(self) -> None:
        safe_messages = _build_safe_provider_messages(
            action="mask",
            canonical_prompt="user: original",
            effective_prompt="MASKED: hello",
        )
        self.assertEqual(safe_messages, [{"role": "user", "content": "MASKED: hello"}])

    def test_build_safe_provider_messages_uses_canonical_prompt_for_non_mask(self) -> None:
        safe_messages = _build_safe_provider_messages(
            action="allow",
            canonical_prompt="user: original",
            effective_prompt="MASKED: ignored",
        )
        self.assertEqual(safe_messages, [{"role": "user", "content": "user: original"}])

    def test_chat_completion_masks_effective_prompt(self) -> None:
        response = evaluate_chat_completion_payload(
            {
                "model": "gateway-test",
                "messages": [{"role": "user", "content": "연락처는 010-1234-5678"}],
            },
            service=GatewayService(),
        )

        content = response["choices"][0]["message"]["content"]
        self.assertIn("[PHONE]", content)
        self.assertNotIn("010-1234-5678", content)
        self.assertEqual(response["gateway_security"]["action"], "mask")

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_security_evaluate_does_not_return_effective_or_raw_prompt(self) -> None:
        client = TestClient(app)
        service = GatewayService()
        raw_prompt = "ordinary internal planning note"

        with patch("apps.gateway_api.main.gateway", service):
            response = client.post(
                "/v1/security/evaluate",
                headers=self._client_headers(),
                json={"prompt": raw_prompt, "user_id": "alice"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertNotIn("effective_prompt", payload)
        self.assertNotIn(raw_prompt, response.text)
        self.assertIn("prompt_changed", payload)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_security_evaluate_requires_client_bearer_token(self) -> None:
        client = TestClient(app)
        self._set_env("KAI_SECURITY_CLIENT_TOKENS", "client-token=client-1:security")

        missing = client.post("/v1/security/evaluate", json={"prompt": "safe"})
        bad = client.post(
            "/v1/security/evaluate",
            headers={"Authorization": "Bearer bad-token"},
            json={"prompt": "safe"},
        )
        good = client.post(
            "/v1/security/evaluate",
            headers={"Authorization": "Bearer client-token"},
            json={"prompt": "safe"},
        )

        self.assertEqual(missing.status_code, 403)
        self.assertEqual(bad.status_code, 403)
        self.assertEqual(good.status_code, 200)

    def test_chat_completion_masked_messages_are_passed_to_adapter(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "provider response"},
                    "finish_reason": "stop",
                }
            ],
        }

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = evaluate_chat_completion_payload(
                {
                    "model": "gateway-test",
                    "messages": [{"role": "user", "content": "연락처는 010-1234-5678"}],
                },
                service=GatewayService(),
            )

        called_payload = adapter.complete.call_args.kwargs
        sent_messages = called_payload["messages"]
        self.assertEqual(len(sent_messages), 1)
        self.assertIn("[PHONE]", str(sent_messages[0]["content"]))
        self.assertNotIn("010-1234-5678", str(sent_messages[0]["content"]))
        self.assertEqual(response["choices"][0]["message"]["content"], "provider response")

    def test_chat_completion_passes_only_allowlisted_provider_options(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "provider response"},
                    "finish_reason": "stop",
                }
            ],
        }

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            evaluate_chat_completion_payload(
                {
                    "model": "gateway-test",
                    "temperature": 0.2,
                    "max_tokens": 32,
                    "top_p": 0.9,
                    "response_format": {"type": "json_object"},
                    "stream": True,
                    "tools": [{"type": "function"}],
                    "messages": [{"role": "user", "content": "safe content"}],
                },
                service=GatewayService(),
            )

        self.assertEqual(
            adapter.complete.call_args.kwargs["provider_options"],
            {
                "temperature": 0.2,
                "max_tokens": 32,
                "top_p": 0.9,
                "response_format": {"type": "json_object"},
            },
        )

    def test_chat_completion_masks_sensitive_provider_response(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "고객 연락처는 010-1234-5678 입니다."},
                    "finish_reason": "stop",
                }
            ],
        }
        service = GatewayService()

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = evaluate_chat_completion_payload(
                {
                    "model": "gateway-test",
                    "messages": [{"role": "user", "content": "safe content"}],
                },
                service=service,
            )

        content = response["choices"][0]["message"]["content"]
        self.assertIn("[PHONE]", content)
        self.assertNotIn("010-1234-5678", content)
        self.assertEqual(response["gateway_security"]["response_guard"]["action"], "mask")
        events = service.evidence_store.list_events(response["gateway_security"]["request_id"])
        response_events = [event for event in events if event.event_type == "response_analyzed"]
        self.assertEqual(len(response_events), 1)
        self.assertEqual(response_events[0].payload["action"], "mask")
        self.assertNotIn("010-1234-5678", str(response_events[0].payload))

    def test_chat_completion_blocks_secret_provider_response(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "API key: sk-1234567890abcdef and password=supersecret1",
                    },
                    "finish_reason": "stop",
                }
            ],
        }
        service = GatewayService()

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = evaluate_chat_completion_payload(
                {
                    "model": "gateway-test",
                    "messages": [{"role": "user", "content": "safe content"}],
                },
                service=service,
            )

        content = response["choices"][0]["message"]["content"]
        self.assertNotIn("sk-1234567890abcdef", content)
        self.assertNotIn("supersecret1", content)
        self.assertEqual(response["gateway_security"]["response_guard"]["action"], "block")
        events = service.evidence_store.list_events(response["gateway_security"]["request_id"])
        response_events = [event for event in events if event.event_type == "response_analyzed"]
        self.assertEqual(len(response_events), 1)
        self.assertEqual(response_events[0].payload["action"], "block")
        self.assertNotIn("sk-1234567890abcdef", str(response_events[0].payload))
        self.assertNotIn("supersecret1", str(response_events[0].payload))

    def test_chat_completion_records_choice_level_response_guard_summary(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "provider response"},
                    "finish_reason": "stop",
                },
                {
                    "index": 1,
                    "message": {
                        "role": "assistant",
                        "content": "API key: sk-1234567890abcdef and password=supersecret1",
                    },
                    "finish_reason": "stop",
                },
            ],
        }
        service = GatewayService()

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = evaluate_chat_completion_payload(
                {
                    "model": "gateway-test",
                    "messages": [{"role": "user", "content": "safe content"}],
                },
                service=service,
            )

        guard = response["gateway_security"]["response_guard"]
        self.assertEqual(guard["action"], "block")
        self.assertEqual(
            [
                {
                    "index": summary["index"],
                    "action": summary["action"],
                    "response_changed": summary["response_changed"],
                }
                for summary in guard["choices"]
            ],
            [
                {"index": 0, "action": "allow", "response_changed": False},
                {"index": 1, "action": "block", "response_changed": True},
            ],
        )
        self.assertEqual(response["choices"][0]["message"]["content"], "provider response")
        self.assertNotIn("sk-1234567890abcdef", response["choices"][1]["message"]["content"])

    def test_chat_completion_uses_canonical_prompt_for_allowing_provider(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "provider response"},
                    "finish_reason": "stop",
                }
            ],
        }
        tool_call_payload = {"name": "find_contact", "arguments": "{\"phone\":\"010-1234-5678\"}"}

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = evaluate_chat_completion_payload(
                {
                    "model": "gateway-test",
                    "messages": [
                        {
                            "role": "user",
                            "content": "what is the contact",
                            "tool_calls": [
                                {"id": "call-1", "type": "function", "function": tool_call_payload}
                            ],
                        }
                    ],
                },
                service=GatewayService(),
            )

        self.assertEqual(response["gateway_security"]["action"], "allow")
        sent_messages = adapter.complete.call_args.kwargs["messages"]
        self.assertEqual(len(sent_messages), 1)
        self.assertEqual(sent_messages[0]["role"], "user")
        self.assertEqual(sent_messages[0]["content"], "user: what is the contact")
        self.assertNotIn("010-1234-5678", str(sent_messages[0]))
        self.assertNotIn("tool_calls", str(sent_messages[0]))

    def test_chat_completion_excludes_assistant_and_tool_history_from_provider(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "provider response"},
                    "finish_reason": "stop",
                }
            ],
        }

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = evaluate_chat_completion_payload(
                {
                    "model": "gateway-test",
                    "messages": [
                        {"role": "user", "content": "safe content"},
                        {"role": "assistant", "content": "previous private answer 010-1234-5678"},
                        {"role": "tool", "content": "tool result 010-1234-5678"},
                    ],
                },
                service=GatewayService(),
            )

        self.assertEqual(response["gateway_security"]["action"], "allow")
        sent_messages = adapter.complete.call_args.kwargs["messages"]
        self.assertEqual(sent_messages, [{"role": "user", "content": "user: safe content"}])
        self.assertNotIn("010-1234-5678", str(sent_messages))
        self.assertNotIn("assistant", str(sent_messages))
        self.assertNotIn("tool result", str(sent_messages))

    def test_chat_completion_masked_payload_is_safe_in_openai_adapter_http_body(self) -> None:
        import os

        endpoint_var = "KAI_SECURITY_EXTERNAL_OPENAI_COMPATIBLE_ENDPOINT"
        api_key_var = "KAI_SECURITY_EXTERNAL_OPENAI_COMPATIBLE_API_KEY"
        old_endpoint = os.environ.get(endpoint_var)
        old_api_key = os.environ.get(api_key_var)
        os.environ[endpoint_var] = "https://provider.local"
        os.environ[api_key_var] = "dummy-key"

        class _FakeHTTPResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return (
                    b'{"id":"mock-id","object":"chat.completion","choices":[{"index":0,'
                    b'"message":{"role":"assistant","content":"provider response"}}]}'
                )

        try:
            with patch("kai_security.providers.openai_compatible.urlopen") as mock_urlopen:
                mock_urlopen.return_value = _FakeHTTPResponse()
                response = evaluate_chat_completion_payload(
                    {
                        "model": "gateway-test",
                        "messages": [
                            {
                                "role": "user",
                                "content": "연락처: 010-1234-5678",
                                "tool_calls": [
                                    {
                                        "id": "call-1",
                                        "type": "function",
                                        "function": {
                                            "name": "noop",
                                            "arguments": "{\"phone\":\"010-1234-5678\"}",
                                        },
                                    }
                                ],
                            }
                        ],
                    },
                    service=GatewayService(),
                )

            request = mock_urlopen.call_args.args[0]
            body = json.loads(request.data.decode("utf-8"))
            self.assertEqual(body["model"], "gateway-test")
            self.assertNotIn("010-1234-5678", json.dumps(body))
            self.assertNotIn("tool_calls", json.dumps(body))
            self.assertIn("[PHONE]", json.dumps(body))
            self.assertEqual(response["choices"][0]["message"]["content"], "provider response")
        finally:
            if old_endpoint is None:
                os.environ.pop(endpoint_var, None)
            else:
                os.environ[endpoint_var] = old_endpoint
            if old_api_key is None:
                os.environ.pop(api_key_var, None)
            else:
                os.environ[api_key_var] = old_api_key

    def test_chat_completion_calls_adapter_for_allowed_prompt(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "provider response"},
                    "finish_reason": "stop",
                }
            ],
        }

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = evaluate_chat_completion_payload(
                {
                    "model": "gateway-test",
                    "messages": [{"role": "user", "content": "safe content"}],
                },
                service=GatewayService(),
            )

        self.assertEqual(response["choices"][0]["message"]["content"], "provider response")
        adapter.complete.assert_called_once()
        called_payload = adapter.complete.call_args.kwargs
        self.assertEqual(called_payload["model"], "gateway-test")
        self.assertEqual(response["gateway_security"]["action"], "allow")
        self.assertEqual(response["gateway_security"]["route"]["provider"], "external-openai-compatible")

    def test_chat_completion_calls_adapter_for_route_private(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "private route"},
                    "finish_reason": "stop",
                }
            ],
        }
        resolved_route = {}

        def _resolve(route):
            resolved_route["route"] = route
            return adapter

        with patch("apps.gateway_api.main.resolve_provider_adapter", side_effect=_resolve):
            response = evaluate_chat_completion_payload(
                {
                    "model": "gateway-test",
                    "data_grade": "confidential",
                    "model_zone": "external",
                    "messages": [
                        {
                            "role": "user",
                            "content": "confidential check",
                            "tool_calls": [
                                {
                                    "id": "private-call-1",
                                    "type": "function",
                                    "function": {"name": "noop", "arguments": "{\"phone\":\"010-1234-5678\"}"},
                                }
                            ],
                        }
                    ],
                },
                service=GatewayService(),
            )

        route = response["gateway_security"]["route"]
        self.assertIsInstance(route, dict)
        self.assertEqual(response["gateway_security"]["action"], "route_private")
        self.assertEqual(route["provider"], "private-llm")
        self.assertEqual(route["model"], "private-default")
        self.assertEqual(resolved_route["route"].provider, "private-llm")
        self.assertEqual(resolved_route["route"].model, route["model"])
        self.assertEqual(adapter.complete.call_args.kwargs["model"], route["model"])
        private_messages = adapter.complete.call_args.kwargs["messages"][0]
        self.assertEqual(private_messages["role"], "user")
        self.assertNotIn("010-1234-5678", str(private_messages))
        self.assertNotIn("tool_calls", str(private_messages))

    def test_chat_completion_does_not_call_adapter_for_approval(self) -> None:
        adapter = Mock()

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter) as resolve_mock:
            response = evaluate_chat_completion_payload(
                {
                    "model": "gateway-test",
                    "data_grade": "restricted",
                    "messages": [{"role": "user", "content": "일반 메시지"}],
                },
                service=GatewayService(),
            )

        self.assertEqual(response["gateway_security"]["action"], "require_approval")
        self.assertNotIn("일반 메시지", response["choices"][0]["message"]["content"])
        resolve_mock.assert_not_called()
        self.assertFalse(adapter.complete.called)

    def test_chat_completion_approval_response_does_not_echo_secret(self) -> None:
        response = evaluate_chat_completion_payload(
            {
                "model": "gateway-test",
                "messages": [{"role": "user", "content": "API key and secret must be hidden."}],
            },
            service=GatewayService(),
        )

        content = response["choices"][0]["message"]["content"]
        self.assertEqual(response["gateway_security"]["action"], "require_approval")
        self.assertNotIn("API key", content)
        self.assertNotIn("secret", content)
        self.assertIsNone(response["gateway_security"]["route"])

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_chat_completion_endpoint_returns_502_on_malformed_provider_payload(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {"unexpected": True}
        client = TestClient(app)

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = client.post(
                "/v1/chat/completions",
                headers=self._client_headers(),
                json={"model": "gateway-test", "messages": [{"role": "user", "content": "safe prompt"}]},
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["detail"], "provider request failed")

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_chat_completion_endpoint_returns_502_when_adapter_raises_runtime_error(self) -> None:
        adapter = Mock()
        adapter.complete.side_effect = RuntimeError("adapter failure")
        client = TestClient(app)

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = client.post(
                "/v1/chat/completions",
                headers=self._client_headers(),
                json={"model": "gateway-test", "messages": [{"role": "user", "content": "safe prompt"}]},
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["detail"], "provider request failed")

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_chat_completion_endpoint_rejects_provider_tool_calls(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "provider response",
                        "tool_calls": [{"id": "call-1", "type": "function"}],
                    },
                    "finish_reason": "stop",
                }
            ],
        }
        client = TestClient(app)

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = client.post(
                "/v1/chat/completions",
                headers=self._client_headers(),
                json={"model": "gateway-test", "messages": [{"role": "user", "content": "safe prompt"}]},
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["detail"], "provider request failed")
        self.assertNotIn("tool_calls", response.text)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_chat_completion_endpoint_rejects_provider_tool_calls_in_later_choices(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "safe first choice"},
                    "finish_reason": "stop",
                },
                {
                    "index": 1,
                    "message": {
                        "role": "assistant",
                        "content": "unsafe second choice",
                        "tool_calls": [{"id": "call-2", "type": "function"}],
                    },
                    "finish_reason": "tool_calls",
                },
            ],
        }
        client = TestClient(app)

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            response = client.post(
                "/v1/chat/completions",
                headers=self._client_headers(),
                json={"model": "gateway-test", "messages": [{"role": "user", "content": "safe prompt"}]},
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["detail"], "provider request failed")
        self.assertNotIn("tool_calls", response.text)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_chat_completion_endpoint_returns_502_on_malformed_upstream_json(self) -> None:
        import os

        endpoint_var = "KAI_SECURITY_EXTERNAL_OPENAI_COMPATIBLE_ENDPOINT"
        old_endpoint = os.environ.get(endpoint_var)
        os.environ[endpoint_var] = "https://provider.local"

        class _BrokenHTTPResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b"{broken json"

        client = TestClient(app)
        try:
            with patch("kai_security.providers.openai_compatible.urlopen") as mock_urlopen:
                mock_urlopen.return_value = _BrokenHTTPResponse()
                response = client.post(
                    "/v1/chat/completions",
                    headers=self._client_headers(),
                    json={"model": "gateway-test", "messages": [{"role": "user", "content": "safe prompt"}]},
                )
        finally:
            if old_endpoint is None:
                os.environ.pop(endpoint_var, None)
            else:
                os.environ[endpoint_var] = old_endpoint

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["detail"], "provider request failed")

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_chat_completion_endpoint_requires_client_bearer_token(self) -> None:
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "provider response"},
                    "finish_reason": "stop",
                }
            ],
        }
        client = TestClient(app)
        self._set_env("KAI_SECURITY_ADMIN_TOKENS", "admin-token=manager-1:admin")
        self._set_env("KAI_SECURITY_CLIENT_TOKENS", "client-token=client-1:security")

        with patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter):
            missing = client.post(
                "/v1/chat/completions",
                json={"model": "gateway-test", "messages": [{"role": "user", "content": "safe prompt"}]},
            )
            admin = client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer admin-token"},
                json={"model": "gateway-test", "messages": [{"role": "user", "content": "safe prompt"}]},
            )
            good = client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer client-token"},
                json={"model": "gateway-test", "messages": [{"role": "user", "content": "safe prompt"}]},
            )

        self.assertEqual(missing.status_code, 403)
        self.assertEqual(admin.status_code, 403)
        self.assertEqual(good.status_code, 200)

    def test_create_gateway_service_loads_policy_path(self) -> None:
        old_value = os.environ.get("KAI_SECURITY_POLICY_PATH")
        with TemporaryDirectory() as tempdir:
            policy_file = Path(tempdir) / "policy.json"
            policy_file.write_text(
                '{"version":"0.2.0","policies":[{"id":"policy-001","priority":10,"when":{"data_grade":"restricted","model_zone":"external"},"action":"route_private","route_model_zone":"private","reason":"test"}]}',
                encoding="utf-8",
            )
            os.environ["KAI_SECURITY_POLICY_PATH"] = str(policy_file)
            try:
                service = create_gateway_service()
                self.assertEqual(service.policy_set.version, "0.2.0")
                self.assertEqual(service.policy_set.source, str(policy_file))
            finally:
                if old_value is None:
                    os.environ.pop("KAI_SECURITY_POLICY_PATH", None)
                else:
                    os.environ["KAI_SECURITY_POLICY_PATH"] = old_value

    def test_create_gateway_service_raises_for_invalid_policy_path(self) -> None:
        old_value = os.environ.get("KAI_SECURITY_POLICY_PATH")
        with TemporaryDirectory() as tempdir:
            policy_file = Path(tempdir) / "broken-policy.json"
            policy_file.write_text("{broken json", encoding="utf-8")
            os.environ["KAI_SECURITY_POLICY_PATH"] = str(policy_file)
            try:
                with self.assertRaises(ValueError):
                    create_gateway_service()
            finally:
                if old_value is None:
                    os.environ.pop("KAI_SECURITY_POLICY_PATH", None)
                else:
                    os.environ["KAI_SECURITY_POLICY_PATH"] = old_value

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_list_policies_requires_admin(self) -> None:
        client = TestClient(app)
        self.assertEqual(client.get("/v1/policies").status_code, 403)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_list_policies_returns_summary(self) -> None:
        old_admin_tokens = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:admin"
        client = TestClient(app)
        service = GatewayService()
        with patch("apps.gateway_api.main.gateway", service):
            try:
                response = client.get("/v1/policies", headers={"Authorization": "Bearer admin-token"})
            finally:
                if old_admin_tokens is None:
                    os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
                else:
                    os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_admin_tokens
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("version", payload)
        self.assertIn("source", payload)
        self.assertIn("policies", payload)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_audit_events_endpoint_supports_event_type_and_limit(self) -> None:
        old_admin_tokens = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:admin"
        service = GatewayService()
        client = TestClient(app)

        first = service.evaluate(build_gateway_request({"prompt": "safe prompt", "user_id": "alice"}))
        second = service.evaluate(build_gateway_request({"prompt": "safe prompt 2", "user_id": "alice"}))
        with patch("apps.gateway_api.main.gateway", service):
            response = client.get(
                "/v1/audit/events?event_type=request_finalized&limit=1",
                headers={"Authorization": "Bearer admin-token"},
            )
            latest_response = client.get(
                "/v1/audit/events?event_type=request_finalized&order=desc&limit=1",
                headers={"Authorization": "Bearer admin-token"},
            )

        if old_admin_tokens is None:
            os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_admin_tokens

        self.assertEqual(response.status_code, 200)
        events = response.json()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "request_finalized")
        self.assertEqual(events[0]["request_id"], first.request.request_id)
        self.assertEqual(latest_response.status_code, 200)
        latest_events = latest_response.json()
        self.assertEqual(latest_events[0]["request_id"], second.request.request_id)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_audit_events_endpoint_supports_payload_filters(self) -> None:
        old_admin_tokens = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:admin"
        service = GatewayService()
        client = TestClient(app)

        service.evaluate(build_gateway_request({"prompt": "safe prompt", "user_id": "alice"}))
        pii = service.evaluate(
            build_gateway_request({"prompt": "고객 연락처는 010-1234-5678 입니다.", "user_id": "bob"})
        )
        with patch("apps.gateway_api.main.gateway", service):
            response = client.get(
                "/v1/audit/events"
                f"?request_id={pii.request.request_id}"
                "&event_type=policy_decided"
                "&action=mask"
                "&policy_id=policy-004-external-korean-pii-mask",
                headers={"Authorization": "Bearer admin-token"},
            )

        if old_admin_tokens is None:
            os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_admin_tokens

        self.assertEqual(response.status_code, 200)
        events = response.json()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["request_id"], pii.request.request_id)
        self.assertEqual(events[0]["payload"]["action"], "mask")
        self.assertEqual(events[0]["payload"]["policy_id"], "policy-004-external-korean-pii-mask")

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_audit_events_endpoint_requires_admin_bearer_and_valid_limit(self) -> None:
        old_admin_tokens = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:admin"
        client = TestClient(app)
        service = GatewayService()
        service.evaluate(build_gateway_request({"prompt": "safe prompt", "user_id": "alice"}))
        with patch("apps.gateway_api.main.gateway", service):
            try:
                no_auth = client.get("/v1/audit/events")
                query_token = client.get("/v1/audit/events?admin_token=admin-token")
                zero_limit = client.get(
                    "/v1/audit/events?limit=0",
                    headers={"Authorization": "Bearer admin-token"},
                )
                huge_limit = client.get(
                    "/v1/audit/events?limit=1001",
                    headers={"Authorization": "Bearer admin-token"},
                )
            finally:
                if old_admin_tokens is None:
                    os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
                else:
                    os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_admin_tokens

        self.assertEqual(no_auth.status_code, 403)
        self.assertEqual(query_token.status_code, 403)
        self.assertEqual(zero_limit.status_code, 400)
        self.assertEqual(huge_limit.status_code, 400)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_audit_events_endpoint_rejects_invalid_filters(self) -> None:
        old_admin_tokens = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:admin"
        client = TestClient(app)
        service = GatewayService()
        service.evaluate(build_gateway_request({"prompt": "safe prompt", "user_id": "alice"}))
        with patch("apps.gateway_api.main.gateway", service):
            bad_order = client.get(
                "/v1/audit/events?order=sideways",
                headers={"Authorization": "Bearer admin-token"},
            )
            bad_time_range = client.get(
                "/v1/audit/events?from_timestamp=2026-06-05T10:00:00Z&to_timestamp=2026-06-05T09:00:00Z",
                headers={"Authorization": "Bearer admin-token"},
            )

        if old_admin_tokens is None:
            os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_admin_tokens

        self.assertEqual(bad_order.status_code, 400)
        self.assertEqual(bad_time_range.status_code, 400)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_audit_events_export_requires_admin_and_supports_csv(self) -> None:
        old_admin_tokens = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:admin"
        client = TestClient(app)
        service = GatewayService()
        service.evidence_store.append(
            AuditEvent(
                event_type="policy_decided",
                request_id="+request-formula",
                timestamp=datetime.now(UTC),
                payload={
                    "action": "block",
                    "policy_id": "=SUM(1,1)",
                    "reason": "formula test",
                    "resolution_comment": "should not be exported",
                },
            )
        )
        with patch("apps.gateway_api.main.gateway", service):
            no_auth = client.get("/v1/audit/events/export?format=csv")
            query_token = client.get("/v1/audit/events/export?format=csv&admin_token=admin-token")
            response = client.get(
                "/v1/audit/events/export?format=csv&event_type=policy_decided&action=block",
                headers={"Authorization": "Bearer admin-token"},
            )

        if old_admin_tokens is None:
            os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_admin_tokens

        self.assertEqual(no_auth.status_code, 403)
        self.assertEqual(query_token.status_code, 403)
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.headers["content-type"])
        self.assertIn("kai-audit-events.csv", response.headers["content-disposition"])
        self.assertIn("'+request-formula", response.text)
        self.assertIn("'=SUM(1,1)", response.text)
        self.assertNotIn("should not be exported", response.text)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_audit_events_export_jsonl_uses_safe_payload(self) -> None:
        old_admin_tokens = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:admin"
        client = TestClient(app)
        service = GatewayService()
        service.evidence_store.append(
            AuditEvent(
                event_type="approval_resolved",
                request_id="req-jsonl",
                timestamp=datetime.now(UTC),
                payload={
                    "approval_id": "approval-1",
                    "request_id": "req-jsonl",
                    "requested_by": "alice",
                    "reason": "approval done",
                    "action": "require_approval",
                    "status": "approved",
                    "created_at": "2026-06-05T00:00:00+00:00",
                    "resolved_by": "manager-1",
                    "resolved_at": "2026-06-05T00:01:00+00:00",
                    "approver_role": "security_manager",
                    "resolution_comment": "raw operator note must stay out",
                },
            )
        )
        with patch("apps.gateway_api.main.gateway", service):
            response = client.get(
                "/v1/audit/events/export?format=jsonl&event_type=approval_resolved",
                headers={"Authorization": "Bearer admin-token"},
            )
            bad_format = client.get(
                "/v1/audit/events/export?format=xml",
                headers={"Authorization": "Bearer admin-token"},
            )

        if old_admin_tokens is None:
            os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_admin_tokens

        self.assertEqual(response.status_code, 200)
        self.assertIn("application/x-ndjson", response.headers["content-type"])
        rows = [json.loads(line) for line in response.text.splitlines() if line.strip()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["payload"]["approval_id"], "approval-1")
        self.assertNotIn("resolution_comment", rows[0]["payload"])
        self.assertNotIn("raw operator note", response.text)
        self.assertEqual(bad_format.status_code, 400)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_resolve_approval_requires_admin_bearer(self) -> None:
        old_admin_tokens = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        old_approver_tokens = os.environ.get("KAI_SECURITY_APPROVER_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:admin"
        os.environ["KAI_SECURITY_APPROVER_TOKENS"] = "approver-token=approver-1:security_manager"
        service = GatewayService()
        client = TestClient(app)
        with patch("apps.gateway_api.main.gateway", service):
            service.evaluate(build_gateway_request({"prompt": "API key and secret exposed", "user_id": "alice"}))
            approval_id = service.approval_queue.list_pending()[0].approval_id
            no_auth = client.post(
                f"/v1/approvals/{approval_id}/resolve",
                json={"approval_token": "approver-token", "approved": True},
            )
            query_token = client.post(
                f"/v1/approvals/{approval_id}/resolve?admin_token=admin-token",
                json={"approval_token": "approver-token", "approved": True},
            )
        if old_admin_tokens is None:
            os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_admin_tokens
        if old_approver_tokens is None:
            os.environ.pop("KAI_SECURITY_APPROVER_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_APPROVER_TOKENS"] = old_approver_tokens

        self.assertEqual(no_auth.status_code, 403)
        self.assertEqual(query_token.status_code, 403)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_resolve_approval_invalid_approval_token_is_forbidden(self) -> None:
        old_admin_tokens = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        old_approver_tokens = os.environ.get("KAI_SECURITY_APPROVER_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:admin"
        os.environ["KAI_SECURITY_APPROVER_TOKENS"] = "approver-token=approver-1:security_manager"
        service = GatewayService()
        client = TestClient(app)
        with patch("apps.gateway_api.main.gateway", service):
            service.evaluate(build_gateway_request({"prompt": "API key and secret exposed", "user_id": "alice"}))
            approval_id = service.approval_queue.list_pending()[0].approval_id
            response = client.post(
                f"/v1/approvals/{approval_id}/resolve",
                headers={"Authorization": "Bearer admin-token"},
                json={"approval_token": "wrong-token", "approved": True},
            )
        if old_admin_tokens is None:
            os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_admin_tokens
        if old_approver_tokens is None:
            os.environ.pop("KAI_SECURITY_APPROVER_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_APPROVER_TOKENS"] = old_approver_tokens

        self.assertEqual(response.status_code, 403)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_resolve_approval_updates_pending_and_audit_events(self) -> None:
        old_admin_tokens = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        old_approver_tokens = os.environ.get("KAI_SECURITY_APPROVER_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:admin"
        os.environ["KAI_SECURITY_APPROVER_TOKENS"] = "approver-token=approver-1:security_manager"
        service = GatewayService()
        client = TestClient(app)
        with patch("apps.gateway_api.main.gateway", service):
            service.evaluate(build_gateway_request({"prompt": "API key and secret exposed", "user_id": "alice"}))
            approval_id = service.approval_queue.list_pending()[0].approval_id
            resolve_response = client.post(
                f"/v1/approvals/{approval_id}/resolve",
                headers={"Authorization": "Bearer admin-token"},
                json={"approval_token": "approver-token", "approved": True, "comment": "approved in test"},
            )
            pending_response = client.get(
                "/v1/approvals/pending",
                headers={"Authorization": "Bearer admin-token"},
            )
            events_response = client.get(
                "/v1/audit/events?event_type=approval_resolved&limit=20",
                headers={"Authorization": "Bearer admin-token"},
            )
        if old_admin_tokens is None:
            os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_admin_tokens
        if old_approver_tokens is None:
            os.environ.pop("KAI_SECURITY_APPROVER_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_APPROVER_TOKENS"] = old_approver_tokens

        self.assertEqual(resolve_response.status_code, 200)
        self.assertEqual(resolve_response.json()["status"], "approved")
        self.assertEqual(pending_response.status_code, 200)
        self.assertEqual(len(pending_response.json()), 0)
        self.assertEqual(events_response.status_code, 200)
        events = events_response.json()
        self.assertTrue(
            any(
                event.get("event_type") == "approval_resolved"
                and event["payload"].get("approval_id") == approval_id
                for event in events
            )
        )

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_resolve_approval_executes_stored_chat_completion_context(self) -> None:
        self._set_env("KAI_SECURITY_ADMIN_TOKENS", "admin-token=manager-1:admin")
        self._set_env("KAI_SECURITY_APPROVER_TOKENS", "approver-token=approver-1:security_manager")
        service = GatewayService()
        client = TestClient(app)
        adapter = Mock()
        adapter.complete.return_value = {
            "id": "adapter-approval-1",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "approved provider response"},
                    "finish_reason": "stop",
                }
            ],
        }

        with (
            patch("apps.gateway_api.main.gateway", service),
            patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter),
        ):
            chat_response = client.post(
                "/v1/chat/completions",
                headers=self._client_headers(),
                json={
                    "model": "gateway-test",
                    "data_grade": "restricted",
                    "model_zone": "external",
                    "temperature": 0.1,
                    "messages": [{"role": "user", "content": "normal business review"}],
                },
            )
            approval_id = chat_response.json()["gateway_security"]["approval_id"]
            resolve_response = client.post(
                f"/v1/approvals/{approval_id}/resolve",
                headers={"Authorization": "Bearer admin-token"},
                json={"approval_token": "approver-token", "approved": True},
            )

        self.assertEqual(chat_response.status_code, 200)
        self.assertEqual(chat_response.json()["gateway_security"]["action"], "require_approval")
        self.assertEqual(resolve_response.status_code, 200)
        resolved = resolve_response.json()
        self.assertEqual(resolved["status"], "approved")
        self.assertIn("completion", resolved)
        self.assertEqual(
            resolved["completion"]["choices"][0]["message"]["content"],
            "approved provider response",
        )
        called_payload = adapter.complete.call_args.kwargs
        self.assertEqual(called_payload["model"], "gateway-test")
        self.assertEqual(called_payload["provider_options"], {"temperature": 0.1})
        self.assertTrue(called_payload["gateway_security"]["approved_execution"])
        event_types = [
            event.event_type
            for event in service.evidence_store.list_events(
                request_id=chat_response.json()["gateway_security"]["request_id"]
            )
        ]
        self.assertIn("approval_resolved", event_types)
        self.assertIn("response_analyzed", event_types)
        self.assertIn("approval_executed", event_types)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_rejected_approval_does_not_execute_stored_context(self) -> None:
        self._set_env("KAI_SECURITY_ADMIN_TOKENS", "admin-token=manager-1:admin")
        self._set_env("KAI_SECURITY_APPROVER_TOKENS", "approver-token=approver-1:security_manager")
        service = GatewayService()
        client = TestClient(app)
        adapter = Mock()

        with (
            patch("apps.gateway_api.main.gateway", service),
            patch("apps.gateway_api.main.resolve_provider_adapter", return_value=adapter),
        ):
            chat_response = client.post(
                "/v1/chat/completions",
                headers=self._client_headers(),
                json={
                    "model": "gateway-test",
                    "data_grade": "restricted",
                    "model_zone": "external",
                    "messages": [{"role": "user", "content": "normal business review"}],
                },
            )
            approval_id = chat_response.json()["gateway_security"]["approval_id"]
            resolve_response = client.post(
                f"/v1/approvals/{approval_id}/resolve",
                headers={"Authorization": "Bearer admin-token"},
                json={"approval_token": "approver-token", "approved": False},
            )

        self.assertEqual(chat_response.status_code, 200)
        self.assertEqual(resolve_response.status_code, 200)
        self.assertEqual(resolve_response.json()["status"], "rejected")
        self.assertNotIn("completion", resolve_response.json())
        adapter.complete.assert_not_called()
        event_types = [
            event.event_type
            for event in service.evidence_store.list_events(
                request_id=chat_response.json()["gateway_security"]["request_id"]
            )
        ]
        self.assertNotIn("approval_executed", event_types)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_resolve_approval_double_resolve_is_conflict(self) -> None:
        old_admin_tokens = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        old_approver_tokens = os.environ.get("KAI_SECURITY_APPROVER_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:admin"
        os.environ["KAI_SECURITY_APPROVER_TOKENS"] = "approver-token=approver-1:security_manager"
        service = GatewayService()
        client = TestClient(app)
        with patch("apps.gateway_api.main.gateway", service):
            service.evaluate(build_gateway_request({"prompt": "API key and secret exposed", "user_id": "alice"}))
            approval_id = service.approval_queue.list_pending()[0].approval_id
            first = client.post(
                f"/v1/approvals/{approval_id}/resolve",
                headers={"Authorization": "Bearer admin-token"},
                json={"approval_token": "approver-token", "approved": True},
            )
            second = client.post(
                f"/v1/approvals/{approval_id}/resolve",
                headers={"Authorization": "Bearer admin-token"},
                json={"approval_token": "approver-token", "approved": True},
            )
        if old_admin_tokens is None:
            os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_admin_tokens
        if old_approver_tokens is None:
            os.environ.pop("KAI_SECURITY_APPROVER_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_APPROVER_TOKENS"] = old_approver_tokens

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 409)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_simulate_policy_requires_admin(self) -> None:
        client = TestClient(app)
        response = client.post(
            "/v1/policies/simulate",
            json={"prompt": "안전한 테스트"},
        )
        self.assertEqual(response.status_code, 403)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_policy_simulate_endpoint_returns_decision_without_queue_side_effect(self) -> None:
        old_admin_tokens = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:admin"
        client = TestClient(app)
        service = GatewayService()
        with patch("apps.gateway_api.main.gateway", service):
            response = client.post(
                "/v1/policies/simulate",
                headers={"Authorization": "Bearer admin-token"},
                json={
                    "prompt": "confidential request",
                    "data_grade": "restricted",
                    "model_zone": "external",
                    "user_id": "alice",
                },
            )
        if old_admin_tokens is None:
            os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_admin_tokens

        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["action"], "require_approval")
        self.assertIn("policy_id", result)
        self.assertIn("finding_count", result)
        self.assertIn("findings", result)
        self.assertIn("route", result)
        self.assertEqual(len(service.approval_queue.list_pending()), 0)
        self.assertEqual(len(service.evidence_store.list_events()), 0)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_policy_simulate_endpoint_masks_pii_finding_values(self) -> None:
        old_admin_tokens = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:admin"
        client = TestClient(app)
        service = GatewayService()
        with patch("apps.gateway_api.main.gateway", service):
            response = client.post(
                "/v1/policies/simulate",
                headers={"Authorization": "Bearer admin-token"},
                json={
                    "prompt": "입금계좌 110-123-456789, 법인등록번호 123456-1234567, 서울특별시 강남구 테헤란로 123 확인",
                    "data_grade": "internal",
                    "model_zone": "external",
                    "user_id": "alice",
                },
            )
        if old_admin_tokens is None:
            os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_admin_tokens

        self.assertEqual(response.status_code, 200)
        rendered = json.dumps(response.json(), ensure_ascii=False)
        self.assertIn("[ACCOUNT_NO]", rendered)
        self.assertIn("[CORP_REG_NO]", rendered)
        self.assertIn("[ADDRESS]", rendered)
        self.assertNotIn("110-123-456789", rendered)
        self.assertNotIn("123456-1234567", rendered)
        self.assertNotIn("서울특별시 강남구 테헤란로", rendered)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_evidence_package_report_requires_admin_bearer(self) -> None:
        old_admin_tokens = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:admin"
        client = TestClient(app)
        service = GatewayService()
        request = build_gateway_request(
            {"prompt": "API key and secret exposed", "user_id": "alice"}
        )
        service.evaluate(request)
        with patch("apps.gateway_api.main.gateway", service):
            no_auth = client.get(f"/v1/reports/evidence-package/{request.request_id}")
            query_token = client.get(
                f"/v1/reports/evidence-package/{request.request_id}?admin_token=admin-token",
            )

        if old_admin_tokens is None:
            os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_admin_tokens

        self.assertEqual(no_auth.status_code, 403)
        self.assertEqual(query_token.status_code, 403)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_evidence_package_report_returns_package_for_existing_request(self) -> None:
        old_admin_tokens = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:admin"
        client = TestClient(app)
        service = GatewayService()
        request = build_gateway_request(
            {"prompt": "API key and secret exposed", "user_id": "alice"}
        )
        service.evaluate(request)
        with patch("apps.gateway_api.main.gateway", service):
            response = client.get(
                f"/v1/reports/evidence-package/{request.request_id}",
                headers={"Authorization": "Bearer admin-token"},
            )

        if old_admin_tokens is None:
            os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_admin_tokens

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["report_type"], "request_evidence_package")
        self.assertEqual(payload["request_id"], request.request_id)
        self.assertEqual(payload["chain_verified"], True)
        self.assertEqual(payload["policy_decision"]["policy_version"], "0.1.0")
        self.assertTrue(all(isinstance(item.get("event_hash"), str) for item in payload["timeline"]))
        self.assertEqual(payload["approval"]["approval_requested"]["count"], 1)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_evidence_package_report_exposes_failed_chain_verification(self) -> None:
        old_admin_tokens = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        old_chain_max = os.environ.get("KAI_SECURITY_REPORT_CHAIN_VERIFY_MAX_EVENTS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:admin"
        os.environ["KAI_SECURITY_REPORT_CHAIN_VERIFY_MAX_EVENTS"] = "50000"
        client = TestClient(app)
        service = GatewayService()
        request = build_gateway_request(
            {"prompt": "API key and secret exposed", "user_id": "alice"}
        )
        service.evaluate(request)
        service.evidence_store._events[0] = replace(
            service.evidence_store._events[0],
            payload={"user_id": "tampered"},
        )
        with patch("apps.gateway_api.main.gateway", service):
            response = client.get(
                f"/v1/reports/evidence-package/{request.request_id}",
                headers={"Authorization": "Bearer admin-token"},
            )

        if old_admin_tokens is None:
            os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_admin_tokens
        if old_chain_max is None:
            os.environ.pop("KAI_SECURITY_REPORT_CHAIN_VERIFY_MAX_EVENTS", None)
        else:
            os.environ["KAI_SECURITY_REPORT_CHAIN_VERIFY_MAX_EVENTS"] = old_chain_max

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["chain_verified"], False)
        self.assertEqual(payload["chain_verification"]["status"], "failed")

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_evidence_package_report_can_skip_chain_verification_above_limit(self) -> None:
        old_admin_tokens = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        old_chain_max = os.environ.get("KAI_SECURITY_REPORT_CHAIN_VERIFY_MAX_EVENTS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:admin"
        os.environ["KAI_SECURITY_REPORT_CHAIN_VERIFY_MAX_EVENTS"] = "0"
        client = TestClient(app)
        service = GatewayService()
        request = build_gateway_request(
            {"prompt": "API key and secret exposed", "user_id": "alice"}
        )
        service.evaluate(request)
        with patch("apps.gateway_api.main.gateway", service):
            response = client.get(
                f"/v1/reports/evidence-package/{request.request_id}",
                headers={"Authorization": "Bearer admin-token"},
            )

        if old_admin_tokens is None:
            os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_admin_tokens
        if old_chain_max is None:
            os.environ.pop("KAI_SECURITY_REPORT_CHAIN_VERIFY_MAX_EVENTS", None)
        else:
            os.environ["KAI_SECURITY_REPORT_CHAIN_VERIFY_MAX_EVENTS"] = old_chain_max

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIsNone(payload["chain_verified"])
        self.assertEqual(payload["chain_verification"]["status"], "skipped")
        self.assertEqual(payload["chain_verification"]["max_event_count"], 0)

    @unittest.skipIf(TestClient is None or app is None, "FastAPI test client is unavailable")
    def test_evidence_package_report_for_unknown_request_returns_404(self) -> None:
        old_admin_tokens = os.environ.get("KAI_SECURITY_ADMIN_TOKENS")
        os.environ["KAI_SECURITY_ADMIN_TOKENS"] = "admin-token=manager-1:admin"
        client = TestClient(app)

        response = client.get(
            "/v1/reports/evidence-package/does-not-exist",
            headers={"Authorization": "Bearer admin-token"},
        )

        if old_admin_tokens is None:
            os.environ.pop("KAI_SECURITY_ADMIN_TOKENS", None)
        else:
            os.environ["KAI_SECURITY_ADMIN_TOKENS"] = old_admin_tokens

        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
