import unittest
from unittest.mock import patch

from kai_security.model_router import ModelRoute
from kai_security.models import ModelZone
from kai_security.providers import _coerce_timeout_seconds, iterate_provider_env_names, resolve_provider_adapter
from kai_security.providers.echo import EchoChatCompletionAdapter
from kai_security.providers.openai_compatible import (
    OpenAICompatibleHTTPAdapter,
    _build_completion_url,
)


class ProviderAdapterTests(unittest.TestCase):
    def test_echo_adapter_returns_effective_prompt(self) -> None:
        adapter = EchoChatCompletionAdapter()
        response = adapter.complete(
            request_id="req-1",
            model="mock-model",
            messages=[{"role": "user", "content": "hello"}],
            effective_prompt="MASKED: text",
            gateway_security={"action": "mask"},
        )

        self.assertEqual(response["model"], "mock-model")
        self.assertEqual(response["choices"][0]["message"]["content"], "MASKED: text")

    def test_openai_post_url_builder_normalizes_endpoints(self) -> None:
        self.assertEqual(
            _build_completion_url("https://api.example.com"),
            "https://api.example.com/v1/chat/completions",
        )
        self.assertEqual(
            _build_completion_url("https://api.example.com/v1"),
            "https://api.example.com/v1/chat/completions",
        )
        self.assertEqual(
            _build_completion_url("https://api.example.com/v1/chat/completions"),
            "https://api.example.com/v1/chat/completions",
        )

    def test_resolver_defaults_to_echo_when_no_endpoint_is_set(self) -> None:
        route = ModelRoute(
            provider="private-llm",
            model="private-default",
            zone=ModelZone.PRIVATE,
            reason="test",
        )

        adapter = resolve_provider_adapter(route)

        self.assertIsInstance(adapter, EchoChatCompletionAdapter)

    def test_resolver_uses_openai_adapter_when_endpoint_is_set(self) -> None:
        import os

        endpoint_var = iterate_provider_env_names(["private-llm"])["private-llm"].endpoint_env
        old_value = os.environ.get(endpoint_var)
        os.environ[endpoint_var] = "https://provider.local"
        try:
            route = ModelRoute(
                provider="private-llm",
                model="private-default",
                zone=ModelZone.PRIVATE,
                reason="test",
            )
            adapter = resolve_provider_adapter(route)

            self.assertIsInstance(adapter, OpenAICompatibleHTTPAdapter)
            self.assertEqual(adapter.endpoint, "https://provider.local")
        finally:
            if old_value is None:
                os.environ.pop(endpoint_var, None)
            else:
                os.environ[endpoint_var] = old_value

    @patch("kai_security.providers.openai_compatible.urlopen")
    def test_openai_adapter_posts_payload_without_network_call(self, mock_urlopen) -> None:
        class _FakeHTTPResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return (
                    b"{"
                    b'"id":"mock-id","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"provider response"}}]}'
                )

        mock_urlopen.return_value = _FakeHTTPResponse()
        adapter = OpenAICompatibleHTTPAdapter(endpoint="https://provider.local", api_key="secret")
        response = adapter.complete(
            request_id="req-1",
            model="mock-model",
            messages=[{"role": "user", "content": "hello"}],
            effective_prompt="MASKED",
            gateway_security={"action": "allow"},
        )

        self.assertEqual(response["id"], "mock-id")
        request = mock_urlopen.call_args.args[0]
        self.assertTrue(request.full_url.endswith("/v1/chat/completions"))
        self.assertIsNotNone(request.data)
        self.assertIn("x-kai-security", {key.lower() for key in request.headers})

    @patch("kai_security.providers.openai_compatible.urlopen")
    def test_openai_adapter_converts_malformed_json_to_runtime_error(self, mock_urlopen) -> None:
        class _BrokenHTTPResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b"{broken json"

        mock_urlopen.return_value = _BrokenHTTPResponse()
        adapter = OpenAICompatibleHTTPAdapter(endpoint="https://provider.local", api_key="secret")

        with self.assertRaises(RuntimeError) as context:
            adapter.complete(
                request_id="req-1",
                model="mock-model",
                messages=[{"role": "user", "content": "hello"}],
                effective_prompt="hello",
                gateway_security={"action": "allow"},
            )

        self.assertEqual(str(context.exception), "provider response has invalid JSON shape")

    def test_resolver_timeout_defaults_to_5_seconds_on_invalid_inputs(self) -> None:
        self.assertEqual(_coerce_timeout_seconds(""), 5.0)
        self.assertEqual(_coerce_timeout_seconds("abc"), 5.0)
        self.assertEqual(_coerce_timeout_seconds("-1"), 5.0)
        self.assertEqual(_coerce_timeout_seconds("nan"), 5.0)
        self.assertEqual(_coerce_timeout_seconds("inf"), 5.0)

    def test_resolver_timeout_accepts_finite_positive_values(self) -> None:
        self.assertEqual(_coerce_timeout_seconds("7.5"), 7.5)
        self.assertEqual(_coerce_timeout_seconds("0.25"), 0.25)


if __name__ == "__main__":
    unittest.main()
