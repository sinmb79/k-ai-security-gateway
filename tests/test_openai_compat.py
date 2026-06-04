import unittest

from kai_security.openai_compat import (
    build_blocked_chat_response,
    build_gateway_chat_response,
    extract_chat_prompt,
)


class OpenAICompatTests(unittest.TestCase):
    def test_extract_chat_prompt_with_string_content(self) -> None:
        payload = {
            "messages": [
                {"role": "system", "content": "보안 지침을 준수해."},
                {"role": "user", "content": "요약해줘."},
            ]
        }

        prompt = extract_chat_prompt(payload)

        self.assertEqual(prompt, "system: 보안 지침을 준수해. user: 요약해줘.")

    def test_extract_chat_prompt_with_multipart_text_content(self) -> None:
        payload = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "이건"},
                        {"type": "text", "text": " 이어붙인"},
                        {"type": "text", "text": " 요청입니다."},
                    ],
                }
            ]
        }

        prompt = extract_chat_prompt(payload)

        self.assertEqual(prompt, "user: 이건 이어붙인 요청입니다.")

    def test_extract_chat_prompt_raises_when_messages_or_content_missing(self) -> None:
        with self.assertRaises(ValueError):
            extract_chat_prompt({})
        with self.assertRaises(ValueError):
            extract_chat_prompt({"messages": []})
        with self.assertRaises(ValueError):
            extract_chat_prompt({"messages": [{"role": "user"}]})

    def test_build_gateway_chat_response_reflects_effective_prompt(self) -> None:
        response = build_gateway_chat_response("req-1", "안전한 응답", model="gpt-test")

        self.assertEqual(response["id"], "req-1")
        self.assertEqual(response["object"], "chat.completion")
        self.assertEqual(response["model"], "gpt-test")
        self.assertEqual(response["choices"][0]["message"]["role"], "assistant")
        self.assertEqual(response["choices"][0]["message"]["content"], "안전한 응답")
        self.assertEqual(response["choices"][0]["finish_reason"], "stop")

    def test_build_blocked_chat_response_is_safe(self) -> None:
        secret = "010-9999-8888"
        blocked = build_blocked_chat_response(
            "req-2", reason=f"민감 정보 발견: {secret}"
        )
        content = blocked["choices"][0]["message"]["content"]

        self.assertEqual(blocked["object"], "chat.completion")
        self.assertEqual(blocked["model"], "gateway-mock")
        self.assertEqual(blocked["choices"][0]["message"]["role"], "assistant")
        self.assertIn("보안 정책", content)
        self.assertEqual(blocked["choices"][0]["finish_reason"], "stop")
        self.assertNotIn(secret, content)


if __name__ == "__main__":
    unittest.main()
