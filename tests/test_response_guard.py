import unittest

from kai_security.response_guard import guard_response_text, response_guard_event_payload


class ResponseGuardTests(unittest.TestCase):
    def test_masks_korean_pii_response(self) -> None:
        result = guard_response_text("고객 연락처는 010-1234-5678 입니다.")

        self.assertEqual(result.action, "mask")
        self.assertTrue(result.response_changed)
        self.assertIn("[PHONE]", result.content)
        self.assertNotIn("010-1234-5678", result.content)

    def test_blocks_secret_response(self) -> None:
        result = guard_response_text(
            "API key: sk-1234567890abcdef and password=supersecret1"
        )

        self.assertEqual(result.action, "block")
        self.assertTrue(result.response_changed)
        self.assertNotIn("sk-1234567890abcdef", result.content)
        self.assertNotIn("supersecret1", result.content)

    def test_allows_generic_secret_hygiene_guidance(self) -> None:
        result = guard_response_text("API keys and passwords should be rotated regularly.")

        self.assertEqual(result.action, "allow")
        self.assertFalse(result.response_changed)
        self.assertEqual(result.content, "API keys and passwords should be rotated regularly.")

    def test_event_payload_excludes_raw_response_values(self) -> None:
        result = guard_response_text(
            "API key: sk-1234567890abcdef and password=supersecret1"
        )

        payload = response_guard_event_payload(result)
        rendered = str(payload)

        self.assertEqual(payload["action"], "block")
        self.assertGreater(payload["finding_count"], 0)
        self.assertNotIn("sk-1234567890abcdef", rendered)
        self.assertNotIn("supersecret1", rendered)


if __name__ == "__main__":
    unittest.main()
