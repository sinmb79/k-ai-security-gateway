import unittest

from kai_security.detectors.pii import detect_korean_pii
from kai_security.models import RiskKind


def _rrn_with_checksum(prefix: str) -> str:
    if len(prefix) != 12 or not prefix.isdigit():
        raise ValueError("prefix must be 12 digits")
    weights = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)
    checksum = sum(int(d) * w for d, w in zip(prefix, weights))
    return f"{prefix}{(11 - (checksum % 11)) % 10}"


def _foreigner_rrn_with_checksum(prefix: str) -> str:
    if len(prefix) != 12 or not prefix.isdigit():
        raise ValueError("prefix must be 12 digits")
    weights = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5, 6)
    checksum = sum(int(d) * w for d, w in zip(prefix, weights))
    return f"{prefix}{(11 - (checksum % 11)) % 10}"


def _business_no_with_checksum(prefix: str) -> str:
    if len(prefix) != 9 or not prefix.isdigit():
        raise ValueError("prefix must be 9 digits")
    weights = (1, 3, 7, 1, 3, 7, 1, 3)
    base = sum(int(d) * w for d, w in zip(prefix[:8], weights))
    split_last = (int(prefix[8]) * 5) // 10 + (int(prefix[8]) * 5) % 10
    return f"{prefix}{(10 - ((base + split_last) % 10)) % 10}"


class KoreanPiiDetectorTests(unittest.TestCase):
    def test_detects_korean_pii_and_masks_by_token(self) -> None:
        rrn = _rrn_with_checksum("9001011" + "23456")
        foreigner = _foreigner_rrn_with_checksum("9001015" + "23456")
        business = _business_no_with_checksum("220116220")
        prompt = (
            f"RRN {rrn[:6]}-{rrn[6:]}, "
            f"foreigner {foreigner[:6]}-{foreigner[6:]}, "
            "phone 010-1234-5678, "
            f"business {business[:3]}-{business[3:5]}-{business[5:]}, "
            "email test-user@example.com, "
            "card 4111 1111 1111 1111."
        )
        result = detect_korean_pii(prompt)

        self.assertTrue(result.has_findings)
        self.assertEqual(result.risk_score, 1.0)
        self.assertEqual(result.masked_text.count("[RRN]"), 2)
        self.assertIn("[PHONE]", result.masked_text)
        self.assertIn("[EMAIL]", result.masked_text)
        self.assertIn("[CARD]", result.masked_text)
        self.assertIn("[BUSINESS_NO]", result.masked_text)
        kinds = [finding.kind for finding in result.findings]
        self.assertTrue(all(kind == RiskKind.KOREAN_PII for kind in kinds))
        labels = {finding.label for finding in result.findings}
        self.assertEqual(labels, {"rrn", "foreigner_rrn", "phone", "business_no", "email", "card"})
        ranges = [(finding.start, finding.end) for finding in result.findings]
        self.assertEqual(len(ranges), len(set(ranges)))

    def test_masks_with_no_dash_variants(self) -> None:
        rrn = _rrn_with_checksum("9001011" + "23456")
        business = _business_no_with_checksum("130812500")
        card = "4111111111111111"

        prompt = (
            f"RRN {rrn}, business {business}, card {card}"
        )
        result = detect_korean_pii(prompt)
        self.assertTrue(result.findings)
        self.assertIn("[BUSINESS_NO]", result.masked_text)
        self.assertIn("[RRN]", result.masked_text)
        self.assertIn("[CARD]", result.masked_text)

    def test_negative_numbers_without_sensitive_pattern(self) -> None:
        prompt = (
            "The date is 2026-06-05 and order id is 123-4567-8901. "
            "Random IDs 12345678, 010-12-3456, and 1111111111111112 are not sensitive."
        )
        result = detect_korean_pii(prompt)
        self.assertEqual(result.findings, ())
        self.assertEqual(result.risk_score, 0.0)
        self.assertEqual(result.masked_text, prompt)

    def test_business_no_checksum_validation(self) -> None:
        # Known-valid generated example
        business = _business_no_with_checksum("220116220")
        dashed = f"{business[:3]}-{business[3:5]}-{business[5:]}"
        prompt = f"사업자등록번호는 {dashed}, {business} 입니다."
        result = detect_korean_pii(prompt)
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(len([f for f in result.findings if f.label == "business_no"]), 2)
        self.assertIn("[BUSINESS_NO]", result.masked_text)

        # Invalid one-digit mutated checksum should not pass validation
        invalid_check_digit = business[:-1] + ("0" if business[-1] != "0" else "1")
        invalid_prompt = f"invalid business_no {invalid_check_digit}"
        invalid_result = detect_korean_pii(invalid_prompt)
        self.assertEqual(len(invalid_result.findings), 0)
        self.assertEqual(invalid_result.masked_text, invalid_prompt)


if __name__ == "__main__":
    unittest.main()
