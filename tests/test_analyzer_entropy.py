"""Tests for AI diff routing behavior in DiffAnalyzer."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from analyzer import DiffAnalyzer


class TestAnalyzerAIDiffContent(unittest.TestCase):
    _RAW_DIFF = (
        "diff --git a/src/app.py b/src/app.py\n"
        "index 1111111..2222222 100644\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -1,0 +1,1 @@\n"
        "+email = 'alice@example.com'\n"
    )

    _SANITIZED_DIFF = _RAW_DIFF.replace("alice@example.com", "[HIDDEN:e1]")

    def _analyzer(self) -> DiffAnalyzer:
        analyzer = DiffAnalyzer(ai_review=True)
        analyzer.ai_enabled = True
        analyzer.max_models_available = 1
        return analyzer

    def test_ai_diff_content_is_used_for_model_review_input(self):
        analyzer = self._analyzer()

        with patch.object(analyzer, "_run_multi_model_review") as mock_review:
            mock_review.return_value = {
                "reviews": [],
                "models_used": 0,
                "models_failed": 0,
                "model_errors": [],
                "consensus": {"consensus_risk": "comment", "agreement_score": 1.0},
            }
            analyzer.analyze(
                self._RAW_DIFF,
                tier_override="L1",
                ai_diff_content=self._SANITIZED_DIFF,
            )

        self.assertEqual(mock_review.call_count, 1)
        self.assertEqual(mock_review.call_args.args[0], self._SANITIZED_DIFF)

    def test_raw_diff_is_used_when_ai_diff_not_provided(self):
        analyzer = self._analyzer()

        with patch.object(analyzer, "_run_multi_model_review") as mock_review:
            mock_review.return_value = {
                "reviews": [],
                "models_used": 0,
                "models_failed": 0,
                "model_errors": [],
                "consensus": {"consensus_risk": "comment", "agreement_score": 1.0},
            }
            analyzer.analyze(self._RAW_DIFF, tier_override="L1")

        self.assertEqual(mock_review.call_count, 1)
        self.assertEqual(mock_review.call_args.args[0], self._RAW_DIFF)

    def test_content_preview_redacted_when_ai_diff_provided(self):
        """C2 regression: content_preview must not leak raw PII."""
        analyzer = self._analyzer()

        with patch.object(analyzer, "_run_multi_model_review") as mock_review:
            mock_review.return_value = {
                "reviews": [],
                "models_used": 0,
                "models_failed": 0,
                "model_errors": [],
                "consensus": {"consensus_risk": "comment", "agreement_score": 1.0},
            }
            result = analyzer.analyze(
                self._RAW_DIFF,
                tier_override="L1",
                ai_diff_content=self._SANITIZED_DIFF,
            )

        zones = result["sensitive_zones"]
        self.assertTrue(len(zones) > 0, "expected at least one sensitive zone")
        for zone in zones:
            self.assertEqual(zone["content_preview"], "[REDACTED]")
            self.assertNotIn("alice@example.com", zone["content_preview"])

    def test_content_preview_shows_raw_when_no_ai_diff(self):
        """Without sanitized diff, content_preview uses the raw line."""
        analyzer = self._analyzer()

        with patch.object(analyzer, "_run_multi_model_review") as mock_review:
            mock_review.return_value = {
                "reviews": [],
                "models_used": 0,
                "models_failed": 0,
                "model_errors": [],
                "consensus": {"consensus_risk": "comment", "agreement_score": 1.0},
            }
            result = analyzer.analyze(self._RAW_DIFF, tier_override="L1")

        zones = result["sensitive_zones"]
        self.assertTrue(len(zones) > 0, "expected at least one sensitive zone")
        # At least one zone should contain the raw email in its preview
        previews = [z["content_preview"] for z in zones]
        self.assertTrue(
            any("alice@example.com" in p for p in previews),
            f"expected raw PII in previews when ai_diff_content is None, got {previews}",
        )


if __name__ == "__main__":
    unittest.main()
