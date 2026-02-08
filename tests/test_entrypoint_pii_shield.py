"""Integration tests for entrypoint PII-Shield plumbing."""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from entrypoint import main
from src.pii_shield import PIIShieldResult


class TestEntrypointPIIShield(unittest.TestCase):
    def test_raw_diff_is_preserved_and_ai_diff_is_provider_sanitized(self):
        raw_diff = (
            "diff --git a/app.py b/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,0 +1,1 @@\n"
            "+contact = 'alice@example.com'\n"
        )
        redacted_diff = raw_diff.replace("alice@example.com", "[HIDDEN:e1]")

        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            event_path = workspace / "event.json"
            event_path.write_text(json.dumps({"pull_request": {"number": 7}}), encoding="utf-8")

            pr = MagicMock()
            pr.number = 7
            pr.title = "Stub PR"
            pr.state = "open"
            pr.mergeable = True

            repo = MagicMock()
            repo.get_pull.return_value = pr

            gh = MagicMock()
            gh.get_repo.return_value = repo

            captured: dict[str, object] = {}

            class StubAnalyzer:
                def __init__(self, *args, **kwargs):
                    pass

                def analyze(
                    self,
                    diff_content,
                    rubric="default",
                    tier_override=None,
                    deliberate=False,
                    ai_diff_content=None,
                ):
                    captured["raw"] = diff_content
                    captured["ai"] = ai_diff_content
                    return {
                        "files_changed": 1,
                        "lines_added": 1,
                        "lines_removed": 0,
                        "files": [],
                        "sensitive_zones": [
                            {"zone": "auth", "file": "app.py", "line": 1, "content_preview": "auth"}
                        ],
                        "diff_hash": "sha256:raw-diff-hash",
                        "models_used": 0,
                        "consensus_risk": "",
                        "agreement_score": 0.0,
                    }

            class StubClassifier:
                @staticmethod
                def discover_builtin_rubrics(_repo_root):
                    return {}

                @staticmethod
                def builtin_names(_repo_root):
                    return {"default"}

                def __init__(self, *args, **kwargs):
                    pass

                def classify(self, analysis):
                    captured["analysis"] = analysis
                    return {
                        "risk_tier": "L0",
                        "risk_drivers": [],
                        "findings": [],
                        "scores": {},
                        "rationale": "ok",
                    }

            packet = MagicMock()
            packet.decision = "merge"
            packet.hard_blocks = []
            packet.conditions = []
            packet.advisory = []

            pii_result = PIIShieldResult(
                sanitized_text=redacted_diff,
                changed=True,
                redaction_count=1,
                redactions_by_type={"email": 1},
                mode="remote",
                provider="pii-shield-test",
                input_hash="sha256:in",
                output_hash="sha256:out",
                signals=[
                    {
                        "zone": "pii",
                        "file": "app.py",
                        "line": 1,
                        "content_preview": "[HIDDEN:e1]",
                        "detector": "pii_shield",
                        "category": "email",
                    }
                ],
                metadata={"schema_version": "2026-01"},
            )
            pii_client = MagicMock()
            pii_client.sanitize_diff.return_value = pii_result

            with patch.dict(
                os.environ,
                {
                    "GITHUB_WORKSPACE": str(workspace),
                    "GITHUB_EVENT_PATH": str(event_path),
                    "GITHUB_REPOSITORY": "o/r",
                    "GITHUB_SHA": "abc1234",
                    "GITHUB_REF": "refs/pull/7/head",
                    "INPUT_GITHUB_TOKEN": "token",
                    "INPUT_POST_COMMENT": "false",
                    "INPUT_GENERATE_BUNDLE": "false",
                    "INPUT_UPLOAD_SARIF": "false",
                    "INPUT_AI_REVIEW": "false",
                    "INPUT_AUTO_MERGE": "false",
                    "INPUT_PII_SHIELD_ENABLED": "true",
                    "INPUT_PII_SHIELD_MODE": "remote",
                    "INPUT_PII_SHIELD_ENDPOINT": "https://shield.example/api/sanitize",
                    "INPUT_PII_SHIELD_FAIL_CLOSED": "true",
                },
                clear=False,
            ):
                with patch("entrypoint.Github", return_value=gh):
                    with patch("entrypoint.fetch_pr_diff", return_value=raw_diff):
                        with patch("entrypoint.DiffAnalyzer", StubAnalyzer):
                            with patch("entrypoint.RiskClassifier", StubClassifier):
                                with patch("entrypoint.PIIShieldClient", return_value=pii_client):
                                    with patch("entrypoint.DecisionEngine") as mock_engine:
                                        mock_engine.return_value.decide.return_value = packet
                                        with patch("entrypoint.render_decision_card", return_value="card"):
                                            with self.assertRaises(SystemExit) as exit_ctx:
                                                main()

            self.assertEqual(exit_ctx.exception.code, 0)
            self.assertIn("alice@example.com", captured["raw"])
            self.assertNotIn("alice@example.com", captured["ai"])
            self.assertIn("[HIDDEN:e1]", captured["ai"])
            pii_client.sanitize_diff.assert_called_once_with(raw_diff)

            analysis = captured["analysis"]
            self.assertIn("pii_shield", analysis)
            self.assertTrue(analysis["pii_shield"]["enabled"])
            self.assertIn("sanitization", analysis)
            self.assertEqual(analysis["sanitization"]["engine_name"], "pii-shield")
            self.assertEqual(analysis["raw_diff_hash"], "sha256:raw-diff-hash")
            expected_ai_hash = "sha256:" + hashlib.sha256(redacted_diff.encode("utf-8")).hexdigest()
            self.assertEqual(analysis["ai_diff_hash"], expected_ai_hash)

            zones = analysis["sensitive_zones"]
            zone_names = {z["zone"] for z in zones}
            self.assertEqual(zone_names, {"auth", "pii"})


if __name__ == "__main__":
    unittest.main()
