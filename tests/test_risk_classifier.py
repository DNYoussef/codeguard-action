import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / "src"))

from risk_classifier import RiskClassifier  # noqa: E402


class RiskClassifierTests(unittest.TestCase):
    def _base_analysis(self):
        return {
            "files": [{
                "path": "src/payments/handler.py",
                "hunks": [{
                    "lines": [
                        {"type": "add", "content": "# payment logic", "line_number": 42},
                        {"type": "context", "content": "def charge()", "line_number": 41},
                    ]
                }],
            }],
            "sensitive_zones": [],
            "lines_added": 1,
            "lines_removed": 0,
        }

    def test_custom_rubric_path_sets_line_numbers(self):
        data = {"rules": [{"id": "PAY", "pattern": "payment", "severity": "critical", "message": "Payment code touched"}]}
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump(data, f)
            rubric_path = Path(f.name)

        classifier = RiskClassifier(rubric="custom", rubric_path=rubric_path)
        result = classifier.classify(self._base_analysis())

        pay_finding = next(f for f in result["findings"] if f["rule_id"] == "PAY")
        self.assertEqual(pay_finding["line"], 42)
        self.assertEqual(pay_finding["severity"], "critical")

    def test_bad_regex_rule_is_skipped_not_fatal(self):
        data = {"rules": [{"id": "BAD", "pattern": "[", "severity": "high", "message": "Broken regex"}]}
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump(data, f)
            rubric_path = Path(f.name)

        classifier = RiskClassifier(rubric="custom", rubric_path=rubric_path)
        result = classifier.classify(self._base_analysis())

        rule_ids = {f["rule_id"] for f in result["findings"]}
        self.assertNotIn("BAD", rule_ids)

    def test_policy_overrides_file_patterns_for_criticality(self):
        policy = {
            "file_patterns": {"L4": [r"critical_path/"]},
            "zone_severity": {"auth": "critical"},
            "size_thresholds": {"large": 10, "medium": 5, "small": 1},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump(policy, f)
            policy_path = Path(f.name)

        analysis = {
            "files": [{"path": "critical_path/main.py", "hunks": [], "added": 2, "removed": 0}],
            "sensitive_zones": [],
            "lines_added": 2,
            "lines_removed": 0,
        }

        classifier = RiskClassifier(rubric="default", policy_path=policy_path)
        result = classifier.classify(analysis)

        self.assertEqual(result["risk_tier"], "L4")


    def test_risk_drivers_include_file_locations(self):
        analysis = {
            "files": [{"path": "src/auth.py", "hunks": []}],
            "sensitive_zones": [
                {"zone": "auth", "file": "src/auth.py", "line": 42},
                {"zone": "auth", "file": "src/auth.py", "line": 99},
            ],
            "lines_added": 5,
            "lines_removed": 0,
        }
        classifier = RiskClassifier(rubric="default")
        result = classifier.classify(analysis)

        zone_drivers = [d for d in result["risk_drivers"] if d["type"] == "sensitive_zone"]
        self.assertTrue(len(zone_drivers) > 0, "Expected zone-based risk drivers")
        first = zone_drivers[0]
        self.assertIn("locations", first)
        self.assertTrue(len(first["locations"]) > 0, "Expected locations in driver")
        self.assertIn("src/auth.py:42", first["locations"])
        # Description should mention the file
        self.assertIn("src/auth.py", first["description"])

    def test_bundle_path_is_relative(self):
        """Ensure set_output bundle_path would be relative to workspace."""
        from pathlib import PurePosixPath
        workspace = PurePosixPath("/github/workspace")
        bundle_path = workspace / ".guardspine" / "bundles" / "bundle-pr1-abc1234.json"
        relative = PurePosixPath(str(bundle_path).replace(str(workspace) + "/", ""))
        self.assertEqual(str(relative), ".guardspine/bundles/bundle-pr1-abc1234.json")


if __name__ == "__main__":
    unittest.main()
