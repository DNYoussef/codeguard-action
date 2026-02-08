"""
Determinism tests for bundle canonicalization and hashing.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bundle_generator import BundleEvent, BundleGenerator


class TestBundleCanonicalization(unittest.TestCase):
    def test_event_hash_is_stable_for_equivalent_dict_order(self):
        a = BundleEvent(
            event_type="analysis_completed",
            timestamp="2026-02-08T00:00:00+00:00",
            actor="guardspine-codeguard",
            data={"z": 1, "a": {"c": 3, "b": 2}},
        )
        b = BundleEvent(
            event_type="analysis_completed",
            timestamp="2026-02-08T00:00:00+00:00",
            actor="guardspine-codeguard",
            data={"a": {"b": 2, "c": 3}, "z": 1},
        )

        self.assertEqual(a.compute_hash("genesis"), b.compute_hash("genesis"))

    def test_zone_file_summary_is_sorted(self):
        generator = BundleGenerator()
        zones = [
            {"zone": "pii", "file": "z.py"},
            {"zone": "pii", "file": "a.py"},
            {"zone": "pii", "file": "m.py"},
            {"zone": "pii", "file": "a.py"},
        ]

        summary = generator._summarize_zones(zones)
        self.assertEqual(summary["pii"]["files"], ["a.py", "m.py", "z.py"])


if __name__ == "__main__":
    unittest.main()

