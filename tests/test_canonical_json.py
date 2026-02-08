"""
Tests for canonical JSON normalization used by bundle hashing/signing.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from canonical_json import canonical_json_dumps


class TestCanonicalJson(unittest.TestCase):
    def test_equivalent_payloads_produce_identical_canonical_json(self):
        payload_a = {
            "z": {"b": 2, "a": 1},
            "tags": {"gamma", "alpha", "beta"},
            "label": "Cafe\u0301",
        }
        payload_b = {
            "label": "Caf\u00e9",
            "tags": {"beta", "gamma", "alpha"},
            "z": {"a": 1, "b": 2},
        }

        self.assertEqual(canonical_json_dumps(payload_a), canonical_json_dumps(payload_b))

    def test_non_finite_float_is_rejected(self):
        with self.assertRaises(ValueError):
            canonical_json_dumps({"score": float("nan")})


if __name__ == "__main__":
    unittest.main()

