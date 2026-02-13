from __future__ import annotations
import json
import os
import sys
from pathlib import Path
import pytest

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from src.bundle_generator import BundleGenerator

# Resolve path to golden vectors
# 1. Env var: FIXTURES_DIR
# 2. Fallback: Relative path to guardspine-spec/fixtures/golden-vectors
current_dir = Path(__file__).parent
default_fixtures_dir = current_dir.parent.parent / "guardspine-spec" / "fixtures" / "golden-vectors"
FIXTURES_DIR = Path(os.environ.get("FIXTURES_DIR", default_fixtures_dir))
VECTORS_PATH = FIXTURES_DIR / "v0.2.0.json"

def test_golden_vectors_proof_generation():
    if not VECTORS_PATH.exists():
        pytest.skip(f"Golden vectors file not found at {VECTORS_PATH}")

    with open(VECTORS_PATH, "r", encoding="utf-8") as f:
        vectors = json.load(f)

    generator = BundleGenerator()

    for case in vectors:
        print(f"Testing vector: {case['id']}")
        
        expected = case["expected"]
        items = expected["items"]
        expected_proof = expected["immutability_proof"]
        
        # Test _build_v020_proof
        # This function takes the list of items (with content hashes) and produces the chain
        proof = generator._build_v020_proof(items)
        
        # Verify Root Hash
        assert proof["root_hash"] == expected_proof["root_hash"]
        
        # Verify Chain
        assert len(proof["hash_chain"]) == len(expected_proof["hash_chain"])
        for idx, link in enumerate(proof["hash_chain"]):
            expected_link = expected_proof["hash_chain"][idx]
            
            assert link["sequence"] == expected_link["sequence"]
            assert link["item_id"] == expected_link["item_id"]
            assert link["content_type"] == expected_link["content_type"]
            assert link["content_hash"] == expected_link["content_hash"]
            assert link["previous_hash"] == expected_link["previous_hash"]
            assert link["chain_hash"] == expected_link["chain_hash"]

if __name__ == "__main__":
    pytest.main([__file__])
