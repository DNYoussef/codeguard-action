from __future__ import annotations
import json
import os
import sys
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock
from datetime import datetime
import pytest

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from src.bundle_generator import BundleGenerator

# Resolve path to guardspine-verify executable
# Use the venv python executable to run the module directly or the console script
current_dir = Path(__file__).parent
project_root = current_dir.parent.parent
verifier_venv = project_root / "guardspine-verify" / ".venv"
verifier_bin = verifier_venv / "bin" / "guardspine-verify"

def test_codeguard_bundle_verification():
    """
    E2E Test: Generate a bundle using CodeGuard's BundleGenerator and verify it 
    using the guardspine-verify CLI tool.
    """
    if not verifier_bin.exists():
        pytest.skip(f"guardspine-verify executable not found at {verifier_bin}")

    # 1. Setup Mock Data
    pr_mock = MagicMock()
    pr_mock.number = 123
    pr_mock.title = "Test PR"
    pr_mock.base.ref = "main"
    pr_mock.head.ref = "feature-branch"
    pr_mock.user.login = "test-user"
    pr_mock.created_at = datetime.now()

    analysis_mock = {
        "files_changed": 1,
        "lines_added": 10,
        "lines_removed": 5,
        "diff_hash": "sha256:dummy_diff_hash",
        "sensitive_zones": []
    }

    risk_result_mock = {
        "risk_tier": "L1",
        "findings": [],
        "risk_drivers": []
    }

    # 2. Generate Bundle
    generator = BundleGenerator()
    bundle = generator.create_bundle(
        pr=pr_mock,
        analysis=analysis_mock,
        risk_result=risk_result_mock,
        repository="guardspine/test-repo",
        commit_sha="abcdef1234567890",
        approvers=["admin-user"]
    )

    # 3. Save Bundle to Temp File
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as tmp:
        json.dump(bundle, tmp, default=str)
        bundle_path = tmp.name

    try:
        # 4. Run guardspine-verify against the generated bundle
        # We use the full path to the verifier executable in the sibling directory's venv
        result = subprocess.run(
            [str(verifier_bin), bundle_path],
            capture_output=True,
            text=True
        )

        # 5. Assertions
        print("Verifier Output:", result.stdout)
        print("Verifier Error:", result.stderr)

        assert result.returncode == 0, f"Verification failed with code {result.returncode}"
        assert "BUNDLE VERIFIED" in result.stdout
        assert "PASS" in result.stdout

    finally:
        # Cleanup
        if os.path.exists(bundle_path):
            os.unlink(bundle_path)

if __name__ == "__main__":
    pytest.main([__file__])
