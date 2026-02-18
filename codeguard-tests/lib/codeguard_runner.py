"""
CodeGuard runner: replay mode (fixtures) and live mode (actual action).

Default mode: REPLAY -- loads JSON from fixtures/outputs/{case.id}.json.
Live mode:    Only when env var CODEGUARD_LIVE=1. Runs real CodeGuard action.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from test_cases.ground_truth import TestCase

logger = logging.getLogger(__name__)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "outputs"

# Safe defaults for missing fields in parsed output.
_SAFE_DEFAULTS = {
    "detected": False,
    "risk_level": 0,
    "signals": [],
    "categories": [],
    "findings": [],
    "council": {
        "enabled": False,
        "models": [],
        "naive": {},
        "round_robin": {},
        "consensus": {
            "risk_level": 0,
            "signals": [],
            "findings": [],
            "human_required": False,
        },
    },
}


@dataclass
class ParsedResult:
    """Normalized output from a CodeGuard run."""
    detected: bool
    risk_level: int
    signals: List[str]
    categories: List[str]
    findings: List[Dict[str, Any]]
    council: Dict[str, Any]
    raw: Dict[str, Any] = field(default_factory=dict)
    parse_warnings: List[str] = field(default_factory=list)


def _apply_defaults(data: Dict[str, Any]) -> Dict[str, Any]:
    """Fill missing top-level keys with safe defaults."""
    warnings = []
    for key, default in _SAFE_DEFAULTS.items():
        if key not in data:
            warnings.append(f"Missing field '{key}', using default")
            data[key] = default
    # Ensure council sub-fields
    council = data.get("council", {})
    if not isinstance(council, dict):
        council = _SAFE_DEFAULTS["council"]
        data["council"] = council
    for sub_key, sub_default in _SAFE_DEFAULTS["council"].items():
        if sub_key not in council:
            warnings.append(f"Missing council.{sub_key}, using default")
            council[sub_key] = sub_default
    data["_parse_warnings"] = warnings
    return data


def _load_fixture(case_id: str) -> Dict[str, Any]:
    """Load and validate a fixture JSON file."""
    fixture_path = FIXTURES_DIR / f"{case_id}.json"
    if not fixture_path.exists():
        raise FileNotFoundError(
            f"Fixture not found: {fixture_path}. "
            f"Create it or run in live mode (CODEGUARD_LIVE=1)."
        )
    with open(fixture_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # In replay mode, require full schema
    required = ["detected", "risk_level", "signals", "categories", "findings", "council"]
    missing = [k for k in required if k not in data]
    if missing:
        raise ValueError(
            f"Fixture {case_id}.json missing required fields: {missing}"
        )
    return data


def _run_live(case: TestCase) -> Dict[str, Any]:
    """
    Run CodeGuard action against a real diff.

    # TODO: wire to actual CodeGuard action
    This would:
    1. Create a temp git repo with diff_builder
    2. Set up GitHub context with mock_github_context
    3. Invoke the CodeGuard action entrypoint
    4. Parse and normalize the output
    """
    raise NotImplementedError(
        "Live mode not yet wired. Set CODEGUARD_LIVE=0 or remove the env var. "
        "See codeguard_runner.py for integration points."
    )


def run(case: TestCase, mode: str = "replay") -> ParsedResult:
    """
    Run CodeGuard against a test case and return normalized results.

    Args:
        case: TestCase with diff content and expected values.
        mode: "replay" (default, uses fixtures) or "live".

    Returns:
        ParsedResult with normalized CodeGuard output.
    """
    if mode == "live":
        data = _run_live(case)
    else:
        data = _load_fixture(case.id)

    data = _apply_defaults(data)
    warnings = data.pop("_parse_warnings", [])

    for w in warnings:
        logger.warning("Case %s: %s", case.id, w)

    return ParsedResult(
        detected=data["detected"],
        risk_level=data["risk_level"],
        signals=data["signals"],
        categories=data["categories"],
        findings=data["findings"],
        council=data["council"],
        raw=data,
        parse_warnings=warnings,
    )
