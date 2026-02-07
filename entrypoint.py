#!/usr/bin/env python3
"""
GuardSpine CodeGuard GitHub Action Entrypoint

Analyzes PR diffs, evaluates risk, and generates evidence bundles.
"""

import json
import os
import sys
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from github import Github
from github.PullRequest import PullRequest

from src.analyzer import DiffAnalyzer
from src.risk_classifier import RiskClassifier
from src.bundle_generator import BundleGenerator
from src.pr_commenter import PRCommenter
from src.sarif_exporter import SARIFExporter

from code_guard.audit import Finding as AuditFinding
from decision.engine import DecisionEngine, render_decision_card


def get_env(name: str, default: str = "") -> str:
    """Get environment variable with default."""
    return os.environ.get(name, default)


def parse_bool(value: str) -> bool:
    """Parse boolean from string."""
    return value.lower() in ("true", "1", "yes")


def resolve_path(raw: Optional[str], workspace: Path) -> Optional[Path]:
    """Resolve a possibly-relative path against the GitHub workspace."""
    if not raw:
        return None
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = workspace / candidate
    return candidate


def main():
    """Main entrypoint for the action."""
    # Parse inputs from environment (set by GitHub Actions)
    risk_threshold = get_env("INPUT_RISK_THRESHOLD", "L3")
    rubric = get_env("INPUT_RUBRIC", "default")
    github_token = get_env("INPUT_GITHUB_TOKEN")
    post_comment = parse_bool(get_env("INPUT_POST_COMMENT", "true"))
    generate_bundle = parse_bool(get_env("INPUT_GENERATE_BUNDLE", "true"))
    upload_sarif = parse_bool(get_env("INPUT_UPLOAD_SARIF", "false"))
    fail_on_high_risk = parse_bool(get_env("INPUT_FAIL_ON_HIGH_RISK", "false"))

    # Optional AI API keys
    openai_key = get_env("INPUT_OPENAI_API_KEY") or get_env("OPENAI_API_KEY")
    anthropic_key = get_env("INPUT_ANTHROPIC_API_KEY") or get_env("ANTHROPIC_API_KEY")
    openrouter_key = get_env("INPUT_OPENROUTER_API_KEY") or get_env("OPENROUTER_API_KEY")
    openrouter_model = get_env("INPUT_OPENROUTER_MODEL", "anthropic/claude-sonnet-4")

    # Ollama for local/on-prem AI (no API key needed)
    ollama_host = get_env("INPUT_OLLAMA_HOST") or get_env("OLLAMA_HOST")
    ollama_model = get_env("INPUT_OLLAMA_MODEL", "llama3.3")

    # Multi-model configuration for tier-based review
    model_1 = get_env("INPUT_MODEL_1")  # Used for L1+
    model_2 = get_env("INPUT_MODEL_2")  # Used for L2+
    model_3 = get_env("INPUT_MODEL_3")  # Used for L3+
    ai_review = parse_bool(get_env("INPUT_AI_REVIEW", "true"))

    # Deliberation (multi-round cross-checking)
    deliberate = parse_bool(get_env("INPUT_DELIBERATE", "false"))

    # Decision policy
    decision_policy = get_env("INPUT_DECISION_POLICY", "standard")

    # Policy and rubric locations
    workspace = Path(get_env("GITHUB_WORKSPACE", ".")).resolve()
    rubrics_dir = resolve_path(get_env("INPUT_RUBRICS_DIR", ".guardspine/rubrics"), workspace)
    risk_policy_path = resolve_path(get_env("INPUT_RISK_POLICY"), workspace)
    bundle_dir = resolve_path(get_env("INPUT_BUNDLE_DIR", ".guardspine/bundles"), workspace) or (workspace / ".guardspine" / "bundles")

    if risk_policy_path and not risk_policy_path.exists():
        print(f"::error::Risk policy file not found: {risk_policy_path}")
        sys.exit(1)

    rubric_path: Optional[Path] = None
    rubric_is_builtin = rubric in RiskClassifier.RUBRICS
    if not rubric_is_builtin:
        # Treat rubric as path; prefer workspace, then rubrics_dir
        candidate = resolve_path(rubric, workspace)
        if (not candidate or not candidate.exists()) and rubrics_dir:
            candidate = resolve_path(rubric, rubrics_dir)
        if candidate and candidate.exists():
            rubric_path = candidate
        else:
            print(f"::error::Rubric file not found: {candidate if candidate else rubric}")
            sys.exit(1)

    # GitHub context
    github_event_path = get_env("GITHUB_EVENT_PATH")
    github_repository = get_env("GITHUB_REPOSITORY")
    github_sha = get_env("GITHUB_SHA")
    github_ref = get_env("GITHUB_REF")

    if not github_token:
        print("::error::GitHub token is required")
        sys.exit(1)

    # Load event data
    with open(github_event_path) as f:
        event = json.load(f)

    # Get PR number
    pr_number = event.get("pull_request", {}).get("number")
    if not pr_number:
        print("::notice::Not a pull request event, skipping analysis")
        sys.exit(0)

    print(f"::group::GuardSpine CodeGuard Analysis")
    print(f"Repository: {github_repository}")
    print(f"PR: #{pr_number}")
    print(f"Risk threshold: {risk_threshold}")
    print(f"Rubric: {rubric}")
    print("::endgroup::")

    # Initialize GitHub client
    gh = Github(github_token)
    repo = gh.get_repo(github_repository)
    pr = repo.get_pull(pr_number)

    # Get diff
    print("::group::Fetching PR diff")
    diff_content = fetch_pr_diff(pr)
    print(f"Diff size: {len(diff_content)} bytes")
    print("::endgroup::")

    # Analyze diff
    print("::group::Analyzing changes")
    analyzer = DiffAnalyzer(
        openai_key=openai_key,
        anthropic_key=anthropic_key,
        openrouter_key=openrouter_key,
        openrouter_model=openrouter_model,
        ollama_host=ollama_host,
        ollama_model=ollama_model,
        model_1=model_1,
        model_2=model_2,
        model_3=model_3,
        ai_review=ai_review
    )
    analysis = analyzer.analyze(diff_content, rubric=rubric, deliberate=deliberate)
    print(f"Files changed: {analysis['files_changed']}")
    print(f"Lines added: {analysis['lines_added']}")
    print(f"Lines removed: {analysis['lines_removed']}")
    print("::endgroup::")

    # Classify risk
    print("::group::Classifying risk")
    if not workspace.exists():
        print("::error::GITHUB_WORKSPACE is not set - cannot locate repository root for rubric loading")
        sys.exit(1)
    try:
        classifier = RiskClassifier(
            rubric=rubric,
            rubric_path=rubric_path,
            policy_path=risk_policy_path,
            repo_root=workspace,
        )
    except Exception as exc:
        print(f"::error::Failed to load rubric/policy: {exc}")
        sys.exit(1)

    risk_result = classifier.classify(analysis)
    risk_tier = risk_result["risk_tier"]
    risk_drivers = risk_result["risk_drivers"]
    findings = risk_result["findings"]

    print(f"Risk tier: {risk_tier}")
    print(f"Top drivers: {json.dumps(risk_drivers[:3], indent=2)}")
    print(f"Findings: {len(findings)}")
    print("::endgroup::")

    # Determine if approval required
    tier_order = ["L0", "L1", "L2", "L3", "L4"]
    threshold_index = tier_order.index(risk_threshold)
    risk_index = tier_order.index(risk_tier)
    requires_approval = risk_index >= threshold_index

    # --- Decision Engine ---
    print("::group::Running Decision Engine")
    audit_findings = _map_findings(findings)
    engine = DecisionEngine(decision_policy)
    decision_packet = engine.decide(audit_findings)
    decision_card_md = render_decision_card(decision_packet)
    print(f"Decision: {decision_packet.decision}")
    print(f"Hard blocks: {len(decision_packet.hard_blocks)}")
    print(f"Conditions: {len(decision_packet.conditions)}")
    print(f"Advisory: {len(decision_packet.advisory)}")
    print("::endgroup::")

    # Set outputs
    set_output("risk_tier", risk_tier)
    set_output("risk_drivers", json.dumps(risk_drivers))
    set_output("findings_count", str(len(findings)))
    set_output("requires_approval", str(requires_approval).lower())
    set_output("decision", decision_packet.decision)

    # Multi-model outputs
    models_used = analysis.get("models_used", 0)
    consensus_risk = analysis.get("consensus_risk", "")
    agreement_score = analysis.get("agreement_score", 0.0)
    set_output("models_used", str(models_used))
    set_output("consensus_risk", consensus_risk)
    set_output("agreement_score", str(agreement_score))

    # Post PR comment (Decision Card replaces old Diff Postcard)
    if post_comment:
        print("::group::Posting PR comment")
        commenter = PRCommenter(gh, repo, pr)
        commenter.post_decision_card(decision_card_md)
        print("Decision Card posted")
        print("::endgroup::")

    # Generate evidence bundle
    bundle_path = None
    if generate_bundle:
        print("::group::Generating evidence bundle")
        generator = BundleGenerator()
        bundle = generator.create_bundle(
            pr=pr,
            diff_content=diff_content,
            analysis=analysis,
            risk_result=risk_result,
            repository=github_repository,
            commit_sha=github_sha
        )

        # Save bundle
        bundle_dir.mkdir(parents=True, exist_ok=True)
        bundle_path = bundle_dir / f"bundle-pr{pr_number}-{github_sha[:7]}.json"

        with open(bundle_path, "w") as f:
            json.dump(bundle, f, indent=2, default=str)

        # Output path relative to workspace so upload-artifact (which runs
        # outside the Docker container) can resolve it against the host
        # workspace directory.  Absolute container paths like
        # /github/workspace/... don't exist on the host.
        try:
            relative_bundle = bundle_path.relative_to(workspace)
        except ValueError:
            relative_bundle = bundle_path
        set_output("bundle_path", str(relative_bundle))
        print(f"Bundle saved: {relative_bundle}")
        print(f"Bundle ID: {bundle['bundle_id']}")
        print("::endgroup::")

        # Upload as artifact
        print(f"::notice::Evidence bundle generated: {relative_bundle}")

    # Upload SARIF if requested
    if upload_sarif and findings:
        print("::group::Generating SARIF report")
        exporter = SARIFExporter()
        sarif = exporter.export(findings, github_repository, github_sha)
        sarif_path = Path(get_env("GITHUB_WORKSPACE", ".")) / "guardspine-results.sarif"

        with open(sarif_path, "w") as f:
            json.dump(sarif, f, indent=2)

        print(f"SARIF saved: {sarif_path}")
        print("::endgroup::")

    # Determine exit status (decision engine is authoritative)
    if decision_packet.decision == "block":
        print(f"::error::Decision Engine: BLOCKED ({len(decision_packet.hard_blocks)} provable failures)")
        print(f"::error file=GUARDSPINE::Merge blocked by {len(decision_packet.hard_blocks)} provable finding(s).")
        sys.exit(1)
    elif decision_packet.decision == "merge-with-conditions":
        print(f"::warning::Decision Engine: CONDITIONAL ({len(decision_packet.conditions)} reviewer action(s) required)")
        if fail_on_high_risk:
            sys.exit(1)
    else:
        print(f"::notice::Decision Engine: MERGE - clean to merge (risk tier {risk_tier})")

    sys.exit(0)


def _map_findings(finding_dicts: list[dict]) -> list[AuditFinding]:
    """Map codeguard-action finding dicts to decision engine Finding objects."""
    mapped = []
    for fd in finding_dicts:
        location = None
        if fd.get("file"):
            location = fd["file"]
            if fd.get("line"):
                location += f":{fd['line']}"
        # Zone findings and rubric findings with rule_id are pattern-matched = provable
        provable = bool(fd.get("rule_id"))
        mapped.append(AuditFinding(
            severity=fd.get("severity", "medium"),
            category=fd.get("zone", "general"),
            location=location,
            description=fd.get("message", ""),
            recommendation=f"Review {fd.get('rule_id', 'finding')}",
            provable=provable,
        ))
    return mapped


def fetch_pr_diff(pr: PullRequest) -> str:
    """Fetch the diff content for a PR."""
    stub_path = os.environ.get("STUB_DIFF_PATH")
    if stub_path:
        path = Path(stub_path)
        if not path.is_absolute():
            workspace = Path(os.environ.get("GITHUB_WORKSPACE", ".")).resolve()
            path = workspace / path
        if path.exists():
            return path.read_text(encoding="utf-8")
        print(f"::error::STUB_DIFF_PATH set but file not found: {path}")
        sys.exit(1)

    import requests

    diff_url = pr.diff_url
    response = requests.get(diff_url, timeout=30)
    response.raise_for_status()
    return response.text


def set_output(name: str, value: str):
    """Set GitHub Actions output."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{name}={value}\n")
    else:
        # Fallback for older runners
        print(f"::set-output name={name}::{value}")


if __name__ == "__main__":
    main()
