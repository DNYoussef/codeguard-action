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


def get_env(name: str, default: str = "") -> str:
    """Get environment variable with default."""
    return os.environ.get(name, default)


def parse_bool(value: str) -> bool:
    """Parse boolean from string."""
    return value.lower() in ("true", "1", "yes")


def main():
    """Main entrypoint for the action."""
    # Parse inputs from environment (set by GitHub Actions)
    risk_threshold = get_env("INPUT_RISK_THRESHOLD", "L3")
    rubric = get_env("INPUT_RUBRIC", "default")
    github_token = get_env("INPUT_GITHUB_TOKEN")
    post_comment = parse_bool(get_env("INPUT_POST_COMMENT", "true"))
    generate_bundle = parse_bool(get_env("INPUT_GENERATE_BUNDLE", "true"))
    upload_sarif = parse_bool(get_env("INPUT_UPLOAD_SARIF", "false"))
    fail_on_high_risk = parse_bool(get_env("INPUT_FAIL_ON_HIGH_RISK", "true"))

    # Optional AI API keys
    openai_key = get_env("INPUT_OPENAI_API_KEY") or get_env("OPENAI_API_KEY")
    anthropic_key = get_env("INPUT_ANTHROPIC_API_KEY") or get_env("ANTHROPIC_API_KEY")
    openrouter_key = get_env("INPUT_OPENROUTER_API_KEY") or get_env("OPENROUTER_API_KEY")
    openrouter_model = get_env("INPUT_OPENROUTER_MODEL", "anthropic/claude-sonnet-4")

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
        openrouter_model=openrouter_model
    )
    analysis = analyzer.analyze(diff_content, rubric=rubric)
    print(f"Files changed: {analysis['files_changed']}")
    print(f"Lines added: {analysis['lines_added']}")
    print(f"Lines removed: {analysis['lines_removed']}")
    print("::endgroup::")

    # Classify risk
    print("::group::Classifying risk")
    classifier = RiskClassifier(rubric=rubric)
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

    # Set outputs
    set_output("risk_tier", risk_tier)
    set_output("risk_drivers", json.dumps(risk_drivers))
    set_output("findings_count", str(len(findings)))
    set_output("requires_approval", str(requires_approval).lower())

    # Post PR comment
    if post_comment:
        print("::group::Posting PR comment")
        commenter = PRCommenter(gh, repo, pr)
        commenter.post_summary(
            risk_tier=risk_tier,
            risk_drivers=risk_drivers,
            findings=findings,
            requires_approval=requires_approval,
            threshold=risk_threshold
        )
        print("Comment posted")
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
        bundle_dir = Path(get_env("GITHUB_WORKSPACE", ".")) / ".guardspine"
        bundle_dir.mkdir(exist_ok=True)
        bundle_path = bundle_dir / f"bundle-pr{pr_number}-{github_sha[:7]}.json"

        with open(bundle_path, "w") as f:
            json.dump(bundle, f, indent=2, default=str)

        set_output("bundle_path", str(bundle_path))
        print(f"Bundle saved: {bundle_path}")
        print(f"Bundle ID: {bundle['bundle_id']}")
        print("::endgroup::")

        # Upload as artifact
        print(f"::notice::Evidence bundle generated: {bundle_path}")

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

    # Determine exit status
    if requires_approval and fail_on_high_risk:
        print(f"::warning::Risk tier {risk_tier} exceeds threshold {risk_threshold}")
        print("::warning::Human approval required before merge")

        # Create check annotation
        print(f"::error file=GUARDSPINE::Risk tier {risk_tier} requires human approval. "
              f"Review the Diff Postcard and approve in GuardSpine.")

        sys.exit(1)
    else:
        print(f"::notice::Risk tier {risk_tier} - auto-approved")
        sys.exit(0)


def fetch_pr_diff(pr: PullRequest) -> str:
    """Fetch the diff content for a PR."""
    import requests

    diff_url = pr.diff_url
    response = requests.get(diff_url)
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
