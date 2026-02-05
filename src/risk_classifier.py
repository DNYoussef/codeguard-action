"""
Risk Classifier - Assigns risk tiers (L0-L4) based on analysis.
"""

import re
from pathlib import Path
from typing import Any
from dataclasses import dataclass

import yaml


# Directory containing built-in rubric files
BUILTIN_RUBRICS_DIR = Path(__file__).parent.parent / "rubrics"


@dataclass
class Finding:
    """A policy finding."""
    id: str
    severity: str  # info, low, medium, high, critical
    message: str
    file: str
    line: int | None
    rule_id: str
    zone: str | None = None


class RiskClassifier:
    """
    Classifies code changes into risk tiers.

    L0: Trivial - docs, comments, formatting
    L1: Low - minor changes, tests
    L2: Medium - feature code, non-sensitive
    L3: High - sensitive areas, needs review
    L4: Critical - security, payments, PII
    """

    # File patterns for risk assessment
    FILE_PATTERNS = {
        "L0": [
            r"\.md$", r"\.txt$", r"\.rst$",  # docs
            r"LICENSE", r"CHANGELOG", r"README",
            r"\.gitignore$", r"\.editorconfig$",
        ],
        "L1": [
            r"test[s]?/", r"spec[s]?/", r"__test__",
            r"\.test\.", r"\.spec\.", r"_test\.py$",
            r"mock", r"fixture",
        ],
        "L3": [
            r"auth", r"login", r"session",
            r"permission", r"role", r"access",
            r"middleware", r"interceptor",
            r"config", r"setting", r"\.env",
        ],
        "L4": [
            r"payment", r"billing", r"transaction",
            r"credit", r"stripe", r"paypal",
            r"encrypt", r"decrypt", r"secret",
            r"password", r"credential", r"token",
            r"ssn", r"social.security", r"pii",
            r"hipaa", r"gdpr", r"compliance",
        ],
    }

    def __init__(self, rubric: str = "default", repo_root: str | Path | None = None):
        """
        Initialize classifier with rubric.
        
        Args:
            rubric: Name of the rubric to load (e.g., "default", "soc2", "hipaa")
            repo_root: Path to the repository root. If provided, rubrics will be
                      searched in the repo's .codeguard/rubrics/ or rubrics/ 
                      directories before falling back to built-in rubrics.
        """
        self.rubric = rubric
        self.repo_root = Path(repo_root) if repo_root else None
        self.rubric_rules = self._load_rubric(rubric)

    def _load_rubric(self, rubric: str) -> dict[str, dict]:
        """
        Load rubric rules from YAML file.
        
        Search order:
        1. <repo_root>/.codeguard/rubrics/<rubric>.yaml
        2. <repo_root>/rubrics/<rubric>.yaml  
        3. Built-in: rubrics/builtin/<rubric>.yaml
        4. Built-in: rubrics/builtin/<rubric>-*.yaml (partial match)
        5. Built-in: rubrics/<rubric>.yaml
        
        Returns dict mapping rule_id to {pattern, severity, message}.
        """
        rules = {}
        candidates = []
        
        # Check repository-local rubrics first
        if self.repo_root:
            repo_rubric_dirs = [
                self.repo_root / ".codeguard" / "rubrics",
                self.repo_root / ".github" / "codeguard" / "rubrics",
                self.repo_root / "rubrics",
            ]
            for rubric_dir in repo_rubric_dirs:
                candidates.append(rubric_dir / f"{rubric}.yaml")
                candidates.append(rubric_dir / f"{rubric}.yml")
        
        # Built-in rubrics (exact match first)
        candidates.extend([
            BUILTIN_RUBRICS_DIR / "builtin" / f"{rubric}.yaml",
            BUILTIN_RUBRICS_DIR / f"{rubric}.yaml",
        ])
        
        # Also check for partial matches in builtin (e.g., "soc2" matches "soc2-controls.yaml")
        builtin_dir = BUILTIN_RUBRICS_DIR / "builtin"
        if builtin_dir.exists():
            for f in builtin_dir.glob(f"{rubric}*.yaml"):
                if f not in candidates:
                    candidates.append(f)
            for f in builtin_dir.glob(f"*{rubric}*.yaml"):
                if f not in candidates:
                    candidates.append(f)
        
        # Find first existing file
        rubric_file = None
        for candidate in candidates:
            if candidate.exists():
                rubric_file = candidate
                break
        
        if rubric_file is None:
            return rules
        
        try:
            with open(rubric_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except (yaml.YAMLError, OSError):
            return rules
        
        if not data or "rules" not in data:
            return rules
        
        for rule in data.get("rules", []):
            rule_id = rule.get("id", "")
            patterns = rule.get("patterns", [])
            severity = rule.get("severity", "medium")
            message = rule.get("description") or rule.get("name", "Policy violation")
            
            if rule_id and patterns:
                # Combine patterns with OR
                combined_pattern = "|".join(f"({p})" for p in patterns)
                rules[rule_id] = {
                    "pattern": combined_pattern,
                    "severity": severity,
                    "message": message,
                }
        
        return rules

    def classify(self, analysis: dict[str, Any]) -> dict[str, Any]:
        """
        Classify risk based on analysis results.

        Returns:
            Dict with: risk_tier, risk_drivers, findings, rationale
        """
        files = analysis.get("files", [])
        sensitive_zones = analysis.get("sensitive_zones", [])
        ai_summary = analysis.get("ai_summary", {})

        # Calculate scores
        file_score = self._score_files(files)
        zone_score = self._score_zones(sensitive_zones)
        size_score = self._score_size(analysis)

        # Collect findings
        findings = self._collect_findings(files, sensitive_zones)

        # Apply rubric rules
        rubric_findings = self._apply_rubric(files)
        findings.extend(rubric_findings)

        # Calculate risk drivers
        risk_drivers = self._calculate_drivers(
            files, sensitive_zones, findings, ai_summary
        )

        # Determine final tier
        max_score = max(file_score, zone_score, size_score)

        # Boost for rubric findings
        if any(f.severity == "critical" for f in findings):
            max_score = max(max_score, 4)
        elif any(f.severity == "high" for f in findings):
            max_score = max(max_score, 3)

        risk_tier = f"L{min(max_score, 4)}"

        return {
            "risk_tier": risk_tier,
            "risk_drivers": risk_drivers,
            "findings": [self._finding_to_dict(f) for f in findings],
            "scores": {
                "file_patterns": file_score,
                "sensitive_zones": zone_score,
                "change_size": size_score,
            },
            "rationale": self._generate_rationale(risk_tier, risk_drivers, findings)
        }

    def _score_files(self, files: list) -> int:
        """Score based on file patterns."""
        max_score = 0

        for file in files:
            path = file.get("path", "")

            # Check L4 patterns first
            for pattern in self.FILE_PATTERNS["L4"]:
                if re.search(pattern, path, re.IGNORECASE):
                    max_score = max(max_score, 4)

            for pattern in self.FILE_PATTERNS["L3"]:
                if re.search(pattern, path, re.IGNORECASE):
                    max_score = max(max_score, 3)

            # L0 patterns reduce score (but don't override higher)
            is_trivial = any(
                re.search(p, path, re.IGNORECASE)
                for p in self.FILE_PATTERNS["L0"]
            )
            is_test = any(
                re.search(p, path, re.IGNORECASE)
                for p in self.FILE_PATTERNS["L1"]
            )

            if max_score == 0:
                if is_trivial:
                    max_score = 0
                elif is_test:
                    max_score = 1
                else:
                    max_score = 2

        return max_score

    def _score_zones(self, zones: list) -> int:
        """Score based on sensitive zones detected."""
        if not zones:
            return 0

        zone_types = set(z.get("zone") for z in zones)

        # Critical zones
        if zone_types & {"payment", "crypto", "pii"}:
            return 4

        # High zones
        if zone_types & {"auth", "security", "database"}:
            return 3

        # Medium zones
        if zone_types & {"config", "infra"}:
            return 2

        return 1

    def _score_size(self, analysis: dict) -> int:
        """Score based on change size."""
        added = analysis.get("lines_added", 0)
        removed = analysis.get("lines_removed", 0)
        total = added + removed

        if total > 500:
            return 3  # Large changes need review
        elif total > 100:
            return 2
        elif total > 20:
            return 1
        return 0

    def _collect_findings(self, files: list, zones: list) -> list[Finding]:
        """Collect findings from analysis."""
        findings = []

        for zone in zones:
            severity = "high" if zone["zone"] in {"payment", "crypto", "pii", "auth"} else "medium"
            findings.append(Finding(
                id=f"ZONE-{zone['zone'].upper()}",
                severity=severity,
                message=f"Sensitive {zone['zone']} code modified",
                file=zone["file"],
                line=zone.get("line"),
                rule_id=f"sensitive-{zone['zone']}",
                zone=zone["zone"]
            ))

        return findings

    def _apply_rubric(self, files: list) -> list[Finding]:
        """Apply rubric-specific rules."""
        findings = []

        for file in files:
            path = file.get("path", "")
            content = ""
            for hunk in file.get("hunks", []):
                for line in hunk.get("lines", []):
                    if line.get("type") in ("add", "remove"):
                        content += line.get("content", "") + "\n"

            for rule_id, rule in self.rubric_rules.items():
                if re.search(rule["pattern"], path + content, re.IGNORECASE):
                    findings.append(Finding(
                        id=f"RUBRIC-{rule_id}",
                        severity=rule["severity"],
                        message=rule["message"],
                        file=path,
                        line=None,
                        rule_id=rule_id,
                    ))

        return findings

    def _calculate_drivers(
        self, files: list, zones: list, findings: list, ai_summary: dict
    ) -> list[dict]:
        """Calculate top risk drivers."""
        drivers = []

        # Zone-based drivers
        zone_counts = {}
        for z in zones:
            zone_counts[z["zone"]] = zone_counts.get(z["zone"], 0) + 1

        for zone, count in sorted(zone_counts.items(), key=lambda x: -x[1])[:3]:
            drivers.append({
                "type": "sensitive_zone",
                "zone": zone,
                "count": count,
                "description": f"{count} changes in {zone} code"
            })

        # Finding-based drivers
        for finding in sorted(findings, key=lambda f: {"critical": 0, "high": 1, "medium": 2}.get(f.severity, 3))[:3]:
            drivers.append({
                "type": "policy_finding",
                "rule": finding.rule_id,
                "severity": finding.severity,
                "description": finding.message
            })

        # AI-based drivers
        if ai_summary.get("concerns"):
            for concern in ai_summary["concerns"][:2]:
                drivers.append({
                    "type": "ai_concern",
                    "description": concern
                })

        return drivers[:5]  # Top 5 drivers

    def _finding_to_dict(self, finding: Finding) -> dict:
        """Convert Finding to dict."""
        return {
            "id": finding.id,
            "severity": finding.severity,
            "message": finding.message,
            "file": finding.file,
            "line": finding.line,
            "rule_id": finding.rule_id,
            "zone": finding.zone,
        }

    def _generate_rationale(self, tier: str, drivers: list, findings: list) -> str:
        """Generate human-readable rationale."""
        if tier == "L0":
            return "Trivial change (documentation, formatting, or configuration only)"
        elif tier == "L1":
            return "Low-risk change (tests or non-critical code)"
        elif tier == "L2":
            return "Medium-risk change (feature code, review recommended)"
        elif tier == "L3":
            top_driver = drivers[0]["description"] if drivers else "sensitive code detected"
            return f"High-risk change: {top_driver}. Human approval required."
        else:  # L4
            critical_findings = [f for f in findings if f.severity == "critical"]
            if critical_findings:
                return f"Critical risk: {critical_findings[0].message}. Executive approval may be required."
            return "Critical risk: security, payment, or PII code affected. Executive approval required."
