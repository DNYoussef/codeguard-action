"""
Risk Classifier - Assigns risk tiers (L0-L4) based on analysis.
"""

import re
import copy
from pathlib import Path
from typing import Any
from dataclasses import dataclass

import yaml

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

    # Rubric-specific rules
    RUBRICS = {
        "default": {},
        "soc2": {
            "CC6.1": {"pattern": r"(auth|access|permission)", "severity": "high", "message": "Change management control affected"},
            "CC6.2": {"pattern": r"(user|account|provision)", "severity": "medium", "message": "Access provisioning affected"},
            "CC7.1": {"pattern": r"(CVE|vulnerab|patch|security)", "severity": "critical", "message": "Vulnerability management"},
            "CC8.1": {"pattern": r"(terraform|kubernetes|docker|infra)", "severity": "high", "message": "Infrastructure change"},
        },
        "hipaa": {
            "164.312.a": {"pattern": r"(phi|patient|medical|health)", "severity": "critical", "message": "PHI access control affected"},
            "164.312.b": {"pattern": r"(audit|log|trail)", "severity": "high", "message": "Audit control affected"},
            "164.312.e": {"pattern": r"(encrypt|tls|ssl|https)", "severity": "critical", "message": "Transmission security"},
        },
        "pci-dss": {
            "3.4": {"pattern": r"(pan|card.number|credit)", "severity": "critical", "message": "Cardholder data handling"},
            "6.5": {"pattern": r"(sql|inject|xss|csrf)", "severity": "critical", "message": "Secure coding requirement"},
            "8.3": {"pattern": r"(password|mfa|auth)", "severity": "high", "message": "Authentication control"},
        },
    }

    DEFAULT_ZONE_SEVERITY = {
        "payment": "critical",
        "crypto": "critical",
        "pii": "critical",
        "command_injection": "critical",
        "deserialization": "critical",
        "xss": "high",
        "auth": "high",
        "security": "high",
        "database": "high",
        "template_injection": "high",
        "path_traversal": "high",
        "weak_crypto": "high",
        "config": "medium",
        "infra": "medium",
    }

    DEFAULT_SIZE_THRESHOLDS = {
        "large": 500,
        "medium": 100,
        "small": 20,
    }

    def __init__(
        self,
        rubric: str = "default",
        rubric_path: str | Path | None = None,
        policy_path: str | Path | None = None,
        repo_root: str | Path | None = None,
    ):
        """Initialize classifier with rubric and optional policy overrides."""
        self.rubric = rubric
        self.repo_root = Path(repo_root) if repo_root else None
        self.rubric_path = Path(rubric_path) if rubric_path else None

        # If no explicit rubric path and rubric not built-in, try repo-local rubrics
        if not self.rubric_path and rubric not in self.RUBRICS and self.repo_root:
            for candidate_dir in [
                self.repo_root / ".codeguard" / "rubrics",
                self.repo_root / ".github" / "codeguard" / "rubrics",
                self.repo_root / "rubrics",
            ]:
                for ext in (".yaml", ".yml"):
                    candidate = candidate_dir / f"{rubric}{ext}"
                    if candidate.exists():
                        self.rubric_path = candidate
                        break
                if self.rubric_path:
                    break

        # Mutable copies of defaults so policy overrides don't leak across runs
        self.file_patterns = copy.deepcopy(self.FILE_PATTERNS)
        self.zone_severity = dict(self.DEFAULT_ZONE_SEVERITY)
        self.size_thresholds = dict(self.DEFAULT_SIZE_THRESHOLDS)

        self.rubric_rules, self.rubric_errors = self._load_rubric_rules()

        if policy_path:
            self._load_policy(Path(policy_path))

    def _load_rubric_rules(self) -> tuple[list[dict], list[str]]:
        """Load rubric rules from built-ins or a YAML file."""
        rules: list[dict] = []
        errors: list[str] = []

        if self.rubric_path:
            if not self.rubric_path.exists():
                raise FileNotFoundError(f"Rubric file not found: {self.rubric_path}")
            try:
                raw = yaml.safe_load(self.rubric_path.read_text()) or {}
            except Exception as exc:
                raise ValueError(f"Failed to parse rubric YAML {self.rubric_path}: {exc}") from exc

            raw_rules = raw.get("rules") if isinstance(raw, dict) else raw
            if isinstance(raw_rules, dict):
                iterable = [{"id": rid, **val} for rid, val in raw_rules.items()]
            elif isinstance(raw_rules, list):
                iterable = raw_rules
            else:
                iterable = []

            for idx, rule in enumerate(iterable):
                try:
                    compiled = re.compile(rule["pattern"], re.IGNORECASE)
                except Exception as exc:
                    errors.append(f"Rule {rule.get('id') or idx} skipped: {exc}")
                    compiled = None
                rules.append({
                    "id": rule.get("id") or f"rule_{idx}",
                    "severity": rule.get("severity", "medium"),
                    "message": rule.get("message", "Policy rule triggered"),
                    "pattern": rule.get("pattern", ""),
                    "compiled": compiled,
                })
        else:
            for rid, rule in self.RUBRICS.get(self.rubric, {}).items():
                try:
                    compiled = re.compile(rule["pattern"], re.IGNORECASE)
                except Exception as exc:
                    errors.append(f"Rule {rid} skipped: {exc}")
                    compiled = None
                rules.append({
                    "id": rid,
                    "severity": rule.get("severity", "medium"),
                    "message": rule.get("message", "Policy rule triggered"),
                    "pattern": rule.get("pattern", ""),
                    "compiled": compiled,
                })

        for err in errors:
            self._warn(err)
        return rules, errors

    def _load_policy(self, path: Path) -> None:
        """Load risk policy YAML to override patterns and thresholds."""
        if not path.exists():
            raise FileNotFoundError(f"Risk policy file not found: {path}")

        try:
            policy = yaml.safe_load(path.read_text()) or {}
        except Exception as exc:
            self._warn(f"Risk policy ignored (parse error): {exc}")
            return

        patterns = policy.get("file_patterns")
        if isinstance(patterns, dict):
            for tier, values in patterns.items():
                if tier in self.file_patterns and isinstance(values, list):
                    self.file_patterns[tier] = values

        zone_severity = policy.get("zone_severity")
        if isinstance(zone_severity, dict):
            for zone, sev in zone_severity.items():
                self.zone_severity[zone] = sev

        size_thresholds = policy.get("size_thresholds")
        if isinstance(size_thresholds, dict):
            self.size_thresholds["large"] = int(size_thresholds.get("large", self.size_thresholds["large"]))
            self.size_thresholds["medium"] = int(size_thresholds.get("medium", self.size_thresholds["medium"]))
            self.size_thresholds["small"] = int(size_thresholds.get("small", self.size_thresholds["small"]))

    def _warn(self, message: str) -> None:
        """Emit a warning in GitHub Actions-friendly format."""
        print(f"::warning::{message}")

    @staticmethod
    def _downgrade_severity(severity: str) -> str:
        """Downgrade severity by one level."""
        return {"critical": "high", "high": "medium", "medium": "low", "low": "info"}.get(severity, severity)

    def classify(self, analysis: dict[str, Any]) -> dict[str, Any]:
        """
        Classify risk based on analysis results.

        Uses three signal sources:
          1. Zone-based keyword findings (deterministic)
          2. Rubric rule findings (deterministic)
          3. AI multi-model consensus (when available) to modulate severity

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

        # --- AI Consensus Modulation ---
        # When AI models reviewed the diff, use their consensus to adjust
        # finding severity. This reduces FPs (AI approves benign keyword
        # matches) and catches FNs (AI flags issues rules missed).
        consensus_risk = analysis.get("consensus_risk", "")
        agreement_score = analysis.get("agreement_score", 0.0)

        if consensus_risk == "approve" and agreement_score >= 0.6:
            # AI majority approved: double-downgrade zone-only findings.
            # Threshold 0.6 = simple majority (2/3 at L3, unanimous at L1/L2).
            # Double downgrade (critical->medium, high->low) drops findings
            # below DecisionEngine condition_rules (high+provable), making
            # them advisory-only. Semantically correct: zone findings are
            # keyword matches, and the AI confirmed they're safe.
            # Rubric findings are NOT downgraded (they are organizational policy).
            for f in findings:
                if f.zone and not f.rule_id.startswith("RUBRIC"):
                    f.severity = self._downgrade_severity(f.severity)
                    f.severity = self._downgrade_severity(f.severity)

        elif consensus_risk == "request_changes" and agreement_score >= 0.6:
            # AI flagged issues: upgrade medium findings to high
            for f in findings:
                if f.severity == "medium":
                    f.severity = "high"
            # Inject AI concern findings (non-provable, so they can only
            # trigger MERGE-WITH-CONDITIONS via DecisionEngine, never BLOCK)
            mmr = analysis.get("multi_model_review", {})
            ai_concerns = []
            if mmr.get("consensus"):
                ai_concerns = mmr["consensus"].get("combined_concerns", [])
            elif ai_summary.get("concerns"):
                ai_concerns = ai_summary["concerns"]
            for idx, concern in enumerate(ai_concerns[:3]):
                findings.append(Finding(
                    id=f"AI-CONCERN-{idx}",
                    severity="high",
                    message=f"AI concern: {concern}",
                    file="",
                    line=None,
                    rule_id="ai-consensus",
                    zone=None,
                ))

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
            for pattern in self.file_patterns["L4"]:
                if re.search(pattern, path, re.IGNORECASE):
                    max_score = max(max_score, 4)

            for pattern in self.file_patterns["L3"]:
                if re.search(pattern, path, re.IGNORECASE):
                    max_score = max(max_score, 3)

            # L0 patterns reduce score (but don't override higher)
            is_trivial = any(
                re.search(p, path, re.IGNORECASE)
                for p in self.file_patterns["L0"]
            )
            is_test = any(
                re.search(p, path, re.IGNORECASE)
                for p in self.file_patterns["L1"]
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

        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_score = 0

        for z in zones:
            sev = self.zone_severity.get(z.get("zone"), "medium")
            max_score = max(max_score, severity_rank.get(sev, 2))

        return max_score

    def _score_size(self, analysis: dict) -> int:
        """Score based on change size."""
        added = analysis.get("lines_added", 0)
        removed = analysis.get("lines_removed", 0)
        total = added + removed

        if total > self.size_thresholds["large"]:
            return 3  # Large changes need review
        elif total > self.size_thresholds["medium"]:
            return 2
        elif total > self.size_thresholds["small"]:
            return 1
        return 0

    def _collect_findings(self, files: list, zones: list) -> list[Finding]:
        """Collect findings from analysis."""
        findings = []

        for zone in zones:
            severity = self.zone_severity.get(zone["zone"], "medium")
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

    def _find_match_line(self, pattern: re.Pattern, file: dict) -> int | None:
        """Return first matching line number for a rule within a file change."""
        for hunk in file.get("hunks", []):
            for line in hunk.get("lines", []):
                if line.get("type") not in ("add", "remove"):
                    continue
                try:
                    if pattern.search(line.get("content", "")):
                        return line.get("line_number")
                except re.error as exc:
                    self._warn(f"Rubric regex error: {exc}")
                    return None
        return None

    def _apply_rubric(self, files: list) -> list[Finding]:
        """Apply rubric-specific rules."""
        findings = []

        for file in files:
            path = file.get("path", "")
            for rule in self.rubric_rules:
                compiled = rule.get("compiled")
                if not compiled:
                    continue

                try:
                    matched_line = self._find_match_line(compiled, file)
                    path_match = compiled.search(path)
                    if matched_line is None and not path_match:
                        continue
                except re.error as exc:
                    self._warn(f"Rubric rule {rule.get('id')} skipped: {exc}")
                    continue

                findings.append(Finding(
                    id=f"RUBRIC-{rule.get('id')}",
                    severity=rule.get("severity", "medium"),
                    message=rule.get("message", "Policy rule triggered"),
                    file=path,
                    line=matched_line,
                    rule_id=rule.get("id", ""),
                ))

        return findings

    def _calculate_drivers(
        self, files: list, zones: list, findings: list, ai_summary: dict
    ) -> list[dict]:
        """Calculate top risk drivers."""
        drivers = []

        # Zone-based drivers - include affected files so reviewers know WHERE
        zone_info: dict[str, dict] = {}
        for z in zones:
            zn = z["zone"]
            if zn not in zone_info:
                zone_info[zn] = {"count": 0, "locations": []}
            zone_info[zn]["count"] += 1
            loc = z.get("file", "")
            line = z.get("line")
            ref = f"{loc}:{line}" if loc and line else loc
            if ref and ref not in zone_info[zn]["locations"]:
                zone_info[zn]["locations"].append(ref)

        for zone, info in sorted(zone_info.items(), key=lambda x: -x[1]["count"])[:3]:
            locs = info["locations"][:3]  # top 3 locations
            loc_str = ", ".join(f"`{l}`" for l in locs)
            if len(info["locations"]) > 3:
                loc_str += f" +{len(info['locations']) - 3} more"
            desc = f"{info['count']} changes in {zone} code"
            if loc_str:
                desc += f" ({loc_str})"
            drivers.append({
                "type": "sensitive_zone",
                "zone": zone,
                "count": info["count"],
                "locations": info["locations"],
                "description": desc,
            })

        # Finding-based drivers - include file/line
        for finding in sorted(findings, key=lambda f: {"critical": 0, "high": 1, "medium": 2}.get(f.severity, 3))[:3]:
            desc = finding.message
            if finding.file:
                loc = finding.file
                if finding.line:
                    loc += f":{finding.line}"
                desc += f" (`{loc}`)"
            drivers.append({
                "type": "policy_finding",
                "rule": finding.rule_id,
                "severity": finding.severity,
                "file": finding.file,
                "line": finding.line,
                "description": desc,
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
