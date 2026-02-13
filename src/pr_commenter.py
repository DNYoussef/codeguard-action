from __future__ import annotations
"""
PR Commenter - Posts risk summaries as PR comments.
"""

from typing import Any
from github import Github
from github.Repository import Repository
from github.PullRequest import PullRequest


class PRCommenter:
    """
    Posts GuardSpine analysis summaries as PR comments.

    Creates a "Diff Postcard" summary showing:
    - Risk tier with visual indicator
    - Top risk drivers
    - Findings summary
    - Approval requirements
    """

    COMMENT_MARKER = "<!-- guardspine-codeguard -->"

    # Risk tier badges and colors
    TIER_INFO = {
        "L0": {"emoji": "white_check_mark", "label": "Trivial", "color": "brightgreen"},
        "L1": {"emoji": "large_blue_circle", "label": "Low Risk", "color": "blue"},
        "L2": {"emoji": "yellow_circle", "label": "Medium Risk", "color": "yellow"},
        "L3": {"emoji": "orange_circle", "label": "High Risk", "color": "orange"},
        "L4": {"emoji": "red_circle", "label": "Critical Risk", "color": "red"},
    }

    def __init__(self, gh: Github, repo: Repository, pr: PullRequest):
        """Initialize commenter with GitHub objects."""
        self.gh = gh
        self.repo = repo
        self.pr = pr

    def post_summary(
        self,
        risk_tier: str,
        risk_drivers: list[dict],
        findings: list[dict],
        requires_approval: bool,
        threshold: str = "L3"
    ) -> None:
        """
        Post or update the GuardSpine summary comment.

        Args:
            risk_tier: Risk classification (L0-L4)
            risk_drivers: List of risk driver dicts
            findings: List of finding dicts
            requires_approval: Whether human approval is needed
            threshold: Configured threshold for blocking
        """
        comment_body = self._build_comment(
            risk_tier=risk_tier,
            risk_drivers=risk_drivers,
            findings=findings,
            requires_approval=requires_approval,
            threshold=threshold
        )

        # Check for existing comment to update
        existing_comment = self._find_existing_comment()

        if existing_comment:
            existing_comment.edit(comment_body)
        else:
            self.pr.create_issue_comment(comment_body)

    def _find_existing_comment(self):
        """Find existing GuardSpine comment if any."""
        for comment in self.pr.get_issue_comments():
            if self.COMMENT_MARKER in comment.body:
                return comment
        return None

    def _build_comment(
        self,
        risk_tier: str,
        risk_drivers: list[dict],
        findings: list[dict],
        requires_approval: bool,
        threshold: str
    ) -> str:
        """Build the comment markdown."""
        tier_info = self.TIER_INFO.get(risk_tier, self.TIER_INFO["L2"])

        # Header with badge
        lines = [
            self.COMMENT_MARKER,
            "",
            "## :shield: GuardSpine Diff Postcard",
            "",
            f"### Risk Assessment: :{tier_info['emoji']}: **{risk_tier}** - {tier_info['label']}",
            "",
        ]

        # Status banner
        if requires_approval:
            lines.extend([
                "> :warning: **Human approval required** - Risk tier exceeds threshold ({threshold})",
                "",
            ])
        else:
            lines.extend([
                "> :white_check_mark: **Auto-approved** - Risk within acceptable threshold",
                "",
            ])

        # Risk drivers section
        if risk_drivers:
            lines.extend([
                "### Risk Drivers",
                "",
            ])
            for driver in risk_drivers[:5]:
                driver_type = driver.get("type", "unknown")
                description = driver.get("description", "No description")

                if driver_type == "sensitive_zone":
                    emoji = ":lock:"
                elif driver_type == "policy_finding":
                    severity = driver.get("severity", "medium")
                    emoji = ":rotating_light:" if severity == "critical" else ":warning:"
                elif driver_type == "ai_concern":
                    emoji = ":robot:"
                else:
                    emoji = ":pushpin:"

                lines.append(f"- {emoji} {description}")

            lines.append("")

        # Findings summary
        if findings:
            lines.extend([
                "### Findings Summary",
                "",
                "| Severity | Count | Top Finding |",
                "|----------|-------|-------------|",
            ])

            # Group by severity
            severity_groups = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
            for finding in findings:
                sev = finding.get("severity", "medium")
                if sev in severity_groups:
                    severity_groups[sev].append(finding)

            for severity in ["critical", "high", "medium", "low", "info"]:
                group = severity_groups[severity]
                if group:
                    count = len(group)
                    top_msg = group[0].get("message", "")[:50]
                    emoji = self._severity_emoji(severity)
                    lines.append(f"| {emoji} {severity.capitalize()} | {count} | {top_msg} |")

            lines.append("")

        # Details section (collapsible)
        if findings:
            lines.extend([
                "<details>",
                "<summary>View all findings</summary>",
                "",
            ])

            for finding in findings[:20]:  # Limit to 20
                file_path = finding.get("file", "unknown")
                line = finding.get("line")
                message = finding.get("message", "No message")
                severity = finding.get("severity", "medium")
                rule_id = finding.get("rule_id", "")

                location = f"`{file_path}"
                if line:
                    location += f":{line}"
                location += "`"

                lines.append(f"- **[{severity.upper()}]** {location}: {message}")
                if rule_id:
                    lines.append(f"  - Rule: `{rule_id}`")

            if len(findings) > 20:
                lines.append(f"\n*...and {len(findings) - 20} more findings*")

            lines.extend([
                "",
                "</details>",
                "",
            ])

        # Footer
        lines.extend([
            "---",
            "",
            ":information_source: *Generated by [GuardSpine CodeGuard](https://github.com/marketplace/actions/guardspine-codeguard)*",
            "",
            f"<sub>Evidence bundle available in workflow artifacts | Threshold: {threshold}</sub>",
        ])

        return "\n".join(lines)

    def _severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level."""
        return {
            "critical": ":red_circle:",
            "high": ":orange_circle:",
            "medium": ":yellow_circle:",
            "low": ":large_blue_circle:",
            "info": ":white_circle:",
        }.get(severity, ":white_circle:")

    def post_decision_card(self, decision_card_md: str) -> None:
        """
        Post or update the Decision Card comment.

        Args:
            decision_card_md: Pre-rendered markdown from render_decision_card()
        """
        body = f"{self.COMMENT_MARKER}\n\n{decision_card_md}"

        existing = self._find_existing_comment()
        if existing:
            existing.edit(body)
        else:
            self.pr.create_issue_comment(body)

    def post_approval_request(
        self,
        risk_tier: str,
        required_approvers: list[str] = None
    ) -> None:
        """
        Post a comment requesting approval from specific users.

        Args:
            risk_tier: Current risk tier
            required_approvers: List of GitHub usernames to request
        """
        lines = [
            self.COMMENT_MARKER + "-approval",
            "",
            f"## :rotating_light: Approval Required",
            "",
            f"This PR has been classified as **{risk_tier}** and requires human approval before merge.",
            "",
        ]

        if required_approvers:
            mentions = " ".join(f"@{u}" for u in required_approvers)
            lines.extend([
                f"**Requested reviewers:** {mentions}",
                "",
            ])

        lines.extend([
            "Please review the Diff Postcard above and:",
            "1. Verify the changes match the PR description",
            "2. Confirm risk assessment is appropriate",
            "3. Approve this PR to unblock merge",
            "",
        ])

        self.pr.create_issue_comment("\n".join(lines))
