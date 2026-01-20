"""
Diff Analyzer - Parses and analyzes PR diffs.
"""

import re
from typing import Any, Optional
from dataclasses import dataclass, field
from unidiff import PatchSet


@dataclass
class FileChange:
    """Represents a changed file."""
    path: str
    added_lines: int
    removed_lines: int
    hunks: list[dict] = field(default_factory=list)
    is_new: bool = False
    is_deleted: bool = False


class DiffAnalyzer:
    """Analyzes PR diffs for risk assessment."""

    # Sensitive patterns that increase risk
    SENSITIVE_PATTERNS = {
        "auth": r"(auth|login|password|credential|token|secret|api.?key)",
        "payment": r"(payment|billing|credit.?card|stripe|paypal|transaction)",
        "crypto": r"(encrypt|decrypt|hash|sign|verify|private.?key|public.?key)",
        "database": r"(sql|query|execute|cursor|connection|migrate)",
        "security": r"(security|permission|access|role|admin|privilege)",
        "pii": r"(email|phone|address|ssn|social.?security|date.?of.?birth)",
        "config": r"(config|setting|environment|env\.|\.env)",
        "infra": r"(terraform|kubernetes|docker|aws|azure|gcp|cloudformation)",
    }

    def __init__(self, openai_key: str = None, anthropic_key: str = None):
        """Initialize analyzer with optional AI backends."""
        self.openai_key = openai_key
        self.anthropic_key = anthropic_key
        self.ai_enabled = bool(openai_key or anthropic_key)

    def analyze(self, diff_content: str, rubric: str = "default") -> dict[str, Any]:
        """
        Analyze a diff and return structured analysis.

        Returns:
            Dict with keys: files_changed, lines_added, lines_removed,
            files, sensitive_zones, ai_summary (if AI enabled)
        """
        try:
            patch = PatchSet(diff_content)
        except Exception as e:
            return self._fallback_analysis(diff_content)

        files = []
        total_added = 0
        total_removed = 0
        sensitive_zones = []

        for patched_file in patch:
            file_change = FileChange(
                path=patched_file.path,
                added_lines=patched_file.added,
                removed_lines=patched_file.removed,
                is_new=patched_file.is_added_file,
                is_deleted=patched_file.is_removed_file,
            )

            # Extract hunks
            for hunk in patched_file:
                hunk_data = {
                    "source_start": hunk.source_start,
                    "source_length": hunk.source_length,
                    "target_start": hunk.target_start,
                    "target_length": hunk.target_length,
                    "lines": []
                }

                for line in hunk:
                    line_data = {
                        "type": "add" if line.is_added else ("remove" if line.is_removed else "context"),
                        "content": line.value.rstrip("\n"),
                        "line_number": line.target_line_no if line.is_added else line.source_line_no
                    }
                    hunk_data["lines"].append(line_data)

                    # Check for sensitive patterns
                    if line.is_added or line.is_removed:
                        for zone_name, pattern in self.SENSITIVE_PATTERNS.items():
                            if re.search(pattern, line.value, re.IGNORECASE):
                                sensitive_zones.append({
                                    "zone": zone_name,
                                    "file": patched_file.path,
                                    "line": line_data["line_number"],
                                    "content_preview": line.value[:100].strip()
                                })

                file_change.hunks.append(hunk_data)

            files.append({
                "path": file_change.path,
                "added": file_change.added_lines,
                "removed": file_change.removed_lines,
                "is_new": file_change.is_new,
                "is_deleted": file_change.is_deleted,
                "hunks": file_change.hunks
            })

            total_added += file_change.added_lines
            total_removed += file_change.removed_lines

        result = {
            "files_changed": len(files),
            "lines_added": total_added,
            "lines_removed": total_removed,
            "files": files,
            "sensitive_zones": sensitive_zones,
            "diff_hash": self._hash_diff(diff_content),
        }

        # Add AI summary if enabled
        if self.ai_enabled:
            result["ai_summary"] = self._generate_ai_summary(diff_content, sensitive_zones)

        return result

    def _fallback_analysis(self, diff_content: str) -> dict[str, Any]:
        """Fallback analysis when unidiff parsing fails."""
        lines = diff_content.split("\n")
        added = sum(1 for l in lines if l.startswith("+") and not l.startswith("+++"))
        removed = sum(1 for l in lines if l.startswith("-") and not l.startswith("---"))

        return {
            "files_changed": diff_content.count("diff --git"),
            "lines_added": added,
            "lines_removed": removed,
            "files": [],
            "sensitive_zones": [],
            "diff_hash": self._hash_diff(diff_content),
            "parse_error": True
        }

    def _hash_diff(self, diff_content: str) -> str:
        """Generate SHA-256 hash of diff content."""
        import hashlib
        return f"sha256:{hashlib.sha256(diff_content.encode()).hexdigest()}"

    def _generate_ai_summary(self, diff_content: str, sensitive_zones: list) -> dict:
        """Generate AI-powered summary of changes."""
        try:
            if self.anthropic_key:
                return self._anthropic_summary(diff_content, sensitive_zones)
            elif self.openai_key:
                return self._openai_summary(diff_content, sensitive_zones)
        except Exception as e:
            return {"error": str(e), "fallback": True}

        return {"summary": "AI analysis not available", "fallback": True}

    def _anthropic_summary(self, diff_content: str, sensitive_zones: list) -> dict:
        """Generate summary using Anthropic Claude."""
        import anthropic

        client = anthropic.Anthropic(api_key=self.anthropic_key)

        prompt = f"""Analyze this code diff and provide:
1. A one-sentence summary of what changed
2. The primary intent (feature, bugfix, refactor, config, security)
3. Any concerns for a security/compliance reviewer

Sensitive zones detected: {len(sensitive_zones)}
{', '.join(set(z['zone'] for z in sensitive_zones[:5])) if sensitive_zones else 'None'}

Diff (truncated to 4000 chars):
{diff_content[:4000]}

Respond in JSON format:
{{"summary": "...", "intent": "...", "concerns": ["...", "..."]}}"""

        response = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )

        import json
        try:
            return json.loads(response.content[0].text)
        except:
            return {"summary": response.content[0].text, "raw": True}

    def _openai_summary(self, diff_content: str, sensitive_zones: list) -> dict:
        """Generate summary using OpenAI."""
        import openai

        client = openai.OpenAI(api_key=self.openai_key)

        prompt = f"""Analyze this code diff and provide:
1. A one-sentence summary of what changed
2. The primary intent (feature, bugfix, refactor, config, security)
3. Any concerns for a security/compliance reviewer

Sensitive zones detected: {len(sensitive_zones)}

Diff (truncated):
{diff_content[:4000]}

Respond in JSON: {{"summary": "...", "intent": "...", "concerns": [...]}}"""

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500
        )

        import json
        try:
            return json.loads(response.choices[0].message.content)
        except:
            return {"summary": response.choices[0].message.content, "raw": True}
