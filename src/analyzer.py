"""
Diff Analyzer - Parses and analyzes PR diffs with tier-based multi-model review.

Architecture:
  L0: Rules-based only (no AI)
  L1: 1 model review
  L2: 2 models review + rubric evaluation
  L3: 3 models review + rubric evaluation
  L4: 3 models review + rubric evaluation + human approval required
"""

import re
import json
import concurrent.futures
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


@dataclass
class ModelReview:
    """A single model's review of the diff."""
    model_name: str
    provider: str
    summary: str
    intent: str
    concerns: list[str]
    risk_assessment: str  # "approve", "request_changes", "comment"
    confidence: float  # 0.0 - 1.0
    rubric_scores: dict[str, int] = field(default_factory=dict)  # rubric_id -> score (1-5)
    raw_response: str = ""
    error: str = ""


@dataclass
class MultiModelConsensus:
    """Aggregated result from multiple model reviews."""
    reviews: list[ModelReview]
    consensus_risk: str  # "approve", "request_changes", "comment"
    agreement_score: float  # 0.0 - 1.0 (how much models agree)
    combined_concerns: list[str]
    rubric_summary: dict[str, float]  # rubric_id -> average score
    dissenting_opinions: list[str]


class DiffAnalyzer:
    """
    Analyzes PR diffs with tier-based multi-model review.

    Tier-based review escalation:
      L0: Rules only (no AI)
      L1: 1 model
      L2: 2 models + rubric
      L3: 3 models + rubric
      L4: 3 models + rubric + human approval
    """

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
        "command_injection": r"(subprocess|os\.system|os\.popen|child_process|shell\s*=\s*True|exec\(|eval\(|spawn)",
        "deserialization": r"(pickle\.load|yaml\.load\(|yaml\.unsafe_load|marshal\.load|shelve\.open|jsonpickle|unserialize|readObject)",
        "template_injection": r"(render_template_string|Template\(|Jinja2|mako\.template|format_map|\.safe_substitute|mark_safe|Markup\(|server.?side.?template)",
        "path_traversal": r"(\.\./|\.\.\\|os\.path\.join|path\.join|send_file|sendFile|readFile|shutil\.(copy|move|copytree)|extractall|zipfile\.ZipFile|tarfile\.open)",
        "weak_crypto": r"(md5|sha1[^0-9]|DES\b|RC4|ECB|random\.random|random\.seed|Math\.random|weak.?hash|insecure.?random)",
        "xss": r"(<script|<img\s|onerror|onload|innerHTML|\.html\(|document\.write|mark_safe|Markup\(|\bResponse\s*\(.*<)",
    }

    # File patterns for preliminary risk tier estimation
    FILE_PATTERNS = {
        "L0": [r"\.md$", r"\.txt$", r"\.rst$", r"LICENSE", r"CHANGELOG", r"README", r"\.gitignore$"],
        "L1": [r"test[s]?/", r"spec[s]?/", r"__test__", r"\.test\.", r"\.spec\.", r"_test\.py$"],
        "L3": [r"auth", r"login", r"session", r"permission", r"role", r"access", r"middleware", r"config"],
        "L4": [r"payment", r"billing", r"transaction", r"credit", r"stripe", r"encrypt", r"decrypt",
               r"secret", r"password", r"credential", r"ssn", r"pii", r"hipaa", r"gdpr"],
    }

    # Models to use at each tier (in priority order)
    TIER_MODEL_COUNT = {
        "L0": 0,  # Rules only
        "L1": 1,  # Single model
        "L2": 2,  # Two models + rubric
        "L3": 3,  # Three models + rubric
        "L4": 3,  # Three models + rubric + human approval
    }

    # Default model configurations for each tier (updated Jan 2026)
    DEFAULT_MODELS = {
        # OpenRouter models (recommended - single API for multiple providers)
        "openrouter": [
            "anthropic/claude-4.5-sonnet",
            "openai/gpt-5.2",
            "google/gemini-3-flash",
        ],
        # Ollama models (for air-gapped/local deployments)
        "ollama": [
            "llama4",
            "mistral-large",
            "codellama-70b",
        ],
        # Direct API models
        "anthropic": ["claude-4.5-haiku"],
        "openai": ["gpt-5.2-mini"],
    }

    def __init__(
        self,
        openai_key: str = None,
        anthropic_key: str = None,
        openrouter_key: str = None,
        openrouter_model: str = None,
        ollama_host: str = None,
        ollama_model: str = None,
        # Model configuration - users can specify up to 3 models
        # Format: "provider/model" or just "model" for ollama
        model_1: str = None,  # Used for L1+
        model_2: str = None,  # Used for L2+
        model_3: str = None,  # Used for L3+
        ai_review: bool = True,  # Enable/disable AI review
    ):
        """
        Initialize analyzer with flexible multi-model configuration.

        Users can configure models in several ways:
        1. Just API keys - uses default models for that provider
        2. Explicit model_1/2/3 - uses exactly those models
        3. Mix - some explicit, some defaults

        Examples:
          # Use 3 OpenRouter models (recommended)
          DiffAnalyzer(openrouter_key="sk-...",
                       model_1="anthropic/claude-sonnet-4",
                       model_2="openai/gpt-4o",
                       model_3="google/gemini-pro")

          # Use 3 Ollama models (air-gapped)
          DiffAnalyzer(ollama_host="http://localhost:11434",
                       model_1="llama3.3",
                       model_2="mistral",
                       model_3="codellama")

          # Mix providers
          DiffAnalyzer(anthropic_key="sk-...", openai_key="sk-...",
                       model_1="claude-3-haiku",
                       model_2="gpt-4o-mini")
        """
        self.openai_key = openai_key
        self.anthropic_key = anthropic_key
        self.openrouter_key = openrouter_key
        self.openrouter_model = openrouter_model or "anthropic/claude-sonnet-4"
        self.ollama_host = ollama_host
        self.ollama_model = ollama_model or "llama3.3"
        self.ai_review_enabled = ai_review

        # Determine which provider to use and build model list
        self.models = []  # List of (provider, model_name) tuples

        # If explicit models provided, use those
        explicit_models = [m for m in [model_1, model_2, model_3] if m]

        if explicit_models:
            for model_spec in explicit_models:
                provider, model = self._parse_model_spec(model_spec)
                if self._provider_available(provider):
                    self.models.append((provider, model))
        else:
            # Auto-configure based on available API keys
            # Priority: OpenRouter (most flexible) > Ollama (local) > Anthropic > OpenAI
            if openrouter_key:
                for model in self.DEFAULT_MODELS["openrouter"]:
                    self.models.append(("openrouter", model))
            elif ollama_host:
                for model in self.DEFAULT_MODELS["ollama"]:
                    self.models.append(("ollama", model))
            elif anthropic_key:
                self.models.append(("anthropic", self.DEFAULT_MODELS["anthropic"][0]))
            elif openai_key:
                self.models.append(("openai", self.DEFAULT_MODELS["openai"][0]))

        self.ai_enabled = len(self.models) > 0 and self.ai_review_enabled
        self.max_models_available = len(self.models)

    @property
    def available_providers(self) -> list[tuple[str, str]]:
        """Return list of (provider, model) tuples that are configured."""
        return self.models

    def _parse_model_spec(self, model_spec: str) -> tuple[str, str]:
        """
        Parse a model specification into (provider, model).

        Formats:
          "provider/model" -> ("provider", "model")
          "model" -> inferred provider based on available keys
        """
        if "/" in model_spec:
            parts = model_spec.split("/", 1)
            return (parts[0], parts[1])

        # Infer provider from model name
        model = model_spec.lower()

        # Check for Anthropic models
        if "claude" in model:
            return ("anthropic", model_spec)

        # Check for OpenAI models
        if "gpt" in model or "o1" in model:
            return ("openai", model_spec)

        # Check for Ollama (local) models
        ollama_models = ["llama", "mistral", "codellama", "phi", "qwen", "mixtral", "gemma"]
        if any(m in model for m in ollama_models):
            if self.ollama_host:
                return ("ollama", model_spec)

        # Default to OpenRouter if available (it supports most models)
        if self.openrouter_key:
            return ("openrouter", model_spec)

        # Fallback to ollama for unknown models
        return ("ollama", model_spec)

    def _provider_available(self, provider: str) -> bool:
        """Check if a provider is configured and available."""
        if provider == "openrouter":
            return bool(self.openrouter_key)
        elif provider == "ollama":
            return bool(self.ollama_host)
        elif provider == "anthropic":
            return bool(self.anthropic_key)
        elif provider == "openai":
            return bool(self.openai_key)
        return False

    def analyze(self, diff_content: str, rubric: str = "default", tier_override: str = None) -> dict[str, Any]:
        """
        Analyze a diff with tier-based multi-model review.

        Flow:
          1. Parse diff and detect sensitive zones
          2. Estimate preliminary risk tier from file patterns
          3. Run appropriate number of AI models based on tier
          4. Aggregate results with rubric scoring (L2+)

        Returns:
            Dict with keys: files_changed, lines_added, lines_removed,
            files, sensitive_zones, preliminary_tier, multi_model_review
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

        # Estimate preliminary tier based on file patterns and sensitive zones
        preliminary_tier = self._estimate_preliminary_tier(files, sensitive_zones, total_added + total_removed)

        result = {
            "files_changed": len(files),
            "lines_added": total_added,
            "lines_removed": total_removed,
            "files": files,
            "sensitive_zones": sensitive_zones,
            "diff_hash": self._hash_diff(diff_content),
            "preliminary_tier": preliminary_tier,
        }

        # Apply tier override if provided (e.g., from eval harness)
        effective_tier = tier_override or preliminary_tier
        models_needed = self.TIER_MODEL_COUNT.get(effective_tier, 1)
        use_rubric = effective_tier in ("L2", "L3", "L4")

        if models_needed > 0 and self.ai_enabled:
            multi_review = self._run_multi_model_review(
                diff_content, sensitive_zones, rubric, models_needed, use_rubric
            )
            result["multi_model_review"] = multi_review

            # Extract top-level outputs for entrypoint.py
            result["models_used"] = multi_review.get("models_used", 0)
            consensus = multi_review.get("consensus") or {}
            result["consensus_risk"] = consensus.get("consensus_risk") or ""
            result["agreement_score"] = consensus.get("agreement_score") or 0.0

            # Legacy compatibility: also include ai_summary from first model
            if multi_review.get("reviews"):
                first_review = multi_review["reviews"][0]
                result["ai_summary"] = {
                    "summary": first_review.get("summary", ""),
                    "intent": first_review.get("intent", ""),
                    "concerns": first_review.get("concerns", []),
                }
        else:
            result["multi_model_review"] = {
                "reviews": [],
                "models_used": 0,
                "tier": preliminary_tier,
                "reason": "L0 tier - rules-based only" if preliminary_tier == "L0" else "No AI providers configured"
            }
            result["models_used"] = 0
            result["consensus_risk"] = ""
            result["agreement_score"] = 0.0

        return result

    def _estimate_preliminary_tier(self, files: list, sensitive_zones: list, total_lines: int) -> str:
        """
        Estimate risk tier from file patterns before AI review.

        This determines how many models will review the change.
        """
        max_tier = 0

        # Check file patterns
        for file in files:
            path = file.get("path", "")

            # Check L4 patterns (highest priority)
            for pattern in self.FILE_PATTERNS["L4"]:
                if re.search(pattern, path, re.IGNORECASE):
                    max_tier = max(max_tier, 4)

            # Check L3 patterns
            for pattern in self.FILE_PATTERNS["L3"]:
                if re.search(pattern, path, re.IGNORECASE):
                    max_tier = max(max_tier, 3)

            # Check L1 patterns (tests)
            for pattern in self.FILE_PATTERNS["L1"]:
                if re.search(pattern, path, re.IGNORECASE):
                    if max_tier == 0:
                        max_tier = 1

            # Check L0 patterns (docs)
            for pattern in self.FILE_PATTERNS["L0"]:
                if re.search(pattern, path, re.IGNORECASE):
                    if max_tier == 0:
                        max_tier = 0

        # Boost tier based on sensitive zones
        zone_types = set(z.get("zone") for z in sensitive_zones)
        if zone_types & {"payment", "crypto", "pii"}:
            max_tier = max(max_tier, 4)
        elif zone_types & {"auth", "security"}:
            max_tier = max(max_tier, 3)
        elif zone_types & {"database", "config", "infra"}:
            max_tier = max(max_tier, 2)

        # Boost for large changes
        if total_lines > 500:
            max_tier = max(max_tier, 3)
        elif total_lines > 100:
            max_tier = max(max_tier, 2)

        # Default to L2 for normal code changes
        if max_tier == 0 and any(not self._is_trivial_file(f["path"]) for f in files):
            max_tier = 2

        return f"L{max_tier}"

    def _is_trivial_file(self, path: str) -> bool:
        """Check if file is trivial (docs, config)."""
        for pattern in self.FILE_PATTERNS["L0"]:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        return False

    def _run_multi_model_review(
        self, diff_content: str, sensitive_zones: list,
        rubric: str, models_needed: int, use_rubric: bool
    ) -> dict:
        """
        Run multiple AI models in parallel for code review.

        Returns aggregated consensus from all models.
        """
        models_to_use = min(models_needed, self.max_models_available)

        if models_to_use == 0:
            return {
                "reviews": [],
                "models_used": 0,
                "consensus": None,
                "reason": "No AI providers available"
            }

        # Select which providers to use
        providers = self.available_providers[:models_to_use]

        # Run reviews in parallel
        reviews = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=models_to_use) as executor:
            future_to_provider = {
                executor.submit(
                    self._get_model_review,
                    provider, model, diff_content, sensitive_zones, rubric, use_rubric
                ): (provider, model)
                for provider, model in providers
            }

            for future in concurrent.futures.as_completed(future_to_provider):
                provider, model = future_to_provider[future]
                try:
                    review = future.result()
                    reviews.append(review)
                except Exception as e:
                    reviews.append({
                        "model_name": model,
                        "provider": provider,
                        "error": str(e),
                        "summary": "",
                        "intent": "",
                        "concerns": [],
                        "risk_assessment": "error",
                        "confidence": 0.0,
                        "rubric_scores": {}
                    })

        # Calculate consensus
        consensus = self._calculate_consensus(reviews, use_rubric)

        return {
            "reviews": reviews,
            "models_used": len(reviews),
            "models_requested": models_needed,
            "used_rubric": use_rubric,
            "rubric_name": rubric if use_rubric else None,
            "consensus": consensus,
        }

    def _get_model_review(
        self, provider: str, model: str, diff_content: str,
        sensitive_zones: list, rubric: str, use_rubric: bool
    ) -> dict:
        """Get a single model's review of the diff."""
        prompt = self._build_review_prompt(diff_content, sensitive_zones, rubric, use_rubric)

        try:
            if provider == "ollama":
                response = self._call_ollama(prompt, model)
            elif provider == "openrouter":
                response = self._call_openrouter(prompt, model)
            elif provider == "anthropic":
                response = self._call_anthropic(prompt, model)
            elif provider == "openai":
                response = self._call_openai(prompt, model)
            else:
                return {"error": f"Unknown provider: {provider}"}

            # Parse response
            parsed = self._parse_review_response(response)
            parsed["model_name"] = model
            parsed["provider"] = provider
            parsed["raw_response"] = response[:500]  # Truncate for storage
            return parsed

        except Exception as e:
            return {
                "model_name": model,
                "provider": provider,
                "error": str(e),
                "summary": "",
                "intent": "",
                "concerns": [],
                "risk_assessment": "error",
                "confidence": 0.0,
                "rubric_scores": {}
            }

    def _build_review_prompt(
        self, diff_content: str, sensitive_zones: list,
        rubric: str, use_rubric: bool
    ) -> str:
        """Build the prompt for AI code review."""
        rubric_section = ""
        if use_rubric:
            rubric_section = f"""
## Rubric Evaluation Required

Score each dimension from 1-5 (1=poor, 5=excellent):

For {rubric.upper()} compliance, evaluate:
- security_impact: Does this change introduce security risks?
- code_quality: Is the code well-structured and maintainable?
- test_coverage: Are changes adequately tested?
- documentation: Are changes documented?
- rollback_safety: Can this change be safely rolled back?

Include rubric_scores in your JSON response.
"""

        return f"""You are a senior code reviewer conducting a security and compliance review.

## Diff to Review
Sensitive zones detected: {len(sensitive_zones)}
Zones: {', '.join(set(z['zone'] for z in sensitive_zones[:5])) if sensitive_zones else 'None'}

```diff
{diff_content[:6000]}
```
{rubric_section}
## Required Response (JSON format)

Respond with ONLY valid JSON:
{{
    "summary": "One-sentence summary of what changed",
    "intent": "feature|bugfix|refactor|config|security|documentation",
    "concerns": ["List of security/compliance concerns, if any"],
    "risk_assessment": "approve|request_changes|comment",
    "confidence": 0.85,
    "rubric_scores": {{"security_impact": 4, "code_quality": 4, "test_coverage": 3, "documentation": 3, "rollback_safety": 4}}
}}

Be specific about concerns. If no concerns, use empty array."""

    def _parse_review_response(self, response: str) -> dict:
        """Parse the JSON response from a model."""
        try:
            # Try to extract JSON from response
            response = response.strip()
            if response.startswith("```json"):
                response = response[7:]
            if response.startswith("```"):
                response = response[3:]
            if response.endswith("```"):
                response = response[:-3]

            parsed = json.loads(response.strip())
            return {
                "summary": parsed.get("summary", ""),
                "intent": parsed.get("intent", "unknown"),
                "concerns": parsed.get("concerns", []),
                "risk_assessment": parsed.get("risk_assessment", "comment"),
                "confidence": float(parsed.get("confidence", 0.5)),
                "rubric_scores": parsed.get("rubric_scores", {}),
            }
        except json.JSONDecodeError:
            return {
                "summary": response[:200],
                "intent": "unknown",
                "concerns": [],
                "risk_assessment": "comment",
                "confidence": 0.3,
                "rubric_scores": {},
                "parse_error": True
            }

    def _calculate_consensus(self, reviews: list, use_rubric: bool) -> dict:
        """Calculate consensus from multiple model reviews."""
        if not reviews:
            return None

        valid_reviews = [r for r in reviews if not r.get("error")]
        if not valid_reviews:
            return {"error": "All model reviews failed"}

        # Count risk assessments (use `or` to handle None values)
        assessments = [r.get("risk_assessment") or "comment" for r in valid_reviews]
        assessment_counts = {}
        for a in assessments:
            assessment_counts[a] = assessment_counts.get(a, 0) + 1

        # Majority vote (or strictest if tie)
        priority = {"request_changes": 3, "comment": 2, "approve": 1, "error": 0}
        sorted_assessments = sorted(
            assessment_counts.items(),
            key=lambda x: (-x[1], -priority.get(x[0], 0))
        )
        consensus_risk = sorted_assessments[0][0] if sorted_assessments else "comment"

        # Agreement score
        if len(valid_reviews) > 1:
            max_agreement = max(assessment_counts.values())
            agreement_score = max_agreement / len(valid_reviews)
        else:
            agreement_score = 1.0

        # Combine concerns (deduplicated)
        all_concerns = []
        seen = set()
        for r in valid_reviews:
            for c in r.get("concerns", []):
                c_lower = c.lower()
                if c_lower not in seen:
                    seen.add(c_lower)
                    all_concerns.append(c)

        # Find dissenting opinions
        dissenting = []
        for r in valid_reviews:
            if r.get("risk_assessment") != consensus_risk:
                dissenting.append(f"{r.get('provider')}/{r.get('model_name')}: {r.get('risk_assessment')}")

        # Aggregate rubric scores
        rubric_summary = {}
        if use_rubric:
            rubric_keys = set()
            for r in valid_reviews:
                rubric_keys.update(r.get("rubric_scores", {}).keys())

            for key in rubric_keys:
                scores = [r.get("rubric_scores", {}).get(key) for r in valid_reviews
                          if r.get("rubric_scores", {}).get(key) is not None]
                if scores:
                    rubric_summary[key] = sum(scores) / len(scores)

        return {
            "consensus_risk": consensus_risk,
            "agreement_score": round(agreement_score, 2),
            "combined_concerns": all_concerns,
            "dissenting_opinions": dissenting,
            "rubric_summary": rubric_summary,
            "models_agreed": assessment_counts.get(consensus_risk, 0),
            "total_models": len(valid_reviews),
        }

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

    def _call_ollama(self, prompt: str, model: str) -> str:
        """Call Ollama local model and return response."""
        import openai

        base_url = self.ollama_host.rstrip('/')
        if not base_url.endswith('/v1'):
            base_url = f"{base_url}/v1"

        client = openai.OpenAI(
            api_key="ollama",  # Ollama doesn't require a real key
            base_url=base_url
        )

        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1000
        )
        return response.choices[0].message.content

    def _call_openrouter(self, prompt: str, model: str) -> str:
        """Call OpenRouter API and return response."""
        import openai

        client = openai.OpenAI(
            api_key=self.openrouter_key,
            base_url="https://openrouter.ai/api/v1"
        )

        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1000,
            extra_headers={
                "HTTP-Referer": "https://github.com/DNYoussef/codeguard-action",
                "X-Title": "GuardSpine CodeGuard"
            }
        )
        return response.choices[0].message.content

    def _call_anthropic(self, prompt: str, model: str) -> str:
        """Call Anthropic API and return response."""
        import anthropic

        client = anthropic.Anthropic(api_key=self.anthropic_key)

        response = client.messages.create(
            model=model,
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text

    def _call_openai(self, prompt: str, model: str) -> str:
        """Call OpenAI API and return response."""
        import openai

        client = openai.OpenAI(api_key=self.openai_key)

        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1000
        )
        return response.choices[0].message.content

    def _generate_ai_summary(self, diff_content: str, sensitive_zones: list) -> dict:
        """Generate AI-powered summary of changes."""
        try:
            # Priority: Ollama (local) > OpenRouter > Anthropic > OpenAI
            if self.ollama_host:
                return self._ollama_summary(diff_content, sensitive_zones)
            elif self.openrouter_key:
                return self._openrouter_summary(diff_content, sensitive_zones)
            elif self.anthropic_key:
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

    def _openrouter_summary(self, diff_content: str, sensitive_zones: list) -> dict:
        """Generate summary using OpenRouter (supports 100+ models)."""
        import openai

        # OpenRouter uses OpenAI-compatible API with different base URL
        client = openai.OpenAI(
            api_key=self.openrouter_key,
            base_url="https://openrouter.ai/api/v1"
        )

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

        response = client.chat.completions.create(
            model=self.openrouter_model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
            extra_headers={
                "HTTP-Referer": "https://github.com/DNYoussef/codeguard-action",
                "X-Title": "GuardSpine CodeGuard"
            }
        )

        import json
        try:
            return json.loads(response.choices[0].message.content)
        except:
            return {"summary": response.choices[0].message.content, "raw": True}

    def _ollama_summary(self, diff_content: str, sensitive_zones: list) -> dict:
        """Generate summary using Ollama (local/on-prem).

        Ollama provides an OpenAI-compatible API at /v1/chat/completions.
        No API key required for local installations.
        """
        import openai

        # Ollama uses OpenAI-compatible API at /v1
        base_url = self.ollama_host.rstrip('/')
        if not base_url.endswith('/v1'):
            base_url = f"{base_url}/v1"

        client = openai.OpenAI(
            api_key="ollama",  # Ollama doesn't require a real key
            base_url=base_url
        )

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

        response = client.chat.completions.create(
            model=self.ollama_model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500
        )

        import json
        try:
            return json.loads(response.choices[0].message.content)
        except:
            return {"summary": response.choices[0].message.content, "raw": True}
