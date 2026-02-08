"""
PII-Shield integration spike.

Supports:
  - remote PII-Shield redaction/detection endpoint
  - provider findings ingestion for risk scoring
  - fail-open/fail-closed behavior
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

import requests


class PIIShieldError(RuntimeError):
    """Raised when PII-Shield processing fails in fail-closed mode."""


@dataclass(frozen=True)
class PIIShieldResult:
    sanitized_text: str
    changed: bool
    redaction_count: int
    redactions_by_type: dict[str, int]
    mode: str
    provider: str
    input_hash: str
    output_hash: str
    signals: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "mode": self.mode,
            "provider": self.provider,
            "changed": self.changed,
            "redaction_count": self.redaction_count,
            "redactions_by_type": dict(self.redactions_by_type),
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "signal_count": len(self.signals),
            "details": dict(self.metadata),
        }

    def to_sensitive_zones(self) -> list[dict[str, Any]]:
        """Convert provider signals to RiskClassifier-sensitive zones."""
        zones: list[dict[str, Any]] = []
        for signal in self.signals:
            zones.append(
                {
                    "zone": signal.get("zone"),
                    "file": signal.get("file") or "__pii_shield__",
                    "line": signal.get("line"),
                    "content_preview": signal.get("content_preview", ""),
                    "detector": signal.get("detector", "pii_shield"),
                    "category": signal.get("category"),
                    "confidence": signal.get("confidence"),
                    "count": signal.get("count"),
                }
            )
        return zones


class PIIShieldClient:
    """PII-Shield integration client (provider-first)."""

    _VALID_MODES = {"auto", "local", "remote"}

    def __init__(
        self,
        enabled: bool = False,
        mode: str = "auto",
        endpoint: str | None = None,
        api_key: str | None = None,
        timeout_seconds: float = 5.0,
        fail_closed: bool = False,
    ):
        self.enabled = enabled
        self.mode = (mode or "auto").strip().lower()
        self.endpoint = endpoint.strip() if endpoint else None
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.fail_closed = fail_closed

        if self.mode not in self._VALID_MODES:
            raise ValueError(
                f"Unsupported PII-Shield mode: {self.mode!r}. "
                f"Expected one of: {sorted(self._VALID_MODES)}"
            )

    @staticmethod
    def _sha256(value: str) -> str:
        return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _with_extra_metadata(
        result: PIIShieldResult,
        extra: dict[str, Any],
    ) -> PIIShieldResult:
        metadata = dict(result.metadata)
        metadata.update(extra)
        return PIIShieldResult(
            sanitized_text=result.sanitized_text,
            changed=result.changed,
            redaction_count=result.redaction_count,
            redactions_by_type=dict(result.redactions_by_type),
            mode=result.mode,
            provider=result.provider,
            input_hash=result.input_hash,
            output_hash=result.output_hash,
            signals=list(result.signals),
            metadata=metadata,
        )

    def sanitize_text(
        self,
        text: str,
        input_format: str = "text",
        include_findings: bool = False,
        purpose: str | None = None,
    ) -> PIIShieldResult:
        """Sanitize text through PII-Shield according to configured mode."""
        input_hash = self._sha256(text)
        if not self.enabled:
            return PIIShieldResult(
                sanitized_text=text,
                changed=False,
                redaction_count=0,
                redactions_by_type={},
                mode="disabled",
                provider="none",
                input_hash=input_hash,
                output_hash=input_hash,
                signals=[],
                metadata={},
            )

        if self.mode == "remote" and not self.endpoint:
            if self.fail_closed:
                raise PIIShieldError("PII-Shield remote mode requires pii_shield_endpoint")
            return PIIShieldResult(
                sanitized_text=text,
                changed=False,
                redaction_count=0,
                redactions_by_type={},
                mode="remote",
                provider="passthrough",
                input_hash=input_hash,
                output_hash=input_hash,
                signals=[],
                metadata={"warning": "remote mode selected but pii_shield_endpoint is not configured"},
            )

        if self.mode in {"auto", "remote"} and self.endpoint:
            try:
                return self._sanitize_remote(
                    text=text,
                    input_format=input_format,
                    include_findings=include_findings,
                    purpose=purpose,
                )
            except Exception as exc:
                remote_error = str(exc)
                if self.mode == "remote" or self.fail_closed:
                    raise PIIShieldError(f"Remote PII-Shield failed: {exc}") from exc
                return PIIShieldResult(
                    sanitized_text=text,
                    changed=False,
                    redaction_count=0,
                    redactions_by_type={},
                    mode="auto",
                    provider="passthrough",
                    input_hash=input_hash,
                    output_hash=input_hash,
                    signals=[],
                    metadata={"warning": "remote PII-Shield failed; running fail-open passthrough", "remote_error": remote_error},
                )

        if self.mode == "local":
            # Kept only for compatibility; no built-in detector is implemented.
            return PIIShieldResult(
                sanitized_text=text,
                changed=False,
                redaction_count=0,
                redactions_by_type={},
                mode="local",
                provider="passthrough",
                input_hash=input_hash,
                output_hash=input_hash,
                signals=[],
                metadata={"warning": "local mode is passthrough; configure remote endpoint for PII-Shield detection"},
            )

        return PIIShieldResult(
            sanitized_text=text,
            changed=False,
            redaction_count=0,
            redactions_by_type={},
            mode=self.mode,
            provider="passthrough",
            input_hash=input_hash,
            output_hash=input_hash,
            signals=[],
            metadata={"warning": "PII-Shield auto mode is passthrough without endpoint"},
        )

    def sanitize_diff(self, diff_content: str) -> PIIShieldResult:
        """Sanitize diff content and return redaction metadata + signals."""
        return self.sanitize_text(
            diff_content,
            input_format="diff",
            include_findings=True,
            purpose="diff",
        )

    def sanitize_json_document(
        self,
        document: Any,
        purpose: str = "json_document",
    ) -> tuple[Any, PIIShieldResult]:
        """
        Sanitize a JSON-like structure while preserving schema shape when possible.
        """
        original_json = json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        result = self.sanitize_text(
            original_json,
            input_format="json",
            include_findings=False,
            purpose=purpose,
        )
        if not result.changed:
            return document, result

        try:
            sanitized_document = json.loads(result.sanitized_text)
            return sanitized_document, result
        except json.JSONDecodeError as exc:
            if self.fail_closed:
                raise PIIShieldError(
                    f"PII-Shield returned non-JSON sanitized content for {purpose}: {exc}"
                ) from exc
            enriched = self._with_extra_metadata(
                result,
                {
                    "parse_error": str(exc),
                    "warning": f"sanitized {purpose} content was not valid JSON; fail-open passthrough",
                },
            )
            return document, enriched

    def _sanitize_remote(
        self,
        text: str,
        input_format: str,
        include_findings: bool,
        purpose: str | None,
    ) -> PIIShieldResult:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "text": text,
            "input_format": input_format,
            "deterministic": True,
            "preserve_line_numbers": True,
            "include_findings": include_findings,
        }
        if purpose:
            payload["purpose"] = purpose

        response = requests.post(
            self.endpoint,
            json=payload,
            headers=headers,
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        body = response.json()

        sanitized = (
            body.get("sanitized_text")
            or body.get("redacted_text")
            or body.get("text")
            or body.get("output")
        )
        if not isinstance(sanitized, str):
            raise ValueError("Remote PII-Shield response did not include sanitized text")

        redactions_by_type = self._extract_redactions_by_type(body)
        redaction_count = body.get("redaction_count")
        if not isinstance(redaction_count, int):
            redaction_count = sum(redactions_by_type.values())
            if redaction_count == 0 and isinstance(body.get("redactions"), list):
                redaction_count = len(body["redactions"])

        signals = self._extract_signals(body, redactions_by_type)

        return PIIShieldResult(
            sanitized_text=sanitized,
            changed=(sanitized != text),
            redaction_count=redaction_count,
            redactions_by_type=redactions_by_type,
            mode="remote",
            provider=body.get("provider", "pii-shield-remote"),
            input_hash=self._sha256(text),
            output_hash=self._sha256(sanitized),
            signals=signals,
            metadata={
                "status_code": response.status_code,
                "schema_version": body.get("schema_version"),
                "engine_version": body.get("engine_version") or body.get("version"),
                "model": body.get("model"),
                "input_format": input_format,
            },
        )

    @staticmethod
    def _extract_redactions_by_type(body: dict[str, Any]) -> dict[str, int]:
        raw = body.get("redactions_by_type")
        if isinstance(raw, dict):
            clean: dict[str, int] = {}
            for key, value in raw.items():
                try:
                    clean[str(key)] = int(value)
                except (TypeError, ValueError):
                    continue
            return clean

        redactions = body.get("redactions")
        if isinstance(redactions, list):
            counts: dict[str, int] = {}
            for item in redactions:
                label = "unknown"
                if isinstance(item, dict):
                    label = str(
                        item.get("type")
                        or item.get("category")
                        or item.get("label")
                        or "unknown"
                    )
                counts[label] = counts.get(label, 0) + 1
            return counts

        return {}

    @staticmethod
    def _map_label_to_zone(label: str) -> str | None:
        normalized = (label or "").strip().lower().replace("-", "_").replace(" ", "_")
        if not normalized:
            return None
        if any(k in normalized for k in ("email", "phone", "ssn", "pii", "phi", "personal")):
            return "pii"
        if any(k in normalized for k in ("card", "pan", "payment", "billing")):
            return "payment"
        if any(k in normalized for k in ("secret", "token", "credential", "password", "api_key", "key", "entropy")):
            return "entropy_secret"
        return None

    @staticmethod
    def _as_int(value: Any) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _extract_signals(
        self,
        body: dict[str, Any],
        redactions_by_type: dict[str, int],
    ) -> list[dict[str, Any]]:
        raw_signals = (
            body.get("detections")
            or body.get("findings")
            or body.get("matches")
            or body.get("redactions")
            or []
        )

        signals: list[dict[str, Any]] = []
        if isinstance(raw_signals, list):
            for item in raw_signals:
                if not isinstance(item, dict):
                    continue
                label = str(
                    item.get("type")
                    or item.get("category")
                    or item.get("label")
                    or item.get("name")
                    or "unknown"
                )
                zone = self._map_label_to_zone(label)
                if not zone:
                    continue
                line = (
                    self._as_int(item.get("line"))
                    or self._as_int(item.get("line_number"))
                    or self._as_int(item.get("start_line"))
                )
                signal = {
                    "zone": zone,
                    "file": str(item.get("file") or item.get("path") or "__pii_shield__"),
                    "line": line,
                    "detector": "pii_shield",
                    "category": label,
                    "content_preview": str(
                        item.get("text")
                        or item.get("value")
                        or item.get("token")
                        or ""
                    )[:120],
                }
                confidence = item.get("confidence")
                try:
                    if confidence is not None:
                        signal["confidence"] = float(confidence)
                except (TypeError, ValueError):
                    pass
                signals.append(signal)

        if not signals:
            for label, count in redactions_by_type.items():
                zone = self._map_label_to_zone(label)
                if not zone:
                    continue
                signals.append(
                    {
                        "zone": zone,
                        "file": "__pii_shield__",
                        "line": None,
                        "detector": "pii_shield",
                        "category": label,
                        "count": int(count),
                        "content_preview": "",
                    }
                )

        deduped: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        for signal in signals:
            key = (
                signal.get("zone"),
                signal.get("file"),
                signal.get("line"),
                signal.get("category"),
                signal.get("content_preview"),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(signal)
        return deduped
