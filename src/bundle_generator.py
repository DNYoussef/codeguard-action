"""
Bundle Generator - Creates cryptographically verifiable evidence bundles.

Follows guardspine-spec v1.0 format.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from dataclasses import dataclass, field

from github.PullRequest import PullRequest


@dataclass
class BundleEvent:
    """A single event in the evidence chain."""
    event_type: str
    timestamp: str
    actor: str
    data: dict
    hash: str = ""

    def compute_hash(self, previous_hash: str = "") -> str:
        """Compute hash for this event including previous hash."""
        content = json.dumps({
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "data": self.data,
            "previous_hash": previous_hash
        }, sort_keys=True, separators=(',', ':'))
        self.hash = hashlib.sha256(content.encode()).hexdigest()
        return self.hash


class BundleGenerator:
    """
    Generates evidence bundles following guardspine-spec v1.0.

    Bundle structure:
    - Header: version, bundle_id, timestamps, context
    - Events: Hash-chained sequence of actions
    - Summary: Risk tier, findings, rationale
    - Signatures: Cryptographic attestations (optional)
    """

    SPEC_VERSION = "1.0.0"

    def __init__(self):
        """Initialize bundle generator."""
        self.events: list[BundleEvent] = []

    def create_bundle(
        self,
        pr: PullRequest,
        diff_content: str,
        analysis: dict[str, Any],
        risk_result: dict[str, Any],
        repository: str,
        commit_sha: str,
        approvers: list[str] = None,
        attestation_key: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Create a complete evidence bundle for a PR.

        Args:
            pr: GitHub PullRequest object
            diff_content: Raw diff content
            analysis: Analysis results from DiffAnalyzer
            risk_result: Classification from RiskClassifier
            repository: Repository name (owner/repo)
            commit_sha: Commit SHA being analyzed
            approvers: List of approver usernames (optional)
            attestation_key: Private key for signing (optional)

        Returns:
            Complete evidence bundle as dict
        """
        bundle_id = self._generate_bundle_id(repository, pr.number, commit_sha)
        created_at = datetime.now(timezone.utc).isoformat()

        # Build event chain
        self.events = []
        previous_hash = ""

        # Event 1: PR Created/Updated
        pr_event = BundleEvent(
            event_type="pr_submitted",
            timestamp=pr.created_at.isoformat() if pr.created_at else created_at,
            actor=pr.user.login if pr.user else "unknown",
            data={
                "pr_number": pr.number,
                "title": pr.title,
                "base_branch": pr.base.ref if pr.base else "main",
                "head_branch": pr.head.ref if pr.head else "unknown",
                "head_sha": commit_sha,
            }
        )
        previous_hash = pr_event.compute_hash(previous_hash)
        self.events.append(pr_event)

        # Event 2: Analysis Completed
        analysis_event = BundleEvent(
            event_type="analysis_completed",
            timestamp=created_at,
            actor="guardspine-codeguard",
            data={
                "files_changed": analysis.get("files_changed", 0),
                "lines_added": analysis.get("lines_added", 0),
                "lines_removed": analysis.get("lines_removed", 0),
                "sensitive_zones_count": len(analysis.get("sensitive_zones", [])),
                "diff_hash": analysis.get("diff_hash", ""),
            }
        )
        previous_hash = analysis_event.compute_hash(previous_hash)
        self.events.append(analysis_event)

        # Event 3: Risk Classification
        risk_event = BundleEvent(
            event_type="risk_classified",
            timestamp=created_at,
            actor="guardspine-codeguard",
            data={
                "risk_tier": risk_result.get("risk_tier", "L2"),
                "findings_count": len(risk_result.get("findings", [])),
                "scores": risk_result.get("scores", {}),
            }
        )
        previous_hash = risk_event.compute_hash(previous_hash)
        self.events.append(risk_event)

        # Event 4: Approval (if approvers provided)
        if approvers:
            for approver in approvers:
                approval_event = BundleEvent(
                    event_type="approval_granted",
                    timestamp=created_at,
                    actor=approver,
                    data={
                        "risk_tier_at_approval": risk_result.get("risk_tier", "L2"),
                        "commit_sha": commit_sha,
                    }
                )
                previous_hash = approval_event.compute_hash(previous_hash)
                self.events.append(approval_event)

        # Build complete bundle
        bundle = {
            "guardspine_spec_version": self.SPEC_VERSION,
            "bundle_id": bundle_id,
            "created_at": created_at,
            "context": {
                "repository": repository,
                "pr_number": pr.number,
                "commit_sha": commit_sha,
                "base_branch": pr.base.ref if pr.base else "main",
                "head_branch": pr.head.ref if pr.head else "unknown",
            },
            "events": [self._event_to_dict(e) for e in self.events],
            "hash_chain": {
                "algorithm": "sha256",
                "final_hash": previous_hash,
                "event_count": len(self.events),
            },
            "summary": {
                "risk_tier": risk_result.get("risk_tier", "L2"),
                "risk_drivers": risk_result.get("risk_drivers", []),
                "findings": risk_result.get("findings", []),
                "rationale": risk_result.get("rationale", ""),
                "requires_approval": risk_result.get("risk_tier", "L2") in ("L3", "L4"),
            },
            "analysis_snapshot": {
                "files_changed": analysis.get("files_changed", 0),
                "lines_added": analysis.get("lines_added", 0),
                "lines_removed": analysis.get("lines_removed", 0),
                "sensitive_zones": self._summarize_zones(analysis.get("sensitive_zones", [])),
                "ai_summary": analysis.get("ai_summary", {}),
            },
            "signatures": [],
        }

        # Add signature if key provided
        if attestation_key:
            signature = self._sign_bundle(bundle, attestation_key)
            bundle["signatures"].append(signature)

        return bundle

    def _generate_bundle_id(self, repository: str, pr_number: int, commit_sha: str) -> str:
        """Generate a unique bundle ID."""
        content = f"{repository}:{pr_number}:{commit_sha}:{datetime.now(timezone.utc).isoformat()}"
        short_hash = hashlib.sha256(content.encode()).hexdigest()[:12]
        return f"gsb_{short_hash}"

    def _event_to_dict(self, event: BundleEvent) -> dict:
        """Convert BundleEvent to dict."""
        return {
            "event_type": event.event_type,
            "timestamp": event.timestamp,
            "actor": event.actor,
            "data": event.data,
            "hash": event.hash,
        }

    def _summarize_zones(self, zones: list) -> dict:
        """Summarize sensitive zones by type."""
        summary = {}
        for zone in zones:
            zone_type = zone.get("zone", "unknown")
            if zone_type not in summary:
                summary[zone_type] = {"count": 0, "files": set()}
            summary[zone_type]["count"] += 1
            summary[zone_type]["files"].add(zone.get("file", "unknown"))

        # Convert sets to lists for JSON serialization
        for zone_type in summary:
            summary[zone_type]["files"] = list(summary[zone_type]["files"])

        return summary

    def _sign_bundle(self, bundle: dict, private_key: str) -> dict:
        """
        Sign bundle with the provided private key.

        Supports PEM-encoded Ed25519, RSA, or EC keys when cryptography is
        available. Falls back to HMAC-SHA256 if cryptography is unavailable.
        """
        # Create canonical JSON for signing
        canonical = json.dumps({
            "bundle_id": bundle["bundle_id"],
            "hash_chain": bundle["hash_chain"],
            "summary": bundle["summary"],
        }, sort_keys=True, separators=(',', ':'))
        canonical_bytes = canonical.encode()

        try:
            from base64 import b64encode
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, ec
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            key = load_pem_private_key(private_key.encode(), password=None)

            if isinstance(key, ed25519.Ed25519PrivateKey):
                signature = key.sign(canonical_bytes)
                algo = "ed25519"
            elif isinstance(key, rsa.RSAPrivateKey):
                signature = key.sign(
                    canonical_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                algo = "rsa-sha256"
            elif isinstance(key, ec.EllipticCurvePrivateKey):
                signature = key.sign(
                    canonical_bytes,
                    ec.ECDSA(hashes.SHA256())
                )
                algo = "ecdsa-sha256"
            else:
                raise ValueError("Unsupported key type for signing")

            public_key_bytes = key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_fingerprint = hashlib.sha256(public_key_bytes).hexdigest()

            return {
                "type": algo,
                "signer": "guardspine-codeguard",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "signature": b64encode(signature).decode(),
                "public_key_fingerprint": public_fingerprint,
            }
        except ImportError:
            import hmac
            signature = hmac.new(private_key.encode(), canonical_bytes, hashlib.sha256).hexdigest()
            return {
                "type": "hmac-sha256",
                "signer": "guardspine-codeguard",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "signature": signature,
                "note": "cryptography library not available; used HMAC-SHA256",
            }
        except Exception as exc:
            import hmac
            signature = hmac.new(private_key.encode(), canonical_bytes, hashlib.sha256).hexdigest()
            return {
                "type": "hmac-sha256",
                "signer": "guardspine-codeguard",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "signature": signature,
                "note": f"key parsing failed; used HMAC-SHA256 instead: {exc}",
            }


def verify_bundle_chain(bundle: dict) -> tuple[bool, str]:
    """
    Verify the hash chain in a bundle.

    Returns:
        Tuple of (is_valid, message)
    """
    events = bundle.get("events", [])
    if not events:
        return False, "No events in bundle"

    previous_hash = ""
    for i, event in enumerate(events):
        # Recompute hash
        content = json.dumps({
            "event_type": event["event_type"],
            "timestamp": event["timestamp"],
            "actor": event["actor"],
            "data": event["data"],
            "previous_hash": previous_hash
        }, sort_keys=True, separators=(',', ':'))
        computed_hash = hashlib.sha256(content.encode()).hexdigest()

        if computed_hash != event["hash"]:
            return False, f"Hash mismatch at event {i}: expected {event['hash']}, got {computed_hash}"

        previous_hash = computed_hash

    # Verify final hash
    final_hash = bundle.get("hash_chain", {}).get("final_hash", "")
    if previous_hash != final_hash:
        return False, f"Final hash mismatch: expected {final_hash}, got {previous_hash}"

    return True, "Hash chain verified successfully"
