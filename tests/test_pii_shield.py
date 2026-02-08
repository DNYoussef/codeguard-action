"""Tests for provider-first PII-Shield integration behavior."""

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pii_shield import PIIShieldClient, PIIShieldError


class TestPIIShieldModes(unittest.TestCase):
    def test_disabled_mode_passthrough(self):
        text = "secret = 'abc123'\n"
        client = PIIShieldClient(enabled=False)
        result = client.sanitize_text(text)

        self.assertEqual(result.mode, "disabled")
        self.assertFalse(result.changed)
        self.assertEqual(result.sanitized_text, text)

    def test_local_mode_is_explicit_passthrough(self):
        diff = "+email='alice@example.com'\n"
        client = PIIShieldClient(enabled=True, mode="local")
        result = client.sanitize_diff(diff)

        self.assertEqual(result.mode, "local")
        self.assertEqual(result.provider, "passthrough")
        self.assertFalse(result.changed)
        self.assertEqual(result.sanitized_text, diff)
        self.assertIn("local mode is passthrough", result.to_metadata()["details"].get("warning", ""))

    def test_remote_mode_without_endpoint_fail_open_passthrough(self):
        diff = "+token='abc'\n"
        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint=None,
            fail_closed=False,
        )

        result = client.sanitize_diff(diff)
        self.assertEqual(result.mode, "remote")
        self.assertFalse(result.changed)
        self.assertEqual(result.sanitized_text, diff)

    def test_remote_mode_without_endpoint_fail_closed_raises(self):
        client = PIIShieldClient(enabled=True, mode="remote", endpoint=None, fail_closed=True)
        with self.assertRaises(PIIShieldError):
            client.sanitize_diff("+email='alice@example.com'\n")


class TestPIIShieldRemoteBehavior(unittest.TestCase):
    @patch("pii_shield.requests.post")
    def test_remote_mode_parses_redactions_and_signals(self, mock_post):
        diff = "+email='alice@example.com'\n+api_key='sk_live_123'\n"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "provider": "pii-shield-remote",
            "sanitized_text": "+email='[HIDDEN:e1]'\n+api_key='[HIDDEN:k1]'\n",
            "redactions_by_type": {"email": 1, "api_key": 1},
            "redaction_count": 2,
            "detections": [
                {"category": "email", "file": "app.py", "line": 1, "text": "alice@example.com"},
                {"category": "api_key", "file": "app.py", "line": 2, "text": "sk_live_123"},
            ],
            "schema_version": "2026-01",
        }
        mock_post.return_value = mock_response

        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint="https://shield.example/api/sanitize",
            api_key="k",
            timeout_seconds=7.5,
        )
        result = client.sanitize_diff(diff)

        self.assertTrue(result.changed)
        self.assertEqual(result.redaction_count, 2)
        self.assertEqual(result.redactions_by_type, {"email": 1, "api_key": 1})
        self.assertEqual(result.provider, "pii-shield-remote")

        zones = result.to_sensitive_zones()
        self.assertEqual(len(zones), 2)
        self.assertEqual({z["zone"] for z in zones}, {"pii", "entropy_secret"})

        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["timeout"], 7.5)
        self.assertEqual(kwargs["json"]["input_format"], "diff")
        self.assertTrue(kwargs["json"]["include_findings"])
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer k")

    @patch("pii_shield.requests.post")
    def test_remote_mode_fail_closed_raises(self, mock_post):
        mock_post.side_effect = requests.exceptions.Timeout("timeout")
        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint="https://example.invalid/shield",
            fail_closed=True,
        )

        with self.assertRaises(PIIShieldError):
            client.sanitize_diff("+email='alice@example.com'\n")

    @patch("pii_shield.requests.post")
    def test_auto_mode_fail_open_passthrough_on_remote_error(self, mock_post):
        mock_post.side_effect = requests.exceptions.ConnectionError("offline")
        client = PIIShieldClient(
            enabled=True,
            mode="auto",
            endpoint="https://example.invalid/shield",
            fail_closed=False,
        )

        raw = "+email='alice@example.com'\n"
        result = client.sanitize_diff(raw)

        self.assertEqual(result.mode, "auto")
        self.assertEqual(result.provider, "passthrough")
        self.assertFalse(result.changed)
        self.assertEqual(result.sanitized_text, raw)
        self.assertIn("remote_error", result.to_metadata()["details"])


class TestPIIShieldJsonSanitization(unittest.TestCase):
    @patch("pii_shield.requests.post")
    def test_sanitize_json_document_returns_parsed_structure(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "provider": "pii-shield-remote",
            "sanitized_text": "{\"message\":\"contact [HIDDEN:e1]\"}",
            "redaction_count": 1,
            "redactions_by_type": {"email": 1},
        }
        mock_post.return_value = mock_response

        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint="https://shield.example/api/sanitize",
        )
        original = {"message": "contact alice@example.com"}

        sanitized, result = client.sanitize_json_document(original, purpose="bundle")
        self.assertTrue(result.changed)
        self.assertEqual(sanitized["message"], "contact [HIDDEN:e1]")

    @patch("pii_shield.requests.post")
    def test_sanitize_json_document_fail_open_on_parse_error(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "provider": "pii-shield-remote",
            "sanitized_text": "not-json",
            "redaction_count": 1,
            "redactions_by_type": {"token": 1},
        }
        mock_post.return_value = mock_response

        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint="https://shield.example/api/sanitize",
            fail_closed=False,
        )
        original = {"token": "secret"}

        sanitized, result = client.sanitize_json_document(original, purpose="bundle")
        self.assertEqual(sanitized, original)
        self.assertIn("parse_error", result.to_metadata()["details"])

    @patch("pii_shield.requests.post")
    def test_sanitize_json_document_fail_closed_on_parse_error(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "provider": "pii-shield-remote",
            "sanitized_text": "not-json",
            "redaction_count": 1,
            "redactions_by_type": {"token": 1},
        }
        mock_post.return_value = mock_response

        client = PIIShieldClient(
            enabled=True,
            mode="remote",
            endpoint="https://shield.example/api/sanitize",
            fail_closed=True,
        )

        with self.assertRaises(PIIShieldError):
            client.sanitize_json_document({"token": "secret"}, purpose="bundle")


if __name__ == "__main__":
    unittest.main()
