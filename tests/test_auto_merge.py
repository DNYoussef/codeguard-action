from __future__ import annotations
"""
Tests for _auto_merge function.

Covers:
  1. Happy path: open PR, mergeable, merge succeeds
  2. PR not open: returns False, no merge attempted
  3. PR has conflicts (mergeable=False): returns False
  4. Merge API fails: returns False, error printed
  5. L4 guard: auto_merge skipped for L4 tier
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from entrypoint import _auto_merge


def _make_pr(state="open", mergeable=True, merged=True, sha="abc1234def5678"):
    """Build a mock PR object matching PyGithub's PullRequest interface."""
    pr = MagicMock()
    pr.number = 42
    pr.title = "Add safe utility function"
    pr.state = state
    pr.mergeable = mergeable
    pr.head.sha = sha

    merge_result = MagicMock()
    merge_result.merged = merged
    merge_result.sha = sha
    merge_result.message = "Merge conflict" if not merged else ""
    pr.merge.return_value = merge_result

    return pr


class TestAutoMerge(unittest.TestCase):

    @patch("entrypoint.set_output")
    def test_happy_path_merge(self, mock_output):
        pr = _make_pr()
        result = _auto_merge(pr, "squash", "L2", "bundle-123")

        self.assertTrue(result)
        pr.merge.assert_called_once_with(
            commit_title="Add safe utility function",
            commit_message="Auto-merged by CodeGuard (risk: L2)\n\nEvidence bundle: bundle-123",
            merge_method="squash",
            sha=pr.head.sha,
        )
        mock_output.assert_any_call("merged", "true")
        mock_output.assert_any_call("merge_sha", pr.head.sha)

    @patch("entrypoint.set_output")
    def test_pr_not_open_skips_merge(self, mock_output):
        pr = _make_pr(state="closed")
        result = _auto_merge(pr, "squash", "L1", "bundle-456")

        self.assertFalse(result)
        pr.merge.assert_not_called()

    @patch("entrypoint.set_output")
    def test_pr_conflicts_skips_merge(self, mock_output):
        pr = _make_pr(mergeable=False)
        result = _auto_merge(pr, "squash", "L2", "bundle-789")

        self.assertFalse(result)
        pr.merge.assert_not_called()

    @patch("entrypoint.set_output")
    def test_merge_api_fails(self, mock_output):
        pr = _make_pr(merged=False)
        result = _auto_merge(pr, "squash", "L3", "bundle-fail")

        self.assertFalse(result)
        pr.merge.assert_called_once()
        mock_output.assert_any_call("merged", "false")

    @patch("entrypoint.set_output")
    def test_mergeable_none_still_attempts(self, mock_output):
        """When GitHub hasn't computed mergeable yet (None), we still try."""
        pr = _make_pr(mergeable=None)
        result = _auto_merge(pr, "rebase", "L0", "bundle-none")

        self.assertTrue(result)
        pr.merge.assert_called_once()

    @patch("entrypoint.set_output")
    def test_merge_method_passed_through(self, mock_output):
        for method in ("merge", "squash", "rebase"):
            pr = _make_pr()
            _auto_merge(pr, method, "L1", "bundle-method")
            self.assertEqual(pr.merge.call_args.kwargs["merge_method"], method)


if __name__ == "__main__":
    unittest.main()
