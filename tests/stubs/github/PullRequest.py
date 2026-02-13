from __future__ import annotations
from datetime import datetime, timezone
import os


class _Actor:
    def __init__(self, login: str):
        self.login = login


class _Branch:
    def __init__(self, ref: str):
        self.ref = ref


class Comment:
    def __init__(self, body: str):
        self.body = body

    def edit(self, body: str):
        self.body = body


class PullRequest:
    """Stub pull request with minimal surface."""

    def __init__(self, number: int, diff_url: str | None = None):
        self.number = number
        self.diff_url = diff_url or os.environ.get("STUB_DIFF_URL", "")
        self.title = "Stub PR"
        self.base = _Branch("main")
        self.head = _Branch("feature")
        self.user = _Actor("stub-user")
        self.created_at = datetime.now(timezone.utc)
        self._comments: list[Comment] = []

    def get_issue_comments(self):
        return self._comments

    def create_issue_comment(self, body: str):
        self._comments.append(Comment(body))
        return self._comments[-1]
