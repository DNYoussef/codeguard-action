from __future__ import annotations
from .PullRequest import PullRequest


class Repository:
    """Stub repository."""

    def __init__(self, full_name: str):
        self.full_name = full_name
        self._pulls: dict[int, PullRequest] = {}

    def get_pull(self, number: int) -> PullRequest:
        if number not in self._pulls:
            self._pulls[number] = PullRequest(number=number)
        return self._pulls[number]
