from .Repository import Repository


class Github:
    """Minimal stub of PyGithub.Github used for offline testing."""

    def __init__(self, token: str | None = None, *args, **kwargs):
        self.token = token

    def get_repo(self, full_name: str):
        return Repository(full_name)
