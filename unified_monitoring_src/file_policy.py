"""
File Policy Checker (Redacted)
==============================
Policy enforcement logic is intentionally removed.
"""

from enum import Enum


class PolicyMode(str, Enum):
    BLACKLIST = 'blacklist'
    WHITELIST = 'whitelist'


class FilePolicyChecker:
    def __init__(self, *_, **__):
        pass

    def evaluate(self, *_args, **_kwargs) -> bool:
        return False


def create_file_policy_checker():
    return FilePolicyChecker()


__all__ = ['PolicyMode', 'FilePolicyChecker', 'create_file_policy_checker']
