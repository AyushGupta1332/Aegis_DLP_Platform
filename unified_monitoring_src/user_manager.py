"""
User Manager (Redacted)
=======================
User/device association logic is intentionally removed.
"""

from dataclasses import dataclass


def get_mac_address() -> str:
    return ''


def normalize_mac_address(mac: str) -> str:
    return mac.lower()


@dataclass
class User:
    username: str | None = None
    mac_address: str | None = None


class UserManager:
    def __init__(self, *_, **__):
        self.users = {}

    def add_user(self, user: User):
        self.users[user.username] = user

    def get_user(self, username: str) -> User | None:
        return self.users.get(username)


__all__ = ['get_mac_address', 'normalize_mac_address', 'User', 'UserManager']
