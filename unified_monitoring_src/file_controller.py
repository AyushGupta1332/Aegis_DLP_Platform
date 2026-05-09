"""
File Transfer Controller (Redacted)
===================================
Transfer control logic is intentionally removed.
"""

from dataclasses import dataclass
from enum import Enum


class TransferStatus(str, Enum):
    ALLOWED = 'allowed'
    BLOCKED = 'blocked'


@dataclass
class TransferResult:
    status: TransferStatus = TransferStatus.BLOCKED
    message: str = 'redacted'


class FileTransferController:
    def __init__(self, *_, **__):
        pass

    def evaluate_transfer(self, *_args, **_kwargs) -> TransferResult:
        return TransferResult()


__all__ = ['TransferStatus', 'TransferResult', 'FileTransferController']
