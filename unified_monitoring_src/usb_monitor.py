"""
USB Monitor (Redacted)
======================
USB monitoring logic is intentionally removed.
"""

from dataclasses import dataclass
from enum import Enum


class USBEventType(str, Enum):
    INSERTED = 'inserted'
    REMOVED = 'removed'


@dataclass
class USBEvent:
    event_type: USBEventType
    device_id: str | None = None


class USBMonitor:
    def __init__(self, *_, **__):
        self.running = False

    def start(self):
        self.running = True

    def stop(self):
        self.running = False


class USBMonitorWithRegistry(USBMonitor):
    def __init__(self, *_, **__):
        super().__init__()


__all__ = ['USBEventType', 'USBEvent', 'USBMonitor', 'USBMonitorWithRegistry']
