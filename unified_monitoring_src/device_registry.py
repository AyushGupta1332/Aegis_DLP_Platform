"""
Device Registry (Redacted)
==========================
Registry logic is intentionally removed.
"""

from dataclasses import dataclass


@dataclass
class RegisteredDevice:
    device_id: str | None = None
    owner: str | None = None


@dataclass
class TransferLog:
    device_id: str | None = None
    status: str | None = None


class DeviceRegistry:
    def __init__(self, *_, **__):
        self.devices = {}

    def register(self, device: RegisteredDevice):
        self.devices[device.device_id] = device

    def is_authorized(self, _device_id: str) -> bool:
        return False


__all__ = ['RegisteredDevice', 'TransferLog', 'DeviceRegistry']
