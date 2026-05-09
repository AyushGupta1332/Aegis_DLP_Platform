"""
Device Identifier (Redacted)
============================
Device identification logic is intentionally removed.
"""

from dataclasses import dataclass


@dataclass
class USBDevice:
    vendor_id: str | None = None
    product_id: str | None = None
    serial: str | None = None
    description: str | None = None


class DeviceIdentifier:
    def __init__(self, *_, **__):
        pass

    def identify(self, *_args, **_kwargs) -> USBDevice:
        return USBDevice()


__all__ = ['USBDevice', 'DeviceIdentifier']
