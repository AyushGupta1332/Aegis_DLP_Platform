"""
Data Classifier (Redacted)
==========================
Model loading and classification logic are intentionally removed.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


def pii_pre_scan(_text: str) -> dict:
    """Return a redacted pre-scan result."""
    return {'status': 'redacted', 'findings': []}


@dataclass
class DataClassifier:
    """Placeholder classifier with no internal model."""

    def classify_file(self, file_path: str | Path) -> dict:
        path = Path(file_path)
        return {
            'filename': path.name,
            'path': str(path),
            'classification': 'Redacted',
            'confidence': 0.0,
            'file_size': 0,
            'file_type': path.suffix,
        }

    def classify_text(self, _text: str) -> dict:
        return {
            'classification': 'Redacted',
            'confidence': 0.0,
        }


_CLASSIFIER = DataClassifier()


def get_classifier() -> DataClassifier:
    """Return a redacted classifier instance."""
    return _CLASSIFIER


__all__ = ['pii_pre_scan', 'DataClassifier', 'get_classifier']
