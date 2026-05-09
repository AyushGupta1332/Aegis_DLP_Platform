"""
Shared Application State (Redacted)
====================================
This public repository omits internal module state and algorithms.
Only minimal shared state needed for the public app shell is retained.
"""

from collections import deque


class AppState:
    """Singleton holding minimal shared application state."""

    def __init__(self):
        self.socketio = None
        self.app = None
        self.event_bus = None
        self.EVENT_BUS_AVAILABLE = False

        self.monitoring_active = False
        self.prediction_queue = deque(maxlen=100)
        self.stats = {
            'total_samples': 0,
            'normal_count': 0,
            'anomaly_count': 0,
            'accuracy': 0.0,
        }

        self.scanning_active = False
        self.classification_results = []
        self.classification_stats = {
            'total_files': 0,
            'sensitive_count': 0,
            'non_sensitive_count': 0,
        }

    def publish_event_bus(self, *_, **__):
        """No-op placeholder for redacted event publishing."""
        return None


app_state = AppState()
