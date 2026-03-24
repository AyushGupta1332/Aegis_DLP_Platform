"""
Shared Application State
=========================
Central store for shared state that multiple blueprints need access to.
This breaks circular import chains by providing a neutral location for globals.

Usage from any blueprint:
    from blueprints.shared_state import app_state
    socketio = app_state.socketio
    event_bus = app_state.event_bus
"""

from collections import deque


class AppState:
    """Singleton holding shared application state."""
    
    def __init__(self):
        # Flask extensions
        self.socketio = None
        self.app = None
        
        # Event Bus
        self.event_bus = None
        self.EVENT_BUS_AVAILABLE = False
        
        # Network IDS state
        self.monitoring_active = False
        self.traffic_gen_process = None
        self.monitor_thread = None
        self.prediction_queue = deque(maxlen=100)
        self.stats = {
            'total_samples': 0,
            'normal_count': 0,
            'anomaly_count': 0,
            'accuracy': 0.0
        }
        self.last_processed_rows = 0
        self.ids_capture_instance = None
        
        # MLP Model (loaded at startup)
        self.mlp_model = None
        self.mlp_scaler = None
        self.mlp_label_encoders = None
        self.mlp_feature_info = None
        
        # Data Classification state
        self.scanning_active = False
        self.scan_thread = None
        self.classification_results = []
        self.classification_stats = {
            'total_files': 0,
            'sensitive_count': 0,
            'non_sensitive_count': 0
        }
        
        # File Encryption state
        self.encryption_file_storage = {}
        
        # Phishing state
        self.yara_rules = None
        self.trusted_set = set()
        self.PHISHING_AVAILABLE = False
        
        # Unified Monitoring state
        self.unified_identifier = None
        self.unified_registry = None
        self.unified_controller = None
        self.unified_user_manager = None
        self.unified_alert_manager = None
        self.UNIFIED_MONITORING_AVAILABLE = False
        
    def publish_event_bus(self, event_type, severity=None, module=None, message=None, **extra_data):
        """Safely publish an event to the Event Bus."""
        if not self.EVENT_BUS_AVAILABLE or not self.event_bus:
            return
        try:
            from modules.event_bus import system_event
            from modules.event_bus.events import Severity as SevEnum
            
            sev = severity if severity else SevEnum.INFO
            evt = system_event(
                event_type=event_type,
                severity=sev,
                module=module or 'Unknown',
                message=message or '',
                **extra_data
            )
            self.event_bus.publish(evt)
        except Exception:
            pass


# Singleton instance
app_state = AppState()
