"""
Aegis DLP - Flask Blueprints (Redacted)
========================================
Internal route implementations are removed from this public repository.
"""

from .event_bus_bp import event_bus_bp
from .file_monitor_bp import file_monitor_bp
from .chatbot import chatbot_bp
from .malware import malware_bp
from .network_ids import network_ids_bp
from .classification import classification_bp
from .encryption import encryption_bp
from .phishing import phishing_bp
from .unified_monitoring import unified_monitoring_bp

ALL_BLUEPRINTS = [
    event_bus_bp,
    file_monitor_bp,
    chatbot_bp,
    malware_bp,
    network_ids_bp,
    classification_bp,
    encryption_bp,
    phishing_bp,
    unified_monitoring_bp,
]
