"""
Aegis DLP - Flask Blueprints
=============================
Modular route organization for the Aegis DLP platform.
Each blueprint handles a specific security module's routes and helpers.

Phase 1 (Migrated):
  - event_bus_bp     — Event Bus dashboard & API (8 routes)
  - file_monitor_bp  — File Monitoring (12 routes)
  - chatbot_bp       — AI Chatbot & Activity Tracking (6 routes)
  - malware_bp       — Malware Scanner / VirusTotal (5 routes)

Phase 2 (Migrated):
  - network_ids_bp         — Network IDS / Anomaly Detection (5 routes)
  - classification_bp      — Data Classification (4 routes)
  - encryption_bp          — File Encryption / CryptoVault (9 routes)
  - phishing_bp            — Phishing Detection (18 routes)
  - unified_monitoring_bp  — Unified Device Monitoring (32 routes)
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

# All fully migrated blueprints ready for registration
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
