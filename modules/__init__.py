# Aegis DLP Modules Package
# This package contains all security analysis modules

# Safe imports (don't fail if dependencies are missing)
try:
    from .data_classifier import get_classifier, DataClassifier
except ImportError:
    pass

try:
    from .malware_scanner import VirusTotalScanner
except ImportError:
    pass

try:
    from .body_classifier import predict_body_label
except ImportError:
    pass

try:
    from .monitor import NormalCapture
except ImportError:
    pass

try:
    from .file_monitor import FileMonitor
except ImportError:
    pass

__all__ = [
    'get_classifier',
    'DataClassifier', 
    'VirusTotalScanner',
    'predict_body_label',
    'NormalCapture',
    'FileMonitor',
]
