"""
File Monitoring Module for Aegis DLP Platform
Real-time file system monitoring with threat detection capabilities.

Features:
- Real-time file event tracking (create, modify, delete, move, access)
- Threat detection (ransomware patterns, bulk changes)
- In-memory storage for maximum speed
- Process attribution
- Email alerts for critical events
"""

import os
import time
import math
import threading
import hashlib
import json
import sqlite3
import queue
from datetime import datetime, timedelta
from collections import deque, defaultdict
from pathlib import Path
import logging

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("Warning: watchdog library not installed. Run: pip install watchdog")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not installed. Process attribution disabled. Run: pip install psutil")

# Event Bus integration
try:
    from modules.event_bus import (
        get_event_bus, EventType, Severity,
        file_event as create_file_event
    )
    EVENT_BUS_AVAILABLE = True
except ImportError:
    EVENT_BUS_AVAILABLE = False

logger = logging.getLogger(__name__)

# Event severity levels
SEVERITY_INFO = 'info'
SEVERITY_WARNING = 'warning'
SEVERITY_CRITICAL = 'critical'

# ---- Externalized Ransomware Extension List ----
_DATA_DIR = Path(__file__).parent.parent / 'data'
_RANSOMWARE_EXT_PATH = _DATA_DIR / 'ransomware_extensions.json'

# Default fallback list (used if JSON file doesn't exist)
_DEFAULT_SUSPICIOUS_EXTENSIONS = {
    '.encrypted', '.locked', '.crypto', '.crypt', '.enc', '.crypted',
    '.locky', '.cerber', '.zepto', '.odin', '.thor', '.zzzzz',
    '.aaa', '.abc', '.xyz', '.micro', '.vvv', '.ccc', '.ecc',
    '.exx', '.ezz', '.xxx', '.ttt', '.rrr', '.darkness'
}

def load_ransomware_extensions() -> set:
    """Load ransomware extension list from external JSON, with fallback."""
    try:
        if _RANSOMWARE_EXT_PATH.exists():
            with open(_RANSOMWARE_EXT_PATH, 'r') as f:
                data = json.load(f)
                return set(data.get('extensions', []))
    except Exception as e:
        logger.warning(f"Could not load ransomware extensions from JSON: {e}")
    return _DEFAULT_SUSPICIOUS_EXTENSIONS.copy()

SUSPICIOUS_EXTENSIONS = load_ransomware_extensions()

def calculate_file_entropy(filepath: str, sample_size: int = 8192) -> float:
    """Calculate Shannon entropy of a file. Values >7.5 suggest encryption."""
    try:
        with open(filepath, 'rb') as f:
            data = f.read(sample_size)
        if not data:
            return 0.0
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        length = len(data)
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy
    except Exception:
        return 0.0

# File type categories for filtering
FILE_CATEGORIES = {
    'documents': {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf', '.odt'},
    'images': {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.ico', '.tiff'},
    'code': {'.py', '.js', '.html', '.css', '.java', '.cpp', '.c', '.h', '.php', '.rb', '.go', '.rs', '.ts'},
    'archives': {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'},
    'executables': {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.msi', '.com', '.scr'},
    'data': {'.json', '.xml', '.csv', '.yaml', '.yml', '.sql', '.db', '.sqlite'}
}

# Config path only (no database)
CONFIG_DIR = Path(__file__).parent.parent / 'databases' / 'file_monitor'
CONFIG_PATH = CONFIG_DIR / 'config.json'

# Events SQLite database
EVENT_DB_PATH = CONFIG_DIR / 'file_events.db'


class EventDBWriter:
    """Async SQLite writer for file events. Runs in a background thread."""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or str(EVENT_DB_PATH)
        self._queue = queue.Queue(maxsize=5000)
        self._running = False
        self._thread = None
        self._init_db()
    
    def _init_db(self):
        """Initialize the SQLite events table."""
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.db_path)
            conn.execute('''CREATE TABLE IF NOT EXISTS file_events (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                path TEXT NOT NULL,
                old_path TEXT,
                is_directory BOOLEAN DEFAULT 0,
                timestamp TEXT NOT NULL,
                severity TEXT DEFAULT 'info',
                filename TEXT,
                extension TEXT,
                directory TEXT,
                file_size INTEGER,
                file_hash TEXT,
                process_name TEXT,
                process_id INTEGER,
                entropy REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON file_events(timestamp)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_events_type ON file_events(event_type)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_events_severity ON file_events(severity)')
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to initialize events DB: {e}")
    
    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._writer_loop, daemon=True)
        self._thread.start()
    
    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def write(self, event: 'FileEvent', entropy: float = None):
        """Queue an event for async DB write."""
        try:
            self._queue.put_nowait((event, entropy))
        except queue.Full:
            logger.warning("Event DB write queue full, dropping event")
    
    def _writer_loop(self):
        """Background loop that batches and writes events to SQLite."""
        while self._running:
            batch = []
            try:
                # Drain up to 50 events at a time
                while len(batch) < 50:
                    try:
                        item = self._queue.get(timeout=1.0)
                        batch.append(item)
                    except queue.Empty:
                        break
                
                if batch:
                    self._write_batch(batch)
            except Exception as e:
                logger.error(f"Event DB writer error: {e}")
    
    def _write_batch(self, batch):
        """Write a batch of events to SQLite."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            for event, entropy in batch:
                cursor.execute('''INSERT OR IGNORE INTO file_events
                    (id, event_type, path, old_path, is_directory, timestamp,
                     severity, filename, extension, directory, file_size,
                     file_hash, process_name, process_id, entropy)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (event.id, event.event_type, event.path, event.old_path,
                     event.is_directory, event.timestamp.isoformat(),
                     event.severity, event.filename, event.extension,
                     event.directory, event.file_size, event.file_hash,
                     event.process_name, event.process_id, entropy))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Event DB batch write error: {e}")


class FileEvent:
    """Represents a file system event with metadata."""
    
    def __init__(self, event_type: str, path: str, is_directory: bool = False,
                 old_path: str = None, severity: str = SEVERITY_INFO,
                 file_size: int = None, file_hash: str = None,
                 process_name: str = None, process_id: int = None):
        self.id = hashlib.md5(f"{time.time()}{path}{event_type}".encode()).hexdigest()[:12]
        self.event_type = event_type
        self.path = path
        self.old_path = old_path
        self.is_directory = is_directory
        self.timestamp = datetime.now()
        self.severity = severity
        self.filename = os.path.basename(path)
        self.extension = os.path.splitext(path)[1].lower()
        self.directory = os.path.dirname(path)
        self.file_size = file_size
        self.file_hash = file_hash
        self.process_name = process_name
        self.process_id = process_id
        
    def to_dict(self):
        return {
            'id': self.id,
            'event_type': self.event_type,
            'path': self.path,
            'old_path': self.old_path,
            'is_directory': self.is_directory,
            'timestamp': self.timestamp.strftime('%d %b %Y, %I:%M:%S %p'),
            'timestamp_display': self.timestamp.strftime('%I:%M:%S %p'),
            'date_display': self.timestamp.strftime('%d %b %Y'),
            'severity': self.severity,
            'filename': self.filename,
            'extension': self.extension,
            'directory': self.directory,
            'file_size': self.file_size,
            'file_size_display': self._format_size(self.file_size),
            'file_hash': self.file_hash,
            'process_name': self.process_name,
            'process_id': self.process_id
        }
    
    def _format_size(self, size):
        """Format file size for display."""
        if size is None:
            return 'N/A'
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"


class ConfigManager:
    """Manages configuration persistence."""
    
    def __init__(self, config_path: str = None):
        self.config_path = config_path or str(CONFIG_PATH)
        self.default_config = {
            'auto_start': False,
            'watched_directories': [],
            'filter_extensions': [],
            'filter_categories': [],
            'access_monitoring_enabled': True,
            'access_poll_interval': 5
        }
        self._ensure_config_exists()
    
    def _ensure_config_exists(self):
        """Create config file if it doesn't exist."""
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            if not os.path.exists(self.config_path):
                self.save_config(self.default_config)
        except Exception as e:
            logger.warning(f"Could not create config: {e}")
    
    def load_config(self) -> dict:
        """Load configuration from file."""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                return {**self.default_config, **config}
        except Exception as e:
            logger.warning(f"Could not load config: {e}")
            return self.default_config.copy()
    
    def save_config(self, config: dict) -> bool:
        """Save configuration to file."""
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False
    
    def update_config(self, updates: dict) -> bool:
        """Update specific configuration values."""
        config = self.load_config()
        config.update(updates)
        return self.save_config(config)


class AccessMonitor:
    """Monitors file access times to detect when files are opened."""
    
    def __init__(self, monitor, poll_interval: int = 5):
        self.monitor = monitor
        self.poll_interval = poll_interval
        self.running = False
        self.thread = None
        self.file_access_times = {}
        self.lock = threading.Lock()
    
    def start(self):
        """Start access monitoring."""
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Access monitoring started")
    
    def stop(self):
        """Stop access monitoring."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        logger.info("Access monitoring stopped")
    
    def _scan_directory(self, directory: str):
        """Scan a directory for files and their access times."""
        try:
            for root, dirs, files in os.walk(directory):
                dirs[:] = [d for d in dirs if not any(
                    p in d for p in ['__pycache__', '.git', 'node_modules', '.vscode']
                )]
                
                for filename in files:
                    filepath = os.path.join(root, filename)
                    try:
                        stat = os.stat(filepath)
                        yield filepath, stat.st_atime
                    except (OSError, PermissionError):
                        continue
        except Exception as e:
            logger.debug(f"Error scanning directory {directory}: {e}")
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                with self.lock:
                    directories = list(self.monitor.watched_directories)
                
                for directory in directories:
                    if not self.running:
                        break
                    
                    for filepath, access_time in self._scan_directory(directory):
                        if not self.running:
                            break
                        
                        old_time = self.file_access_times.get(filepath)
                        
                        if old_time is None:
                            self.file_access_times[filepath] = access_time
                        elif access_time > old_time + 1:
                            self.file_access_times[filepath] = access_time
                            self._emit_access_event(filepath)
                
            except Exception as e:
                logger.error(f"Access monitor error: {e}")
            
            for _ in range(self.poll_interval * 2):
                if not self.running:
                    break
                time.sleep(0.5)
    
    def _emit_access_event(self, filepath: str):
        """Emit an access event."""
        if not self.monitor.is_monitoring:
            return
        
        try:
            stat = os.stat(filepath)
            file_size = stat.st_size
        except:
            file_size = None
        
        event = FileEvent(
            event_type='accessed',
            path=filepath,
            is_directory=False,
            severity=SEVERITY_INFO,
            file_size=file_size
        )
        
        self.monitor.add_event(event)
        
        if self.monitor.socketio:
            self.monitor.socketio.emit('file_event', event.to_dict())


class SentinelFileHandler(FileSystemEventHandler):
    """Custom file system event handler with threat detection."""
    
    def __init__(self, monitor, socketio=None):
        super().__init__()
        self.monitor = monitor
        self.socketio = socketio
        self.event_buffer = deque(maxlen=1000)
        self.last_emit_time = {}
        self.emit_cooldown = 0.3  # Fast response
        
        # Track file states
        self.file_states = {}
        
        # System files to ignore
        self.ignore_files = {
            'thumbs.db', 'desktop.ini', '.ds_store', 'folder.jpg', 'folder.gif',
            'albumart.jpg', 'icon.ico', '.thumbnails'
        }
        
        # Ignore patterns
        self.ignore_patterns = [
            '.tmp', '.temp', '~$', '.swp', '.lock', '.partial',
            'thumbcache_', '.crdownload', '.part'
        ]
    
    def _is_ignored_file(self, path: str) -> bool:
        """Check if file should be ignored."""
        filename = os.path.basename(path).lower()
        
        if filename in self.ignore_files:
            return True
        
        for pattern in self.ignore_patterns:
            if pattern in filename.lower():
                return True
        
        return False
        
    def _should_emit(self, path: str, event_type: str) -> bool:
        """Rate limit events."""
        now = time.time()
        key = f"{path}:{event_type}"
        last_time = self.last_emit_time.get(key, 0)
        if now - last_time < self.emit_cooldown:
            return False
        self.last_emit_time[key] = now
        return True
    
    def _get_file_size(self, path: str) -> int:
        """Get file size."""
        try:
            if os.path.exists(path) and os.path.isfile(path):
                return os.path.getsize(path)
        except (OSError, PermissionError):
            pass
        return None
    
    def _has_file_actually_changed(self, path: str) -> bool:
        """Verify if file content actually changed by checking size."""
        try:
            if not os.path.exists(path) or not os.path.isfile(path):
                return False
            
            current_size = os.path.getsize(path)
            current_mtime = os.path.getmtime(path)
            
            old_state = self.file_states.get(path)
            
            # First time seeing this file - record state, don't report
            if old_state is None:
                self.file_states[path] = (current_size, current_mtime)
                return False
            
            old_size, old_mtime = old_state
            self.file_states[path] = (current_size, current_mtime)
            
            # Only report if size actually changed
            if current_size != old_size:
                return True
            
            # If mtime changed by >2 seconds and same size, might be real edit
            # (Some apps save without size change)
            if abs(current_mtime - old_mtime) > 2:
                return True
            
            return False
            
        except (OSError, PermissionError):
            return False
    
    def _check_suspicious_extension(self, path: str) -> bool:
        """Check if file has suspicious extension."""
        ext = os.path.splitext(path)[1].lower()
        return ext in SUSPICIOUS_EXTENSIONS
    
    def _detect_bulk_changes(self) -> bool:
        """Detect rapid bulk file changes using per-directory behavioral baseline."""
        now = datetime.now()
        cutoff = now - timedelta(seconds=10)
        recent_count = sum(1 for event in self.event_buffer if event.timestamp > cutoff)
        
        # Fixed threshold as fallback
        if recent_count > 20:
            return True
        
        # Per-directory adaptive baseline
        if not hasattr(self, '_dir_baselines'):
            self._dir_baselines = {}  # dir -> deque of event counts per 60s window
            self._dir_current_window = {}  # dir -> (window_start, count)
        
        # Update per-directory counts
        for event in self.event_buffer:
            if event.timestamp < cutoff:
                continue
            directory = event.directory
            if directory not in self._dir_current_window:
                self._dir_current_window[directory] = (now, 0)
                self._dir_baselines[directory] = deque(maxlen=60)  # ~60 windows of history
            
            window_start, count = self._dir_current_window[directory]
            if (now - window_start).total_seconds() > 60:
                # Rotate window
                self._dir_baselines[directory].append(count)
                self._dir_current_window[directory] = (now, 1)
            else:
                self._dir_current_window[directory] = (window_start, count + 1)
        
        # Check each directory against its baseline
        for directory, baseline in self._dir_baselines.items():
            if len(baseline) < 3:
                continue  # Not enough history
            avg = sum(baseline) / len(baseline)
            _, current_count = self._dir_current_window.get(directory, (now, 0))
            if avg > 0 and current_count > avg * 5:
                logger.warning(
                    "Behavioral anomaly in %s: %d events vs avg %.1f (5x threshold)",
                    directory, current_count, avg
                )
                return True
        
        return False
    
    def _determine_severity(self, event_type: str, path: str) -> str:
        """Determine event severity."""
        if self._check_suspicious_extension(path):
            return SEVERITY_CRITICAL
        
        ext = os.path.splitext(path)[1].lower()
        if ext in FILE_CATEGORIES.get('executables', set()):
            if event_type in ('created', 'modified'):
                return SEVERITY_WARNING
        
        if self._detect_bulk_changes():
            return SEVERITY_CRITICAL
        
        if event_type == 'deleted' and ext in FILE_CATEGORIES.get('documents', set()):
            return SEVERITY_WARNING
        
        return SEVERITY_INFO
    
    def _process_event(self, event_type: str, src_path: str, 
                       is_directory: bool = False, dest_path: str = None):
        """Process and emit file system event."""
        if not self.monitor.is_monitoring:
            return
        
        if is_directory and event_type == 'modified':
            return
        
        if self._is_ignored_file(src_path):
            return
        
        if not self.monitor._should_process_path(src_path):
            return
        
        if not self._should_emit(src_path, event_type):
            return
        
        severity = self._determine_severity(event_type, src_path)
        file_size = self._get_file_size(src_path)
        
        file_event = FileEvent(
            event_type=event_type,
            path=src_path,
            is_directory=is_directory,
            old_path=dest_path if event_type == 'moved' else None,
            severity=severity,
            file_size=file_size
        )
        
        self.event_buffer.append(file_event)
        self.monitor.add_event(file_event)
        
        # Emit immediately via WebSocket
        if self.socketio:
            self.socketio.emit('file_event', file_event.to_dict())
            
            if severity == SEVERITY_CRITICAL:
                self.socketio.emit('threat_alert', {
                    'message': f'Critical: Suspicious activity detected - {event_type} {file_event.filename}',
                    'event': file_event.to_dict()
                })
        
        logger.debug(f"File event: {event_type} - {src_path}")
    
    def on_created(self, event: FileSystemEvent):
        self._process_event('created', event.src_path, event.is_directory)
    
    def on_deleted(self, event: FileSystemEvent):
        self._process_event('deleted', event.src_path, event.is_directory)
    
    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            return
        # Verify file content actually changed (filters out Windows Explorer noise)
        if not self._has_file_actually_changed(event.src_path):
            return
        self._process_event('modified', event.src_path, event.is_directory)
    
    def on_moved(self, event: FileSystemEvent):
        self._process_event('moved', event.dest_path, event.is_directory, event.src_path)


class FileMonitor:
    """Main file monitoring controller for Aegis DLP."""
    
    def __init__(self, socketio=None):
        self.socketio = socketio
        self.is_monitoring = False
        self.observer = None
        self.watched_directories = set()
        self.event_history = deque(maxlen=1000)  # In-memory ring buffer (fast display)
        self.stats = {
            'total_events': 0,
            'created': 0,
            'modified': 0,
            'deleted': 0,
            'moved': 0,
            'accessed': 0,
            'warnings': 0,
            'critical': 0
        }
        self.handler = None
        self.lock = threading.Lock()
        
        # Initialize managers
        self.config_manager = ConfigManager()
        self.access_monitor = None
        
        # SQLite event persistence (durable record alongside ring buffer)
        self._event_db_writer = EventDBWriter()
        self._event_db_writer.start()
        
        # Filtering options
        self.filter_extensions = set()
        self.filter_categories = set()
        self.exclude_patterns = {
            '__pycache__', '.git', '.svn', 'node_modules', '.vscode',
            '.idea', '*.pyc', '*.pyo', '*.tmp', '*.temp', '~$*'
        }
        
        # Load saved configuration
        self._load_saved_config()
    
    def _load_saved_config(self):
        """Load saved configuration on startup."""
        config = self.config_manager.load_config()
        
        for directory in config.get('watched_directories', []):
            if os.path.exists(directory):
                self.watched_directories.add(directory)
        
        if config.get('filter_extensions'):
            self.filter_extensions = set(config['filter_extensions'])
        if config.get('filter_categories'):
            self.filter_categories = set(config['filter_categories'])
        
        logger.info(f"Loaded config: {len(self.watched_directories)} directories")
    
    def _save_config(self):
        """Save current configuration."""
        config = self.config_manager.load_config()
        config['watched_directories'] = list(self.watched_directories)
        config['filter_extensions'] = list(self.filter_extensions)
        config['filter_categories'] = list(self.filter_categories)
        self.config_manager.save_config(config)
    
    def _should_process_path(self, path: str) -> bool:
        """Check if path should be processed based on filters."""
        filename = os.path.basename(path)
        
        for pattern in self.exclude_patterns:
            if pattern.startswith('*'):
                if filename.endswith(pattern[1:]):
                    return False
            elif pattern in path:
                return False
        
        if self.filter_extensions:
            ext = os.path.splitext(path)[1].lower()
            if ext not in self.filter_extensions:
                return False
        
        if self.filter_categories:
            ext = os.path.splitext(path)[1].lower()
            in_category = any(
                ext in FILE_CATEGORIES.get(cat, set())
                for cat in self.filter_categories
            )
            if not in_category:
                return False
        
        return True
    
    def add_event(self, event: FileEvent):
        """Add event to history, update stats, and persist to SQLite."""
        # Compute entropy for new/modified files (ransomware detection)
        entropy = None
        if event.event_type in ('created', 'modified') and not event.is_directory:
            try:
                if os.path.exists(event.path) and os.path.isfile(event.path):
                    entropy = calculate_file_entropy(event.path)
                    if entropy and entropy > 7.5:
                        event.severity = SEVERITY_WARNING
                        logger.warning(f"High entropy ({entropy:.2f}) detected: {event.path}")
            except Exception:
                pass
        
        with self.lock:
            self.event_history.appendleft(event)
            self.stats['total_events'] += 1
            self.stats[event.event_type] = self.stats.get(event.event_type, 0) + 1
            
            if event.severity == SEVERITY_WARNING:
                self.stats['warnings'] += 1
            elif event.severity == SEVERITY_CRITICAL:
                self.stats['critical'] += 1
        
        # Persist to SQLite (async, non-blocking)
        if hasattr(self, '_event_db_writer') and self._event_db_writer:
            self._event_db_writer.write(event, entropy)
        
        # Emit stats update
        if self.socketio:
            self.socketio.emit('monitor_stats', self.get_stats())
        
        # Publish to Event Bus for correlation engine
        if EVENT_BUS_AVAILABLE:
            self._publish_to_event_bus(event)
    
    def _publish_to_event_bus(self, event: FileEvent):
        """Bridge file events to the central Event Bus."""
        try:
            bus = get_event_bus()
            
            # Map file event types to EventType
            EVENT_TYPE_MAP = {
                'created': EventType.FILE_CREATED,
                'modified': EventType.FILE_MODIFIED,
                'deleted': EventType.FILE_DELETED,
                'moved': EventType.FILE_MOVED,
                'accessed': EventType.FILE_ACCESSED,
            }
            
            # Map severity levels
            SEVERITY_MAP = {
                SEVERITY_INFO: Severity.INFO,
                SEVERITY_WARNING: Severity.HIGH,
                SEVERITY_CRITICAL: Severity.CRITICAL,
            }
            
            event_type = EVENT_TYPE_MAP.get(event.event_type, EventType.FILE_MODIFIED)
            severity = SEVERITY_MAP.get(event.severity, Severity.INFO)
            
            # Check for ransomware pattern
            if event.extension in SUSPICIOUS_EXTENSIONS:
                event_type = EventType.FILE_RANSOMWARE_PATTERN
                severity = Severity.CRITICAL
            
            security_event = create_file_event(
                event_type=event_type,
                path=event.path,
                severity=severity,
                file_size=event.file_size,
                filename=event.filename,
                extension=event.extension,
                process_name=event.process_name,
                process_id=event.process_id,
                old_path=event.old_path,
            )
            
            bus.publish(security_event)
            
        except Exception as e:
            logger.debug(f"Failed to publish file event to bus: {e}")
    
    def add_directory(self, directory: str) -> dict:
        """Add a directory to the watch list."""
        directory = os.path.normpath(directory)
        
        if not os.path.exists(directory):
            return {'status': 'error', 'message': f'Directory does not exist: {directory}'}
        
        if not os.path.isdir(directory):
            return {'status': 'error', 'message': f'Path is not a directory: {directory}'}
        
        if directory in self.watched_directories:
            return {'status': 'info', 'message': f'Directory already being watched: {directory}'}
        
        self.watched_directories.add(directory)
        self._save_config()
        
        if self.is_monitoring and self.observer:
            try:
                self.observer.schedule(self.handler, directory, recursive=True)
                logger.info(f"Added directory to monitoring: {directory}")
            except Exception as e:
                return {'status': 'error', 'message': f'Failed to watch directory: {str(e)}'}
        
        return {'status': 'success', 'message': f'Added directory: {directory}'}
    
    def remove_directory(self, directory: str) -> dict:
        """Remove a directory from the watch list."""
        directory = os.path.normpath(directory)
        
        if directory not in self.watched_directories:
            return {'status': 'info', 'message': f'Directory not in watch list: {directory}'}
        
        self.watched_directories.discard(directory)
        self._save_config()
        
        return {'status': 'success', 'message': f'Removed directory: {directory}'}
    
    def start(self) -> dict:
        """Start file monitoring."""
        if not WATCHDOG_AVAILABLE:
            return {'status': 'error', 'message': 'watchdog library not installed'}
        
        if self.is_monitoring:
            return {'status': 'info', 'message': 'Monitoring already active'}
        
        if not self.watched_directories:
            return {'status': 'error', 'message': 'No directories to watch. Add directories first.'}
        
        try:
            self.handler = SentinelFileHandler(self, self.socketio)
            self.observer = Observer()
            
            for directory in self.watched_directories:
                if os.path.exists(directory):
                    self.observer.schedule(self.handler, directory, recursive=True)
                    logger.info(f"Watching directory: {directory}")
            
            self.observer.start()
            self.is_monitoring = True
            
            # Access monitoring disabled by default - too noisy on Windows
            # Windows updates st_atime even when just browsing/scrolling in Explorer
            # Uncomment below to enable (will generate many false positives)
            # config = self.config_manager.load_config()
            # if config.get('access_monitoring_enabled', False):
            #     poll_interval = config.get('access_poll_interval', 5)
            #     self.access_monitor = AccessMonitor(self, poll_interval)
            #     self.access_monitor.start()
            
            logger.info("File monitoring started")
            return {'status': 'success', 'message': 'Monitoring started', 
                    'directories': list(self.watched_directories)}
            
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def stop(self) -> dict:
        """Stop file monitoring."""
        if not self.is_monitoring:
            return {'status': 'info', 'message': 'Monitoring not active'}
        
        try:
            if self.observer:
                self.observer.stop()
                self.observer.join(timeout=5)
                self.observer = None
            
            if self.access_monitor:
                self.access_monitor.stop()
                self.access_monitor = None
            
            self.is_monitoring = False
            self.handler = None
            
            logger.info("File monitoring stopped")
            return {'status': 'success', 'message': 'Monitoring stopped'}
            
        except Exception as e:
            logger.error(f"Error stopping monitoring: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_stats(self) -> dict:
        """Get monitoring statistics."""
        with self.lock:
            return {
                **self.stats,
                'is_monitoring': self.is_monitoring,
                'directories_count': len(self.watched_directories),
                'directories': list(self.watched_directories)
            }
    
    def get_events(self, limit: int = 50, event_type: str = None,
                   search: str = None, start_date: str = None, 
                   end_date: str = None) -> list:
        """Get events with optional filtering from memory."""
        with self.lock:
            filtered_events = list(self.event_history)
        
        # Apply filters
        if event_type and event_type != 'all':
            filtered_events = [e for e in filtered_events if e.event_type == event_type]
        
        if search:
            search_lower = search.lower()
            filtered_events = [e for e in filtered_events 
                             if search_lower in e.filename.lower() or search_lower in e.path.lower()]
        
        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date)
                filtered_events = [e for e in filtered_events if e.timestamp.date() >= start_dt.date()]
            except:
                pass
        
        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date)
                filtered_events = [e for e in filtered_events if e.timestamp.date() <= end_dt.date()]
            except:
                pass
        
        return [e.to_dict() for e in filtered_events[:limit]]
    
    def get_event_by_id(self, event_id: str) -> dict:
        """Get a single event by ID."""
        with self.lock:
            for event in self.event_history:
                if event.id == event_id:
                    return event.to_dict()
        return None
    
    def export_events(self, format: str = 'csv', limit: int = 1000) -> str:
        """Export events to CSV or JSON."""
        events = self.get_events(limit=limit)
        
        if format == 'json':
            return json.dumps(events, indent=2)
        else:  # CSV
            if not events:
                return ''
            headers = ['id', 'event_type', 'path', 'old_path', 'timestamp', 'severity',
                      'filename', 'extension', 'file_size', 'process_name']
            lines = [','.join(headers)]
            for event in events:
                row = [str(event.get(h, '') or '').replace(',', ';').replace('\n', ' ') for h in headers]
                lines.append(','.join(row))
            return '\n'.join(lines)
    
    def get_status(self) -> dict:
        """Get monitoring status."""
        return {
            'is_monitoring': self.is_monitoring,
            'directories': list(self.watched_directories),
            'watchdog_available': WATCHDOG_AVAILABLE
        }
    
    def get_config(self) -> dict:
        """Get current configuration."""
        return self.config_manager.load_config()
    
    def update_config(self, updates: dict) -> dict:
        """Update configuration."""
        if self.config_manager.update_config(updates):
            return {'status': 'success', 'message': 'Configuration updated'}
        return {'status': 'error', 'message': 'Failed to update configuration'}
    
    def set_filters(self, extensions: list = None, categories: list = None,
                   exclude_patterns: list = None):
        """Set event filtering options."""
        if extensions is not None:
            self.filter_extensions = set(ext.lower() if ext.startswith('.') else f'.{ext.lower()}' 
                                         for ext in extensions)
        
        if categories is not None:
            valid_categories = set(FILE_CATEGORIES.keys())
            self.filter_categories = set(cat for cat in categories if cat in valid_categories)
        
        if exclude_patterns is not None:
            self.exclude_patterns = set(exclude_patterns)
        
        self._save_config()


# Singleton instance
_file_monitor_instance = None

def get_file_monitor(socketio=None) -> FileMonitor:
    """Get or create the file monitor singleton."""
    global _file_monitor_instance
    if _file_monitor_instance is None:
        _file_monitor_instance = FileMonitor(socketio)
    elif socketio and _file_monitor_instance.socketio is None:
        _file_monitor_instance.socketio = socketio
    return _file_monitor_instance
