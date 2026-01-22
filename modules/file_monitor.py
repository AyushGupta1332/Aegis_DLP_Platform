"""
File Monitoring Module for Aegis DLP Platform
Real-time file system monitoring with threat detection capabilities.
"""

import os
import time
import threading
import hashlib
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

logger = logging.getLogger(__name__)

# Event severity levels
SEVERITY_INFO = 'info'
SEVERITY_WARNING = 'warning'
SEVERITY_CRITICAL = 'critical'

# Suspicious file extensions (ransomware indicators)
SUSPICIOUS_EXTENSIONS = {
    '.encrypted', '.locked', '.crypto', '.crypt', '.enc', '.crypted',
    '.locky', '.cerber', '.zepto', '.odin', '.thor', '.zzzzz',
    '.aaa', '.abc', '.xyz', '.micro', '.vvv', '.ccc', '.ecc',
    '.exx', '.ezz', '.xxx', '.ttt', '.rrr', '.darkness'
}

# File type categories for filtering
FILE_CATEGORIES = {
    'documents': {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf', '.odt'},
    'images': {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.ico', '.tiff'},
    'code': {'.py', '.js', '.html', '.css', '.java', '.cpp', '.c', '.h', '.php', '.rb', '.go', '.rs', '.ts'},
    'archives': {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'},
    'executables': {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.msi', '.com', '.scr'},
    'data': {'.json', '.xml', '.csv', '.yaml', '.yml', '.sql', '.db', '.sqlite'}
}


class FileEvent:
    """Represents a file system event with metadata."""
    
    def __init__(self, event_type: str, path: str, is_directory: bool = False,
                 old_path: str = None, severity: str = SEVERITY_INFO):
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
        
    def to_dict(self):
        return {
            'id': self.id,
            'event_type': self.event_type,
            'path': self.path,
            'old_path': self.old_path,
            'is_directory': self.is_directory,
            'timestamp': self.timestamp.isoformat(),
            'timestamp_display': self.timestamp.strftime('%H:%M:%S'),
            'severity': self.severity,
            'filename': self.filename,
            'extension': self.extension,
            'directory': self.directory
        }


class SentinelFileHandler(FileSystemEventHandler):
    """Custom file system event handler with threat detection and false positive filtering."""
    
    def __init__(self, monitor, socketio=None):
        super().__init__()
        self.monitor = monitor
        self.socketio = socketio
        self.event_buffer = deque(maxlen=1000)
        self.recent_events = defaultdict(list)  # Track events per file for pattern detection
        self.last_emit_time = {}
        self.emit_cooldown = 2.0  # Minimum seconds between emits for same file (increased from 0.5)
        
        # Track file states to detect actual modifications
        self.file_states = {}  # {path: (mtime, size)}
        self.pending_modifications = {}  # {path: timestamp} for debouncing
        self.modification_debounce = 3.0  # Seconds to wait before confirming modification
        
        # System files to ignore (Windows generates events for these when browsing)
        self.ignore_files = {
            'thumbs.db', 'desktop.ini', '.ds_store', 'folder.jpg', 'folder.gif',
            'albumart.jpg', 'icon.ico', '.thumbnails', '~$',  # Office temp files
        }
        
        # Ignore patterns for temp/system activities
        self.ignore_patterns = [
            '.tmp', '.temp', '~$', '.swp', '.lock', '.partial',
            'thumbcache_', '.crdownload', '.part'
        ]
    
    def _is_ignored_file(self, path: str) -> bool:
        """Check if file should be ignored (system files, temp files, etc.)."""
        filename = os.path.basename(path).lower()
        
        # Check exact matches
        if filename in self.ignore_files:
            return True
        
        # Check patterns
        for pattern in self.ignore_patterns:
            if pattern in filename.lower():
                return True
        
        return False
        
    def _should_emit(self, path: str, event_type: str) -> bool:
        """Rate limit events for the same file with event-type awareness."""
        now = time.time()
        key = f"{path}:{event_type}"
        last_time = self.last_emit_time.get(key, 0)
        if now - last_time < self.emit_cooldown:
            return False
        self.last_emit_time[key] = now
        return True
    
    def _get_file_state(self, path: str) -> tuple:
        """Get current file state (mtime, size) for comparison."""
        try:
            if os.path.exists(path) and os.path.isfile(path):
                stat = os.stat(path)
                return (stat.st_mtime, stat.st_size)
        except (OSError, PermissionError):
            pass
        return None
    
    def _has_file_actually_changed(self, path: str) -> bool:
        """Check if file content actually changed by comparing mtime and size."""
        current_state = self._get_file_state(path)
        if current_state is None:
            return False  # File doesn't exist or can't access
        
        old_state = self.file_states.get(path)
        
        # If we haven't seen this file, record it but don't report as modified
        if old_state is None:
            self.file_states[path] = current_state
            return False
        
        # Check if mtime AND size actually changed
        old_mtime, old_size = old_state
        new_mtime, new_size = current_state
        
        # Update stored state
        self.file_states[path] = current_state
        
        # Only report if size changed (more reliable than mtime which Windows updates on access)
        if new_size != old_size:
            return True
        
        # If size is same but mtime changed significantly (>5 sec), might be real modification
        if abs(new_mtime - old_mtime) > 5:
            return True
        
        return False
    
    def _check_suspicious_extension(self, path: str) -> bool:
        """Check if file has suspicious extension."""
        ext = os.path.splitext(path)[1].lower()
        return ext in SUSPICIOUS_EXTENSIONS
    
    def _detect_bulk_changes(self) -> bool:
        """Detect rapid bulk file changes (potential ransomware)."""
        now = datetime.now()
        cutoff = now - timedelta(seconds=10)
        
        # Count recent events
        recent_count = sum(
            1 for event in self.event_buffer 
            if event.timestamp > cutoff
        )
        
        # Alert if more than 20 files changed in 10 seconds
        return recent_count > 20
    
    def _determine_severity(self, event_type: str, path: str) -> str:
        """Determine event severity based on patterns."""
        # Check for suspicious extensions
        if self._check_suspicious_extension(path):
            return SEVERITY_CRITICAL
        
        # Check for executables
        ext = os.path.splitext(path)[1].lower()
        if ext in FILE_CATEGORIES.get('executables', set()):
            if event_type in ('created', 'modified'):
                return SEVERITY_WARNING
        
        # Check for bulk changes
        if self._detect_bulk_changes():
            return SEVERITY_CRITICAL
        
        # Deletion of important files
        if event_type == 'deleted' and ext in FILE_CATEGORIES.get('documents', set()):
            return SEVERITY_WARNING
        
        return SEVERITY_INFO
    
    def _process_event(self, event_type: str, src_path: str, 
                       is_directory: bool = False, dest_path: str = None):
        """Process and emit file system event."""
        if not self.monitor.is_monitoring:
            return
        
        # Skip directory modification events (these are noisy and usually not meaningful)
        if is_directory and event_type == 'modified':
            return
        
        # Skip ignored files
        if self._is_ignored_file(src_path):
            return
        
        # Skip if filtered out by monitor settings
        if not self.monitor._should_process_path(src_path):
            return
        
        # For modification events, verify actual content change
        if event_type == 'modified' and not is_directory:
            if not self._has_file_actually_changed(src_path):
                return  # False positive - file didn't actually change
        
        # Rate limiting
        if not self._should_emit(src_path, event_type):
            return
        
        severity = self._determine_severity(event_type, src_path)
        
        file_event = FileEvent(
            event_type=event_type,
            path=src_path,
            is_directory=is_directory,
            old_path=dest_path if event_type == 'moved' else None,
            severity=severity
        )
        
        # Add to buffer
        self.event_buffer.append(file_event)
        self.monitor.add_event(file_event)
        
        # Emit via WebSocket
        if self.socketio:
            self.socketio.emit('file_event', file_event.to_dict())
            
            # Emit threat alert for critical events
            if severity == SEVERITY_CRITICAL:
                self.socketio.emit('threat_alert', {
                    'message': f'Critical: Suspicious activity detected - {event_type} {file_event.filename}',
                    'event': file_event.to_dict()
                })
        
        logger.debug(f"File event: {event_type} - {src_path}")
    
    def on_created(self, event: FileSystemEvent):
        # Record initial state for new files
        if not event.is_directory:
            self.file_states[event.src_path] = self._get_file_state(event.src_path)
        self._process_event('created', event.src_path, event.is_directory)
    
    def on_deleted(self, event: FileSystemEvent):
        # Remove from tracked states
        self.file_states.pop(event.src_path, None)
        self._process_event('deleted', event.src_path, event.is_directory)
    
    def on_modified(self, event: FileSystemEvent):
        # Skip directory modifications entirely - they're almost always noise
        if event.is_directory:
            return
        self._process_event('modified', event.src_path, event.is_directory)
    
    def on_moved(self, event: FileSystemEvent):
        # Update tracked state for moved files
        if event.src_path in self.file_states:
            self.file_states[event.dest_path] = self.file_states.pop(event.src_path)
        self._process_event('moved', event.dest_path, event.is_directory, event.src_path)


class FileMonitor:
    """
    Main file monitoring controller for Aegis DLP.
    Monitors directories for file system changes with threat detection.
    """
    
    def __init__(self, socketio=None):
        self.socketio = socketio
        self.is_monitoring = False
        self.observer = None
        self.watched_directories = set()
        self.event_history = deque(maxlen=500)
        self.stats = {
            'total_events': 0,
            'created': 0,
            'modified': 0,
            'deleted': 0,
            'moved': 0,
            'warnings': 0,
            'critical': 0
        }
        self.handler = None
        self.lock = threading.Lock()
        
        # Filtering options
        self.filter_extensions = set()  # Empty = all extensions
        self.filter_categories = set()  # Empty = all categories
        self.exclude_patterns = {
            '__pycache__', '.git', '.svn', 'node_modules', '.vscode',
            '.idea', '*.pyc', '*.pyo', '*.tmp', '*.temp', '~$*'
        }
    
    def _should_process_path(self, path: str) -> bool:
        """Check if path should be processed based on filters."""
        filename = os.path.basename(path)
        
        # Check exclude patterns
        for pattern in self.exclude_patterns:
            if pattern.startswith('*'):
                if filename.endswith(pattern[1:]):
                    return False
            elif pattern in path:
                return False
        
        # Check extension filters
        if self.filter_extensions:
            ext = os.path.splitext(path)[1].lower()
            if ext not in self.filter_extensions:
                return False
        
        # Check category filters
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
        """Add event to history and update stats."""
        with self.lock:
            self.event_history.append(event)
            self.stats['total_events'] += 1
            self.stats[event.event_type] = self.stats.get(event.event_type, 0) + 1
            
            if event.severity == SEVERITY_WARNING:
                self.stats['warnings'] += 1
            elif event.severity == SEVERITY_CRITICAL:
                self.stats['critical'] += 1
        
        # Emit stats update
        if self.socketio:
            self.socketio.emit('monitor_stats', self.get_stats())
    
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
        
        # If already monitoring, add to observer
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
        
        # Note: watchdog doesn't support unscheduling individual directories easily
        # Would need to restart observer to remove a directory
        
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
            
            # Reset stats on start
            self.stats = {
                'total_events': 0,
                'created': 0,
                'modified': 0,
                'deleted': 0,
                'moved': 0,
                'warnings': 0,
                'critical': 0
            }
            self.event_history.clear()
            
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
    
    def get_events(self, limit: int = 50) -> list:
        """Get recent events."""
        with self.lock:
            events = list(self.event_history)[-limit:]
            return [e.to_dict() for e in reversed(events)]
    
    def get_status(self) -> dict:
        """Get monitoring status."""
        return {
            'is_monitoring': self.is_monitoring,
            'directories': list(self.watched_directories),
            'watchdog_available': WATCHDOG_AVAILABLE
        }
    
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
