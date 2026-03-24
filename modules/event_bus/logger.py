"""
Aegis DLP - Event Logger (Persistent Event Storage)
=====================================================
SQLite-based event persistence for audit trail and correlation queries.
All events published on the Event Bus are stored here for:
- Forensic analysis and incident response
- Correlation engine time-window queries
- Dashboard event timeline
- Compliance audit trail
"""

import os
import json
import sqlite3
import threading
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path

from .events import SecurityEvent, EventType, Severity, ModuleSource

logger = logging.getLogger(__name__)

# Database path
DB_DIR = Path(__file__).parent.parent.parent / 'databases' / 'event_bus'
DB_PATH = DB_DIR / 'events.db'


class EventLogger:
    """Persistent event storage using SQLite.
    
    Thread-safe: uses connection-per-thread with WAL mode for 
    concurrent read/write performance.
    """
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or str(DB_PATH)
        self._local = threading.local()
        self._init_lock = threading.Lock()
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Initialize schema
        self._init_db()
        
        logger.info("Event Logger initialized at: %s", self.db_path)
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a thread-local database connection."""
        if not hasattr(self._local, 'connection') or self._local.connection is None:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=-8000")  # 8MB cache
            self._local.connection = conn
        return self._local.connection
    
    def _init_db(self):
        """Create the events table and indexes."""
        with self._init_lock:
            conn = self._get_connection()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    event_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'info',
                    timestamp TEXT NOT NULL,
                    correlation_id TEXT,
                    data TEXT DEFAULT '{}',
                    metadata TEXT DEFAULT '{}',
                    created_at TEXT DEFAULT (datetime('now'))
                );
                
                CREATE INDEX IF NOT EXISTS idx_event_type 
                    ON security_events(event_type);
                CREATE INDEX IF NOT EXISTS idx_source 
                    ON security_events(source);
                CREATE INDEX IF NOT EXISTS idx_severity 
                    ON security_events(severity);
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                    ON security_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_correlation_id 
                    ON security_events(correlation_id);
                CREATE INDEX IF NOT EXISTS idx_created_at 
                    ON security_events(created_at);
                    
                -- Correlation matches table
                CREATE TABLE IF NOT EXISTS correlation_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    matched_events TEXT NOT NULL,
                    response_actions TEXT DEFAULT '[]',
                    timestamp TEXT DEFAULT (datetime('now')),
                    resolved BOOLEAN DEFAULT 0,
                    resolution_notes TEXT
                );
                
                CREATE INDEX IF NOT EXISTS idx_corr_rule 
                    ON correlation_matches(rule_name);
                CREATE INDEX IF NOT EXISTS idx_corr_timestamp 
                    ON correlation_matches(timestamp);
                CREATE INDEX IF NOT EXISTS idx_corr_resolved 
                    ON correlation_matches(resolved);
            """)
            conn.commit()
    
    # =========================================================================
    # EVENT LOGGING
    # =========================================================================
    
    def log_event(self, event: SecurityEvent) -> bool:
        """Store an event in the database.
        
        Args:
            event: SecurityEvent to persist
            
        Returns:
            True if stored successfully
        """
        try:
            conn = self._get_connection()
            conn.execute("""
                INSERT OR IGNORE INTO security_events 
                (event_id, event_type, source, severity, timestamp, 
                 correlation_id, data, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id,
                event.event_type.value,
                event.source.value,
                event.severity.value,
                event.timestamp,
                event.correlation_id,
                json.dumps(event.data),
                json.dumps(event.metadata),
            ))
            conn.commit()
            return True
        except Exception as e:
            logger.error("Failed to log event %s: %s", event.event_id, e)
            return False
    
    def log_correlation_match(self, rule_name: str, threat_level: str,
                               matched_event_ids: List[str],
                               response_actions: List[str] = None) -> bool:
        """Store a correlation match result."""
        try:
            conn = self._get_connection()
            conn.execute("""
                INSERT INTO correlation_matches 
                (rule_name, threat_level, matched_events, response_actions)
                VALUES (?, ?, ?, ?)
            """, (
                rule_name,
                threat_level,
                json.dumps(matched_event_ids),
                json.dumps(response_actions or []),
            ))
            conn.commit()
            return True
        except Exception as e:
            logger.error("Failed to log correlation match: %s", e)
            return False
    
    # =========================================================================
    # QUERYING EVENTS
    # =========================================================================
    
    def get_events(self, limit: int = 100,
                   event_type: str = None,
                   source: str = None,
                   severity: str = None,
                   min_severity: str = None,
                   correlation_id: str = None,
                   since: str = None,
                   until: str = None,
                   search: str = None,
                   offset: int = 0) -> List[Dict]:
        """Query stored events with filtering.
        
        Args:
            limit:           Max events to return
            event_type:      Filter by event type value
            source:          Filter by source module
            severity:        Filter by exact severity
            min_severity:    Filter by minimum severity
            correlation_id:  Filter by correlation chain
            since:           ISO timestamp - events after this time
            until:           ISO timestamp - events before this time
            search:          Search in event data (JSON contains)
            offset:          Pagination offset
        
        Returns:
            List of event dicts
        """
        conditions = []
        params = []
        
        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        
        if source:
            conditions.append("source = ?")
            params.append(source)
        
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        
        if min_severity:
            severity_levels = ['info', 'low', 'medium', 'high', 'critical']
            idx = severity_levels.index(min_severity) if min_severity in severity_levels else 0
            valid_severities = severity_levels[idx:]
            placeholders = ','.join('?' * len(valid_severities))
            conditions.append(f"severity IN ({placeholders})")
            params.extend(valid_severities)
        
        if correlation_id:
            conditions.append("correlation_id = ?")
            params.append(correlation_id)
        
        if since:
            conditions.append("timestamp >= ?")
            params.append(since)
        
        if until:
            conditions.append("timestamp <= ?")
            params.append(until)
        
        if search:
            conditions.append("data LIKE ?")
            params.append(f"%{search}%")
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        try:
            conn = self._get_connection()
            cursor = conn.execute(f"""
                SELECT * FROM security_events 
                WHERE {where_clause}
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """, params + [limit, offset])
            
            rows = cursor.fetchall()
            return [self._row_to_dict(row) for row in rows]
        except Exception as e:
            logger.error("Failed to query events: %s", e)
            return []
    
    def get_events_in_window(self, event_types: List[str], 
                              window_seconds: float) -> List[Dict]:
        """Get events of specific types within a time window.
        
        This is the key query for the Correlation Engine.
        
        Args:
            event_types:     List of event type values to match
            window_seconds:  Look back N seconds from now
            
        Returns:
            List of matching events, ordered by timestamp
        """
        since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        since_str = since.isoformat()
        
        placeholders = ','.join('?' * len(event_types))
        
        try:
            conn = self._get_connection()
            cursor = conn.execute(f"""
                SELECT * FROM security_events
                WHERE event_type IN ({placeholders})
                  AND timestamp >= ?
                ORDER BY timestamp ASC
            """, event_types + [since_str])
            
            return [self._row_to_dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error("Failed to query events in window: %s", e)
            return []
    
    def count_events_in_window(self, event_type: str, 
                                window_seconds: float) -> int:
        """Count events of a type within a time window.
        
        Used for threshold-based correlation rules (e.g., "50+ FILE_MODIFIED in 60s").
        """
        since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        since_str = since.isoformat()
        
        try:
            conn = self._get_connection()
            cursor = conn.execute("""
                SELECT COUNT(*) FROM security_events
                WHERE event_type = ? AND timestamp >= ?
            """, (event_type, since_str))
            
            return cursor.fetchone()[0]
        except Exception as e:
            logger.error("Failed to count events: %s", e)
            return 0
    
    def get_event_by_id(self, event_id: str) -> Optional[Dict]:
        """Get a single event by its ID."""
        try:
            conn = self._get_connection()
            cursor = conn.execute(
                "SELECT * FROM security_events WHERE event_id = ?", 
                (event_id,)
            )
            row = cursor.fetchone()
            return self._row_to_dict(row) if row else None
        except Exception as e:
            logger.error("Failed to get event: %s", e)
            return None
    
    def get_correlation_matches(self, limit: int = 50, 
                                 unresolved_only: bool = False) -> List[Dict]:
        """Get correlation match history."""
        try:
            conn = self._get_connection()
            condition = "WHERE resolved = 0" if unresolved_only else ""
            cursor = conn.execute(f"""
                SELECT * FROM correlation_matches
                {condition}
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'id': row['id'],
                    'rule_name': row['rule_name'],
                    'threat_level': row['threat_level'],
                    'matched_events': json.loads(row['matched_events']),
                    'response_actions': json.loads(row['response_actions']),
                    'timestamp': row['timestamp'],
                    'resolved': bool(row['resolved']),
                    'resolution_notes': row['resolution_notes'],
                })
            return results
        except Exception as e:
            logger.error("Failed to get correlation matches: %s", e)
            return []
    
    def resolve_correlation(self, match_id: int, notes: str = "") -> bool:
        """Mark a correlation match as resolved."""
        try:
            conn = self._get_connection()
            conn.execute("""
                UPDATE correlation_matches 
                SET resolved = 1, resolution_notes = ?
                WHERE id = ?
            """, (notes, match_id))
            conn.commit()
            return True
        except Exception as e:
            logger.error("Failed to resolve correlation: %s", e)
            return False
    
    # =========================================================================
    # STATISTICS
    # =========================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get event statistics from the database."""
        try:
            conn = self._get_connection()
            
            # Total count
            total = conn.execute(
                "SELECT COUNT(*) FROM security_events"
            ).fetchone()[0]
            
            # By type
            type_counts = {}
            for row in conn.execute(
                "SELECT event_type, COUNT(*) as cnt FROM security_events GROUP BY event_type ORDER BY cnt DESC"
            ).fetchall():
                type_counts[row['event_type']] = row['cnt']
            
            # By source
            source_counts = {}
            for row in conn.execute(
                "SELECT source, COUNT(*) as cnt FROM security_events GROUP BY source ORDER BY cnt DESC"
            ).fetchall():
                source_counts[row['source']] = row['cnt']
            
            # By severity
            severity_counts = {}
            for row in conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM security_events GROUP BY severity ORDER BY cnt DESC"
            ).fetchall():
                severity_counts[row['severity']] = row['cnt']
            
            # Last 24 hours
            last_24h = conn.execute("""
                SELECT COUNT(*) FROM security_events 
                WHERE created_at >= datetime('now', '-1 day')
            """).fetchone()[0]
            
            # Unresolved correlations
            unresolved = conn.execute(
                "SELECT COUNT(*) FROM correlation_matches WHERE resolved = 0"
            ).fetchone()[0]
            
            return {
                'total_events': total,
                'events_last_24h': last_24h,
                'by_type': type_counts,
                'by_source': source_counts,
                'by_severity': severity_counts,
                'unresolved_correlations': unresolved,
            }
        except Exception as e:
            logger.error("Failed to get stats: %s", e)
            return {}
    
    # =========================================================================
    # MAINTENANCE
    # =========================================================================
    
    def cleanup(self, days_to_keep: int = 30):
        """Remove events older than N days."""
        try:
            conn = self._get_connection()
            cursor = conn.execute("""
                DELETE FROM security_events 
                WHERE created_at < datetime('now', ?)
            """, (f"-{days_to_keep} days",))
            deleted = cursor.rowcount
            conn.commit()
            
            if deleted:
                logger.info("Cleaned up %d events older than %d days", 
                             deleted, days_to_keep)
                conn.execute("VACUUM")
                conn.commit()
            
            return deleted
        except Exception as e:
            logger.error("Cleanup failed: %s", e)
            return 0
    
    # =========================================================================
    # HELPERS
    # =========================================================================
    
    def _row_to_dict(self, row) -> Dict:
        """Convert an sqlite3.Row to a dictionary."""
        if row is None:
            return {}
        d = dict(row)
        # Parse JSON fields
        if 'data' in d and isinstance(d['data'], str):
            try:
                d['data'] = json.loads(d['data'])
            except json.JSONDecodeError:
                pass
        if 'metadata' in d and isinstance(d['metadata'], str):
            try:
                d['metadata'] = json.loads(d['metadata'])
            except json.JSONDecodeError:
                pass
        return d


# =============================================================================
# SINGLETON
# =============================================================================

_event_logger_instance: Optional[EventLogger] = None
_logger_lock = threading.Lock()


def get_event_logger(db_path: str = None) -> EventLogger:
    """Get or create the EventLogger singleton."""
    global _event_logger_instance
    
    with _logger_lock:
        if _event_logger_instance is None:
            _event_logger_instance = EventLogger(db_path)
        return _event_logger_instance
