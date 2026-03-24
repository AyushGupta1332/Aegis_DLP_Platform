"""Security-specific tools for Aegis DLP platform."""
import logging
import os
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Any
from .base import BaseTool

# Get database paths - Go up from agentic/tools/ to project root
TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))  # agentic/tools/
AGENTIC_DIR = os.path.dirname(TOOLS_DIR)  # agentic/
PROJECT_ROOT = os.path.dirname(AGENTIC_DIR)  # project root

# Correct paths
PHISHING_DB = os.path.join(PROJECT_ROOT, 'databases', 'emails.db')
DATA_DIR = os.path.join(PROJECT_ROOT, 'data')


class AnomalyQueryTool(BaseTool):
    """Tool to query anomaly detection logs and MLP model predictions."""
    
    def __init__(self):
        super().__init__(
            name="anomaly_query",
            description="Query network anomaly detection results. Can get recent anomalies, statistics, or specific details."
        )
    
    async def execute(self, query_type: str = "recent", limit: int = 10) -> Dict[str, Any]:
        """
        Query anomaly detection data.
        query_type: 'recent' | 'stats' | 'summary' | 'live'
        """
        logging.info(f"Querying anomaly data: {query_type}")
        
        try:
            # First try to get live stats from Flask app globals
            live_stats = self._get_live_stats()
            
            if query_type == "live" or query_type == "stats":
                if live_stats:
                    return {
                        "status": "success",
                        "source": "live",
                        "total_samples": live_stats.get('total_samples', 0),
                        "normal_count": live_stats.get('normal_count', 0),
                        "anomaly_count": live_stats.get('anomaly_count', 0),
                        "monitoring_active": live_stats.get('monitoring_active', False),
                        "anomaly_rate": f"{(live_stats.get('anomaly_count', 0) / max(live_stats.get('total_samples', 1), 1) * 100):.2f}%"
                    }
            
            # Fall back to CSV files for historical data
            # First check for fixed ids_capture.csv file
            fixed_csv = os.path.join(DATA_DIR, 'ids_capture.csv')
            if os.path.exists(fixed_csv):
                latest_csv = fixed_csv
                search_dir = DATA_DIR
            else:
                # Fallback to legacy normal_windows_* files
                csv_locations = [DATA_DIR, PROJECT_ROOT]
                csv_files = []
                search_dir = None
                
                for loc in csv_locations:
                    if os.path.exists(loc):
                        files = [f for f in os.listdir(loc) 
                                if f.startswith('normal_windows_') and f.endswith('.csv')]
                        if files:
                            csv_files = files
                            search_dir = loc
                            break
                
                if csv_files:
                    latest_csv = max(csv_files, key=lambda f: os.path.getctime(os.path.join(search_dir, f)))
                    latest_csv = os.path.join(search_dir, latest_csv)
                else:
                    latest_csv = None
            
            if not latest_csv:
                # Return live stats if available, otherwise no data message
                if live_stats and live_stats.get('total_samples', 0) > 0:
                    return {
                        "status": "success",
                        "source": "live",
                        "total_samples": live_stats.get('total_samples', 0),
                        "normal_count": live_stats.get('normal_count', 0),
                        "anomaly_count": live_stats.get('anomaly_count', 0),
                        "monitoring_active": live_stats.get('monitoring_active', False),
                        "message": "Live monitoring data available."
                    }
                return {
                    "status": "no_data",
                    "message": "No anomaly detection logs found. Start monitoring to generate data.",
                    "recommendation": "Go to Anomaly Detection and start network monitoring."
                }
            
            # Read the CSV file
            df = pd.read_csv(latest_csv)
            
            total_samples = len(df)
            
            # Check if we have prediction data (anomaly column)
            if 'anomaly' in df.columns:
                anomaly_count = int(df['anomaly'].sum()) if df['anomaly'].dtype in ['int64', 'float64'] else 0
                normal_count = total_samples - anomaly_count
            else:
                anomaly_count = 0
                normal_count = total_samples
            
            if query_type == "stats":
                return {
                    "status": "success",
                    "source": "file",
                    "total_samples": total_samples,
                    "normal_count": normal_count,
                    "anomaly_count": anomaly_count,
                    "anomaly_rate": f"{(anomaly_count/total_samples*100):.2f}%" if total_samples > 0 else "0%",
                    "data_file": os.path.basename(latest_csv),
                    "last_updated": datetime.fromtimestamp(os.path.getctime(latest_csv)).isoformat()
                }
            
            elif query_type == "recent":
                # Get last N samples
                recent_samples = df.tail(limit).to_dict('records')
                return {
                    "status": "success",
                    "recent_samples": recent_samples[-5:],  # Limit to 5 for readability
                    "total_in_file": total_samples,
                    "showing": min(5, len(recent_samples))
                }
            
            else:  # summary
                return {
                    "status": "success",
                    "summary": f"Analyzed {total_samples} network traffic samples. "
                              f"Detected {anomaly_count} anomalies ({(anomaly_count/total_samples*100):.1f}% anomaly rate)." 
                              if total_samples > 0 else "No samples analyzed yet.",
                    "recommendation": "The MLP neural network is monitoring for intrusions and suspicious patterns."
                }
                
        except Exception as e:
            logging.error(f"Anomaly query error: {e}")
            return {"status": "error", "message": str(e)}
    
    def _get_live_stats(self) -> Dict[str, Any]:
        """Try to get live stats from Flask app globals."""
        try:
            import sys
            # Try to access Flask app globals
            if '__main__' in sys.modules:
                main = sys.modules['__main__']
                stats = getattr(main, 'stats', None)
                monitoring_active = getattr(main, 'monitoring_active', False)
                if stats:
                    return {
                        'total_samples': stats.get('total_samples', 0),
                        'normal_count': stats.get('normal_count', 0),
                        'anomaly_count': stats.get('anomaly_count', 0),
                        'monitoring_active': monitoring_active
                    }
        except Exception as e:
            logging.debug(f"Could not get live stats: {e}")
        return {}


class PhishingQueryTool(BaseTool):
    """Tool to query phishing email detection database."""
    
    def __init__(self):
        super().__init__(
            name="phishing_query",
            description="Query phishing email detection results. Can search emails, get statistics, or find specific threats."
        )
    
    async def execute(self, query_type: str = "stats", search_term: str = None, limit: int = 10) -> Dict[str, Any]:
        """
        Query phishing email data.
        query_type: 'stats' | 'recent' | 'search' | 'threats'
        """
        logging.info(f"Querying phishing data: {query_type}")
        
        if not os.path.exists(PHISHING_DB):
            return {
                "status": "no_data",
                "message": "No phishing emails analyzed yet. Connect your email in Phishing Detection to start scanning.",
                "recommendation": "Go to Phishing Detection and connect Gmail or Outlook."
            }
        
        try:
            conn = sqlite3.connect(PHISHING_DB)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if query_type == "stats":
                cursor.execute("SELECT COUNT(*) as total FROM Email")
                total = cursor.fetchone()['total']
                
                cursor.execute("SELECT category, COUNT(*) as count FROM Email GROUP BY category")
                categories = {row['category']: row['count'] for row in cursor.fetchall()}
                
                cursor.execute("SELECT COUNT(*) as review_count FROM Email WHERE needs_review = 1")
                needs_review = cursor.fetchone()['review_count']
                
                conn.close()
                
                return {
                    "status": "success",
                    "total_emails_analyzed": total,
                    "categories": categories,
                    "phishing_detected": categories.get('phishing', 0),
                    "suspicious_count": categories.get('suspicious', 0),
                    "safe_count": categories.get('safe', 0) + categories.get('legitimate', 0),
                    "needs_review": needs_review
                }
            
            elif query_type == "threats" or query_type == "recent":
                cursor.execute("""
                    SELECT sender, subject, category, confidence_score, created_at 
                    FROM Email 
                    WHERE category IN ('phishing', 'suspicious')
                    ORDER BY created_at DESC 
                    LIMIT ?
                """, (limit,))
                
                threats = []
                for row in cursor.fetchall():
                    threats.append({
                        "sender": row['sender'],
                        "subject": row['subject'][:50] + "..." if len(row['subject']) > 50 else row['subject'],
                        "category": row['category'],
                        "confidence": f"{row['confidence_score']:.0f}%" if row['confidence_score'] else "N/A",
                        "detected_at": row['created_at']
                    })
                
                conn.close()
                
                return {
                    "status": "success",
                    "threats_found": len(threats),
                    "threats": threats,
                    "message": f"Found {len(threats)} phishing/suspicious emails" if threats else "No threats detected recently"
                }
            
            elif query_type == "search" and search_term:
                cursor.execute("""
                    SELECT sender, subject, category, confidence_score 
                    FROM Email 
                    WHERE sender LIKE ? OR subject LIKE ?
                    LIMIT ?
                """, (f"%{search_term}%", f"%{search_term}%", limit))
                
                results = []
                for row in cursor.fetchall():
                    results.append({
                        "sender": row['sender'],
                        "subject": row['subject'][:50],
                        "category": row['category'],
                        "confidence": f"{row['confidence_score']:.0f}%" if row['confidence_score'] else "N/A"
                    })
                
                conn.close()
                
                return {
                    "status": "success",
                    "search_term": search_term,
                    "results_found": len(results),
                    "results": results
                }
            
            conn.close()
            return {"status": "success", "message": "Query completed"}
            
        except Exception as e:
            logging.error(f"Phishing query error: {e}")
            return {"status": "error", "message": str(e)}


class ClassificationQueryTool(BaseTool):
    """Tool to query data classification results from recent scans."""
    
    def __init__(self):
        super().__init__(
            name="classification_query",
            description="Query data classification scan results. Find sensitive files detected by RoBERTa model. Can show most sensitive files, stats, or recent scans."
        )
    
    def _get_classification_data(self):
        """Get classification results and stats from Flask app globals."""
        classification_results = []
        classification_stats = {}
        scanning_active = False
        
        try:
            import sys
            # Try __main__ first (most common when running app.py)
            if '__main__' in sys.modules:
                main = sys.modules['__main__']
                classification_results = getattr(main, 'classification_results', [])
                classification_stats = getattr(main, 'classification_stats', {})
                scanning_active = getattr(main, 'scanning_active', False)
        except Exception as e:
            logging.debug(f"Could not get classification data: {e}")
        
        return classification_results, classification_stats, scanning_active
    
    async def execute(self, query_type: str = "stats", limit: int = 10) -> Dict[str, Any]:
        """
        Query classification data from the Flask app's global state.
        query_type: 'stats' | 'sensitive' | 'recent' | 'top_confidence'
        """
        logging.info(f"Querying classification data: {query_type}")
        
        try:
            classification_results, classification_stats, scanning_active = self._get_classification_data()
            
            if not classification_results and not classification_stats.get('total_files', 0):
                return {
                    "status": "no_data",
                    "scanning_active": scanning_active,
                    "message": "No files have been scanned yet. Go to Data Classification and scan a folder first.",
                    "recommendation": "Navigate to Data Classification and scan a directory to analyze files.",
                    "model_info": "Uses RoBERTa transformer to detect sensitive data (PII, financial info, credentials, etc.)"
                }
            
            total_files = classification_stats.get('total_files', len(classification_results))
            sensitive_count = classification_stats.get('sensitive_count', 0)
            non_sensitive_count = classification_stats.get('non_sensitive_count', 0)
            
            if query_type == "stats":
                return {
                    "status": "success",
                    "total_files_scanned": total_files,
                    "sensitive_files": sensitive_count,
                    "non_sensitive_files": non_sensitive_count,
                    "risk_percentage": f"{(sensitive_count/total_files*100):.1f}%" if total_files > 0 else "0%",
                    "message": f"Scanned {total_files} files. Found {sensitive_count} sensitive files ({(sensitive_count/total_files*100):.1f}% risk)." if total_files > 0 else "No files scanned."
                }
            
            elif query_type == "sensitive" or query_type == "top_confidence":
                # Get sensitive files sorted by confidence
                sensitive_files = [
                    r for r in classification_results 
                    if r.get('classification') == 'Sensitive'
                ]
                
                # Sort by confidence descending
                sensitive_files.sort(key=lambda x: x.get('confidence', 0), reverse=True)
                
                # Take top N
                top_sensitive = sensitive_files[:limit]
                
                if not top_sensitive:
                    return {
                        "status": "success",
                        "message": "No sensitive files detected in the recent scan.",
                        "total_scanned": total_files
                    }
                
                files_list = []
                for f in top_sensitive:
                    files_list.append({
                        "filename": f.get('filename', 'Unknown'),
                        "path": f.get('path', ''),
                        "confidence": f"{f.get('confidence', 0):.1f}%",
                        "file_type": f.get('file_type', 'Unknown')
                    })
                
                return {
                    "status": "success",
                    "message": f"Found {len(sensitive_files)} sensitive files. Showing top {len(files_list)} by confidence.",
                    "sensitive_files": files_list,
                    "total_sensitive": len(sensitive_files)
                }
            
            elif query_type == "recent":
                # Get most recent scan results
                recent = classification_results[-limit:] if len(classification_results) > limit else classification_results
                recent = list(reversed(recent))  # Most recent first
                
                files_list = []
                for f in recent:
                    files_list.append({
                        "filename": f.get('filename', 'Unknown'),
                        "classification": f.get('classification', 'Unknown'),
                        "confidence": f"{f.get('confidence', 0):.1f}%"
                    })
                
                return {
                    "status": "success",
                    "message": f"Showing {len(files_list)} most recently scanned files.",
                    "recent_files": files_list
                }
            
            else:
                return {
                    "status": "success",
                    "total_files_scanned": total_files,
                    "sensitive_files": sensitive_count,
                    "model_info": "RoBERTa transformer for sensitive data detection"
                }
                
        except Exception as e:
            logging.error(f"Classification query error: {e}")
            return {
                "status": "error", 
                "message": f"Could not access scan results: {str(e)}",
                "recommendation": "Try running a scan first in the Data Classification page."
            }


class SecuritySummaryTool(BaseTool):
    """Tool to get overall security status summary including user activities."""
    
    def __init__(self):
        super().__init__(
            name="security_summary",
            description="Get overall security status, summary of all Aegis DLP features, and user's recent security activities."
        )
    
    async def execute(self, user_id: str = "default") -> Dict[str, Any]:
        """Get comprehensive security summary including user activities."""
        logging.info(f"Generating security summary for user: {user_id}")
        
        summary = {
            "status": "success",
            "platform": "Aegis DLP Platform",
            "total_modules": 9,
            "features": {
                "anomaly_detection": {
                    "model": "MLP Neural Network",
                    "status": "Active",
                    "description": "Real-time network intrusion detection"
                },
                "phishing_detection": {
                    "model": "RoBERTa + YARA",
                    "status": "Active" if os.path.exists(PHISHING_DB) else "Not configured",
                    "description": "Email threat detection and analysis"
                },
                "data_classification": {
                    "model": "RoBERTa Transformer",
                    "status": "Ready",
                    "description": "Sensitive data detection in files"
                },
                "file_monitoring": {
                    "model": "Watchdog",
                    "status": "Ready",
                    "description": "Real-time file system event monitoring"
                },
                "file_encryption": {
                    "model": "AES-256 Fernet",
                    "status": "Active",
                    "description": "Secure file encryption with QR sharing"
                },
                "malware_scanner": {
                    "model": "VirusTotal API",
                    "status": "Ready",
                    "description": "File and URL malware scanning"
                },
                "device_monitoring": {
                    "model": "USB Control",
                    "status": "Ready",
                    "description": "USB device registration and file transfer control"
                },
                "ai_assistant": {
                    "model": "LLaMA 3.1 via Groq",
                    "status": "Active",
                    "description": "AI-powered security assistant (that's me!)"
                },
                "event_bus": {
                    "model": "Pub/Sub + Correlation Engine",
                    "status": "Active",
                    "description": "Central event-driven system connecting all modules with compound threat detection and automated responses"
                }
            },
            "recommendation": "All 9 security modules operational. Use specific queries for detailed status."
        }
        
        # Add quick stats if phishing DB exists
        if os.path.exists(PHISHING_DB):
            try:
                conn = sqlite3.connect(PHISHING_DB)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM Email WHERE category IN ('phishing', 'suspicious')")
                threat_count = cursor.fetchone()[0]
                conn.close()
                summary["active_threats"] = threat_count
            except:
                pass
        
        # Get user's session activities
        try:
            from ..memory import get_activity_tracker
            tracker = get_activity_tracker()
            activity_summary = tracker.get_activity_summary(user_id)
            
            if activity_summary.get('has_activities'):
                summary["user_session"] = {
                    "total_activities": activity_summary.get('total_activities', 0),
                    "activity_breakdown": activity_summary.get('activity_counts', {}),
                    "recent_activities": []
                }
                
                # Format recent activities for display
                for activity in activity_summary.get('recent_activities', [])[:5]:
                    summary["user_session"]["recent_activities"].append({
                        "type": activity.get('type'),
                        "summary": activity.get('summary'),
                        "time": activity.get('timestamp')
                    })
            else:
                summary["user_session"] = {
                    "message": "No security activities recorded in this session. Use Aegis DLP tools to start tracking."
                }
        except Exception as e:
            logging.warning(f"Could not retrieve user activities: {e}")
            summary["user_session"] = {"message": "Activity tracking not available."}
        
        return summary


class FileMonitoringQueryTool(BaseTool):
    """Tool to query real-time file system monitoring events and statistics."""
    
    def __init__(self):
        super().__init__(
            name="file_monitoring_query",
            description="Query real-time file system monitoring. Get file events (created, modified, deleted), monitored directories, and activity statistics."
        )
    
    def _get_file_monitor_data(self):
        """Get file monitoring data from Flask app globals."""
        try:
            import sys
            if '__main__' in sys.modules:
                main = sys.modules['__main__']
                # Try to get file monitor instance
                get_file_monitor = getattr(main, 'get_file_monitor', None)
                if get_file_monitor:
                    monitor = get_file_monitor()
                    if monitor:
                        return {
                            'is_running': monitor.is_running,
                            'events': list(monitor.events)[-50:] if hasattr(monitor, 'events') else [],
                            'directories': list(monitor.watched_directories) if hasattr(monitor, 'watched_directories') else [],
                            'stats': monitor.get_stats() if hasattr(monitor, 'get_stats') else {}
                        }
        except Exception as e:
            logging.debug(f"Could not get file monitor data: {e}")
        return None
    
    async def execute(self, query_type: str = "status", limit: int = 20) -> Dict[str, Any]:
        """
        Query file monitoring data.
        query_type: 'status' | 'events' | 'stats' | 'directories'
        """
        logging.info(f"Querying file monitoring: {query_type}")
        
        try:
            data = self._get_file_monitor_data()
            
            if not data:
                return {
                    "status": "not_available",
                    "message": "File monitoring is not currently active or not configured.",
                    "recommendation": "Go to File Monitoring page and start monitoring a directory."
                }
            
            if query_type == "status":
                return {
                    "status": "success",
                    "monitoring_active": data.get('is_running', False),
                    "directories_watched": len(data.get('directories', [])),
                    "total_events": len(data.get('events', [])),
                    "directories": data.get('directories', [])[:5]
                }
            
            elif query_type == "events":
                events = data.get('events', [])[-limit:]
                formatted_events = []
                for event in events:
                    formatted_events.append({
                        "type": event.get('event_type', 'unknown'),
                        "path": event.get('path', ''),
                        "filename": os.path.basename(event.get('path', '')),
                        "time": event.get('timestamp', '')
                    })
                return {
                    "status": "success",
                    "events": formatted_events,
                    "total_shown": len(formatted_events),
                    "monitoring_active": data.get('is_running', False)
                }
            
            elif query_type == "stats":
                stats = data.get('stats', {})
                return {
                    "status": "success",
                    "statistics": stats,
                    "monitoring_active": data.get('is_running', False),
                    "directories_count": len(data.get('directories', []))
                }
            
            elif query_type == "directories":
                return {
                    "status": "success",
                    "directories": data.get('directories', []),
                    "count": len(data.get('directories', [])),
                    "monitoring_active": data.get('is_running', False)
                }
            
            return {"status": "success", "message": "Query completed"}
            
        except Exception as e:
            logging.error(f"File monitoring query error: {e}")
            return {"status": "error", "message": str(e)}


class MalwareScannerQueryTool(BaseTool):
    """Tool to query malware scan history and VirusTotal integration results."""
    
    def __init__(self):
        super().__init__(
            name="malware_scanner_query",
            description="Query malware scan results from VirusTotal integration. Get scan history, threat statistics, and details of scanned files/URLs."
        )
    
    async def execute(self, query_type: str = "stats", limit: int = 10) -> Dict[str, Any]:
        """
        Query malware scanner data.
        query_type: 'stats' | 'history' | 'threats' | 'recent'
        """
        logging.info(f"Querying malware scanner: {query_type}")
        
        try:
            # Check if malware database exists
            malware_db = os.path.join(PROJECT_ROOT, 'databases', 'malware_scans.db')
            
            if not os.path.exists(malware_db):
                return {
                    "status": "no_data",
                    "message": "No malware scans have been performed yet.",
                    "recommendation": "Go to Malware Scanner and scan a file or URL using VirusTotal."
                }
            
            conn = sqlite3.connect(malware_db)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if query_type == "stats":
                # Get overall statistics
                cursor.execute("SELECT COUNT(*) FROM scans")
                total_scans = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM scans WHERE threat_level IN ('high', 'critical')")
                high_threats = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM scans WHERE threat_level = 'clean'")
                clean_files = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM scans WHERE scan_type = 'file'")
                file_scans = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM scans WHERE scan_type = 'url'")
                url_scans = cursor.fetchone()[0]
                
                conn.close()
                
                return {
                    "status": "success",
                    "total_scans": total_scans,
                    "high_risk_threats": high_threats,
                    "clean_files": clean_files,
                    "file_scans": file_scans,
                    "url_scans": url_scans,
                    "detection_rate": f"{(high_threats/total_scans*100):.1f}%" if total_scans > 0 else "0%"
                }
            
            elif query_type == "threats" or query_type == "history":
                # Get recent scans with threats
                if query_type == "threats":
                    cursor.execute("""
                        SELECT filename, scan_type, threat_level, malicious_count, 
                               suspicious_count, scan_date 
                        FROM scans 
                        WHERE threat_level IN ('high', 'critical', 'medium')
                        ORDER BY scan_date DESC 
                        LIMIT ?
                    """, (limit,))
                else:
                    cursor.execute("""
                        SELECT filename, scan_type, threat_level, malicious_count, 
                               suspicious_count, scan_date 
                        FROM scans 
                        ORDER BY scan_date DESC 
                        LIMIT ?
                    """, (limit,))
                
                results = []
                for row in cursor.fetchall():
                    results.append({
                        "filename": row['filename'],
                        "scan_type": row['scan_type'],
                        "threat_level": row['threat_level'],
                        "malicious": row['malicious_count'],
                        "suspicious": row['suspicious_count'],
                        "scan_date": row['scan_date']
                    })
                
                conn.close()
                
                return {
                    "status": "success",
                    "results": results,
                    "count": len(results),
                    "query_type": query_type
                }
            
            elif query_type == "recent":
                cursor.execute("""
                    SELECT filename, threat_level, scan_date 
                    FROM scans 
                    ORDER BY scan_date DESC 
                    LIMIT 5
                """)
                
                recent = []
                for row in cursor.fetchall():
                    recent.append({
                        "filename": row['filename'],
                        "threat_level": row['threat_level'],
                        "scan_date": row['scan_date']
                    })
                
                conn.close()
                return {
                    "status": "success",
                    "recent_scans": recent
                }
            
            conn.close()
            return {"status": "success", "message": "Query completed"}
            
        except Exception as e:
            logging.error(f"Malware scanner query error: {e}")
            return {"status": "error", "message": str(e)}


class UnifiedDeviceMonitoringQueryTool(BaseTool):
    """Tool to query unified device monitoring - USB devices, file transfers, and permissions."""
    
    def __init__(self):
        super().__init__(
            name="device_monitoring_query",
            description="Query unified device monitoring. Get information about registered USB devices, file transfer policies, and device permissions."
        )
    
    async def execute(self, query_type: str = "status", limit: int = 10) -> Dict[str, Any]:
        """
        Query device monitoring data.
        query_type: 'status' | 'devices' | 'transfers' | 'policies'
        """
        logging.info(f"Querying device monitoring: {query_type}")
        
        try:
            # Check if unified monitoring database exists
            device_db = os.path.join(PROJECT_ROOT, 'databases', 'unified_monitoring', 'devices.db')
            users_db = os.path.join(PROJECT_ROOT, 'databases', 'unified_monitoring', 'users.db')
            
            if not os.path.exists(device_db):
                return {
                    "status": "not_configured",
                    "message": "Unified Device Monitoring is not set up yet.",
                    "recommendation": "Go to Device Monitoring and configure device registration."
                }
            
            conn = sqlite3.connect(device_db)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if query_type == "status":
                # Get device count
                cursor.execute("SELECT COUNT(*) FROM devices")
                total_devices = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM devices WHERE is_active = 1")
                active_devices = cursor.fetchone()[0]
                
                # Get transfer stats
                cursor.execute("SELECT COUNT(*) FROM transfer_logs")
                total_transfers = cursor.fetchone()[0]
                
                conn.close()
                
                # Get user count if users.db exists
                total_users = 0
                if os.path.exists(users_db):
                    try:
                        users_conn = sqlite3.connect(users_db)
                        users_cursor = users_conn.cursor()
                        users_cursor.execute("SELECT COUNT(*) FROM users")
                        total_users = users_cursor.fetchone()[0]
                        users_conn.close()
                    except:
                        pass
                
                return {
                    "status": "success",
                    "total_devices": total_devices,
                    "active_devices": active_devices,
                    "total_transfers": total_transfers,
                    "total_users": total_users,
                    "feature": "Unified Device Monitoring & File Transfer Control"
                }
            
            elif query_type == "devices":
                cursor.execute("""
                    SELECT friendly_name, device_type, is_active, registered_at, drive_letter
                    FROM devices 
                    ORDER BY registered_at DESC 
                    LIMIT ?
                """, (limit,))
                
                devices = []
                for row in cursor.fetchall():
                    devices.append({
                        "name": row['friendly_name'] or 'Unknown Device',
                        "type": row['device_type'] or 'USB Device',
                        "active": bool(row['is_active']),
                        "drive": row['drive_letter'] or 'N/A',
                        "registered": row['registered_at']
                    })
                
                conn.close()
                
                return {
                    "status": "success",
                    "devices": devices,
                    "count": len(devices)
                }
            
            elif query_type == "transfers":
                # Check for transfer logs
                cursor.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name='transfer_logs'
                """)
                
                if cursor.fetchone():
                    cursor.execute("""
                        SELECT device_hash, source_path, destination_path, 
                               file_size, transfer_status, timestamp 
                        FROM transfer_logs 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    """, (limit,))
                    
                    transfers = []
                    for row in cursor.fetchall():
                        # Extract filename from path
                        source = row['source_path'] or ''
                        filename = os.path.basename(source) if source else 'Unknown'
                        
                        transfers.append({
                            "filename": filename,
                            "source": source,
                            "destination": row['destination_path'],
                            "size_bytes": row['file_size'],
                            "status": row['transfer_status'],
                            "time": row['timestamp']
                        })
                    
                    conn.close()
                    return {
                        "status": "success",
                        "transfers": transfers,
                        "count": len(transfers)
                    }
                
                conn.close()
                return {
                    "status": "no_data",
                    "message": "No file transfer logs available."
                }
            
            conn.close()
            return {"status": "success", "message": "Query completed"}
            
        except Exception as e:
            logging.error(f"Device monitoring query error: {e}")
            return {"status": "error", "message": str(e)}


class EventBusQueryTool(BaseTool):
    """Tool to query the Event Bus & Correlation Engine - security event monitoring, correlation rules, and automated responses."""
    
    def __init__(self):
        super().__init__(
            name="event_bus_query",
            description="Query the Security Event Bus system. Get recent security events across all modules, correlation rules that detect compound threats, correlation matches, automated response action logs, event statistics, and system health."
        )
    
    def _get_event_bus_data(self):
        """Get Event Bus instances from Flask app globals."""
        try:
            import sys
            if '__main__' in sys.modules:
                main = sys.modules['__main__']
                
                event_bus = getattr(main, 'event_bus', None)
                EVENT_BUS_AVAILABLE = getattr(main, 'EVENT_BUS_AVAILABLE', False)
                
                if EVENT_BUS_AVAILABLE and event_bus:
                    # Also get logger, correlation engine, response executor
                    get_event_logger = getattr(main, 'get_event_logger', None)
                    get_correlation_engine = getattr(main, 'get_correlation_engine', None)
                    get_response_executor = getattr(main, 'get_response_executor', None)
                    
                    return {
                        'bus': event_bus,
                        'logger': get_event_logger() if get_event_logger else None,
                        'correlation': get_correlation_engine() if get_correlation_engine else None,
                        'executor': get_response_executor() if get_response_executor else None,
                        'available': True
                    }
        except Exception as e:
            logging.debug(f"Could not get event bus data: {e}")
        return None
    
    async def execute(self, query_type: str = "stats", limit: int = 20) -> Dict[str, Any]:
        """
        Query Event Bus data.
        query_type: 'stats' | 'events' | 'correlation_rules' | 'correlation_matches' | 'subscriptions' | 'responses' | 'health'
        """
        logging.info(f"Querying event bus: {query_type}")
        
        try:
            data = self._get_event_bus_data()
            
            if not data or not data.get('available'):
                return {
                    "status": "not_available",
                    "message": "Event Bus system is not currently active.",
                    "recommendation": "The Event Bus initializes automatically when the application starts. Check if the event_bus module is properly loaded."
                }
            
            bus = data['bus']
            event_logger = data.get('logger')
            correlation_engine = data.get('correlation')
            response_executor = data.get('executor')
            
            if query_type == "stats":
                result = {
                    "status": "success",
                    "feature": "Security Event Bus & Correlation Engine"
                }
                
                # Bus stats
                bus_stats = bus.get_stats()
                result["bus_stats"] = {
                    "total_events_published": bus_stats.get('total_published', 0),
                    "total_events_delivered": bus_stats.get('total_delivered', 0),
                    "total_errors": bus_stats.get('total_errors', 0),
                    "active_subscriptions": bus_stats.get('active_subscriptions', 0),
                    "history_size": bus_stats.get('history_size', 0),
                    "dispatcher_running": bus_stats.get('dispatcher_running', False),
                    "events_by_type": dict(list(bus_stats.get('events_by_type', {}).items())[:10]),
                    "events_by_severity": bus_stats.get('events_by_severity', {}),
                    "events_by_source": bus_stats.get('events_by_source', {})
                }
                
                # Logger stats
                if event_logger:
                    logger_stats = event_logger.get_stats()
                    result["persistence_stats"] = {
                        "total_events_logged": logger_stats.get('total_events', 0),
                        "events_last_24h": logger_stats.get('events_last_24h', 0),
                        "by_severity": logger_stats.get('by_severity', {}),
                        "unresolved_correlations": logger_stats.get('unresolved_correlations', 0)
                    }
                
                # Correlation stats
                if correlation_engine:
                    corr_stats = correlation_engine.get_stats()
                    result["correlation_stats"] = {
                        "total_rules": corr_stats.get('total_rules', 0),
                        "enabled_rules": corr_stats.get('enabled_rules', 0),
                        "total_evaluations": corr_stats.get('total_evaluations', 0),
                        "total_matches": corr_stats.get('total_matches', 0),
                        "matches_by_rule": corr_stats.get('matches_by_rule', {})
                    }
                
                # Response stats
                if response_executor:
                    resp_stats = response_executor.get_stats()
                    result["response_stats"] = {
                        "total_actions_executed": resp_stats.get('total_executed', 0),
                        "total_failures": resp_stats.get('total_failures', 0),
                        "registered_handlers": resp_stats.get('registered_handlers', []),
                        "log_size": resp_stats.get('log_size', 0)
                    }
                
                return result
            
            elif query_type == "events":
                events = bus.get_recent_events(limit=limit)
                formatted = []
                for evt in events:
                    formatted.append({
                        "event_type": evt.get('event_type', 'unknown'),
                        "severity": evt.get('severity', 'unknown'),
                        "source": evt.get('source', 'unknown'),
                        "message": evt.get('data', {}).get('message', 'No message'),
                        "timestamp": evt.get('created_at', ''),
                        "event_id": evt.get('event_id', '')[:8] + '...'
                    })
                return {
                    "status": "success",
                    "events": formatted,
                    "total_shown": len(formatted),
                    "message": f"Showing {len(formatted)} most recent security events across all modules."
                }
            
            elif query_type == "correlation_rules":
                if not correlation_engine:
                    return {"status": "error", "message": "Correlation engine not available."}
                
                rules = correlation_engine.get_rules()
                formatted_rules = []
                for rule in rules:
                    formatted_rules.append({
                        "name": rule.get('name', 'Unknown'),
                        "description": rule.get('description', ''),
                        "threat_level": rule.get('threat_level', 'unknown'),
                        "trigger_events": rule.get('trigger_events', []),
                        "time_window": f"{rule.get('time_window', 0)}s",
                        "count_threshold": rule.get('count_threshold', 0),
                        "responses": rule.get('responses', []),
                        "enabled": rule.get('enabled', False),
                        "matches": rule.get('matches', 0),
                        "last_fired": rule.get('last_fired', 'Never')
                    })
                return {
                    "status": "success",
                    "rules": formatted_rules,
                    "total_rules": len(formatted_rules),
                    "message": f"{len(formatted_rules)} correlation rules configured for compound threat detection."
                }
            
            elif query_type == "correlation_matches":
                if not event_logger:
                    return {"status": "error", "message": "Event logger not available."}
                
                matches = event_logger.get_correlation_matches(limit=limit)
                formatted_matches = []
                for match in matches:
                    formatted_matches.append({
                        "rule_name": match.get('rule_name', 'Unknown'),
                        "threat_level": match.get('threat_level', 'unknown'),
                        "response_actions": match.get('response_actions', []),
                        "timestamp": match.get('timestamp', ''),
                        "resolved": match.get('resolved', False),
                        "matched_event_count": len(match.get('matched_events', []))
                    })
                return {
                    "status": "success",
                    "matches": formatted_matches,
                    "total_shown": len(formatted_matches),
                    "message": f"Found {len(formatted_matches)} correlation matches (compound threat detections)."
                }
            
            elif query_type == "subscriptions":
                subs = bus.get_subscriptions()
                formatted_subs = []
                for sub in subs:
                    formatted_subs.append({
                        "subscriber": sub.get('subscriber_id', 'Unknown'),
                        "pattern": sub.get('pattern', '*'),
                        "description": sub.get('description', ''),
                        "active": sub.get('active', False),
                        "calls": sub.get('call_count', 0),
                        "errors": sub.get('error_count', 0)
                    })
                return {
                    "status": "success",
                    "subscriptions": formatted_subs,
                    "total": len(formatted_subs),
                    "message": f"{len(formatted_subs)} active event subscriptions registered."
                }
            
            elif query_type == "responses":
                if not response_executor:
                    return {"status": "error", "message": "Response executor not available."}
                
                actions = response_executor.get_action_log(limit=limit)
                formatted_actions = []
                for action in actions:
                    formatted_actions.append({
                        "action": action.get('action', 'Unknown'),
                        "rule": action.get('rule', ''),
                        "status": action.get('status', 'unknown'),
                        "timestamp": action.get('timestamp', ''),
                        "details": str(action.get('details', ''))[:100]
                    })
                return {
                    "status": "success",
                    "actions": formatted_actions,
                    "total_shown": len(formatted_actions),
                    "message": f"Showing {len(formatted_actions)} automated response actions."
                }
            
            elif query_type == "health":
                health = bus.get_health()
                return {
                    "status": "success",
                    "system_status": health.get('status', 'unknown'),
                    "subscribers": health.get('subscribers', {}),
                    "message": f"Event Bus is {health.get('status', 'unknown')}."
                }
            
            return {"status": "success", "message": "Query completed"}
            
        except Exception as e:
            logging.error(f"Event bus query error: {e}")
            return {"status": "error", "message": str(e)}
