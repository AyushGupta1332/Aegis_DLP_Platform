"""Security-specific tools for Aegis DLP platform."""
import logging
import os
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Any
from .base import BaseTool

# Get database paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHISHING_DB = os.path.join(BASE_DIR, 'phishing_emails.db')


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
        query_type: 'recent' | 'stats' | 'summary'
        """
        logging.info(f"Querying anomaly data: {query_type}")
        
        try:
            # Look for anomaly CSV files
            csv_files = [f for f in os.listdir(BASE_DIR) 
                        if f.startswith('normal_windows_') and f.endswith('.csv')]
            
            if not csv_files:
                return {
                    "status": "no_data",
                    "message": "No anomaly detection logs found. Start monitoring to generate data.",
                    "recommendation": "Go to Anomaly Detection and start network monitoring."
                }
            
            # Get the most recent CSV file
            latest_csv = max(csv_files, key=lambda f: os.path.getctime(os.path.join(BASE_DIR, f)))
            df = pd.read_csv(os.path.join(BASE_DIR, latest_csv))
            
            total_samples = len(df)
            
            # Check if we have prediction data (anomaly column)
            if 'anomaly' in df.columns:
                anomaly_count = df['anomaly'].sum() if df['anomaly'].dtype in ['int64', 'float64'] else 0
                normal_count = total_samples - anomaly_count
            else:
                anomaly_count = 0
                normal_count = total_samples
            
            if query_type == "stats":
                return {
                    "status": "success",
                    "total_samples": total_samples,
                    "normal_count": normal_count,
                    "anomaly_count": anomaly_count,
                    "anomaly_rate": f"{(anomaly_count/total_samples*100):.2f}%" if total_samples > 0 else "0%",
                    "data_file": latest_csv,
                    "last_updated": datetime.fromtimestamp(os.path.getctime(os.path.join(BASE_DIR, latest_csv))).isoformat()
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
    
    async def execute(self, query_type: str = "stats", limit: int = 10) -> Dict[str, Any]:
        """
        Query classification data from the Flask app's global state.
        query_type: 'stats' | 'sensitive' | 'recent' | 'top_confidence'
        """
        logging.info(f"Querying classification data: {query_type}")
        
        try:
            # Import the globals from the Flask app
            # This is a bit of a hack but necessary to access in-memory scan results
            import sys
            if 'app' in sys.modules:
                app_module = sys.modules['app']
                classification_results = getattr(app_module, 'classification_results', [])
                classification_stats = getattr(app_module, 'classification_stats', {})
            else:
                # Try importing directly
                try:
                    from __main__ import classification_results, classification_stats
                except ImportError:
                    classification_results = []
                    classification_stats = {}
            
            if not classification_results:
                return {
                    "status": "no_data",
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
            "features": {
                "anomaly_detection": {
                    "model": "MLP Neural Network",
                    "status": "Active",
                    "description": "Real-time network traffic analysis"
                },
                "data_classification": {
                    "model": "RoBERTa Transformer",
                    "status": "Ready",
                    "description": "Sensitive data detection in files"
                },
                "phishing_detection": {
                    "model": "RoBERTa + YARA",
                    "status": "Active" if os.path.exists(PHISHING_DB) else "Not configured",
                    "description": "Email threat detection"
                },
                "file_encryption": {
                    "model": "AES-256 Fernet",
                    "status": "Active",
                    "description": "Secure file encryption with view-only mode"
                }
            },
            "recommendation": "All security systems operational. Use specific queries for detailed status."
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
