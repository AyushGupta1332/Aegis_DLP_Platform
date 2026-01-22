"""Memory service for conversation persistence using ChromaDB."""
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any
import os

# Try to import ChromaDB
try:
    import chromadb
    from chromadb.utils import embedding_functions
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    logging.warning("chromadb not installed, memory features disabled")

# Configuration
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHROMA_DB_PATH = os.path.join(BASE_DIR, "databases", "chroma_db")
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# Initialize ChromaDB
chroma_client = None
memory_collection = None

if CHROMADB_AVAILABLE:
    try:
        chroma_client = chromadb.PersistentClient(path=CHROMA_DB_PATH)
        embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=EMBEDDING_MODEL
        )
        memory_collection = chroma_client.get_or_create_collection(
            name="sentinelx_memory",
            embedding_function=embedding_function,
            metadata={"hnsw:space": "cosine"}
        )
        logging.info("✅ ChromaDB initialized for Aegis DLP AI")
    except Exception as e:
        logging.warning(f"ChromaDB initialization failed: {e}")


class MemoryService:
    """Service for managing AI conversation memory."""
    
    def __init__(self):
        self.short_term_memory: Dict[str, List[Dict]] = {}
    
    def add_to_memory(self, user_id: str, query: str, response: str):
        """Add conversation to persistent memory."""
        # Add to short-term memory
        if user_id not in self.short_term_memory:
            self.short_term_memory[user_id] = []
        
        self.short_term_memory[user_id].append({
            "role": "user",
            "content": query,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        self.short_term_memory[user_id].append({
            "role": "assistant", 
            "content": response,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        # Keep only last 20 turns in short-term
        if len(self.short_term_memory[user_id]) > 40:
            self.short_term_memory[user_id] = self.short_term_memory[user_id][-40:]
        
        # Add to ChromaDB for semantic search
        if memory_collection:
            try:
                document = f"User: {query}\nAssistant: {response}"
                doc_id = f"{user_id}-{datetime.now(timezone.utc).timestamp()}"
                memory_collection.add(
                    documents=[document],
                    metadatas=[{"user_id": user_id, "timestamp": datetime.now(timezone.utc).timestamp()}],
                    ids=[doc_id]
                )
            except Exception as e:
                logging.warning(f"Failed to add to ChromaDB: {e}")
    
    def search_memory(self, user_id: str, query: str, n_results: int = 3) -> List[str]:
        """Search past conversations for relevant context."""
        if not memory_collection:
            return []
        
        try:
            results = memory_collection.query(
                query_texts=[query],
                n_results=n_results,
                where={"user_id": user_id}
            )
            return results.get('documents', [[]])[0]
        except Exception as e:
            logging.warning(f"Memory search failed: {e}")
            return []
    
    def get_conversation_history(self, user_id: str, limit: int = 10) -> List[Dict]:
        """Get recent conversation history."""
        history = self.short_term_memory.get(user_id, [])
        return history[-limit*2:] if history else []
    
    def clear_history(self, user_id: str):
        """Clear conversation history for user."""
        if user_id in self.short_term_memory:
            self.short_term_memory[user_id] = []
        
        # Also clear from ChromaDB
        if memory_collection:
            try:
                # Get all IDs for this user
                results = memory_collection.get(
                    where={"user_id": user_id},
                    include=[]
                )
                if results['ids']:
                    memory_collection.delete(ids=results['ids'])
            except Exception as e:
                logging.warning(f"Failed to clear ChromaDB: {e}")


# Activity collection for tracking tool usage
activity_collection = None

if CHROMADB_AVAILABLE and chroma_client:
    try:
        embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=EMBEDDING_MODEL
        )
        activity_collection = chroma_client.get_or_create_collection(
            name="sentinelx_activities",
            embedding_function=embedding_function,
            metadata={"hnsw:space": "cosine"}
        )
        logging.info("✅ Activity tracking collection initialized")
    except Exception as e:
        logging.warning(f"Activity collection initialization failed: {e}")


class ActivityTracker:
    """Service for tracking user security activities and tool usage."""
    
    def __init__(self):
        self.session_activities: Dict[str, List[Dict]] = {}
    
    def log_activity(self, user_id: str, activity_type: str, summary: str, details: Dict = None):
        """
        Log a security activity for a user.
        
        Args:
            user_id: User identifier
            activity_type: Type of activity (anomaly_scan, classification, phishing_scan, encryption)
            summary: Human-readable summary of what happened
            details: Optional dict with specific metrics/results
        """
        if details is None:
            details = {}
        
        timestamp = datetime.now(timezone.utc)
        
        activity = {
            "type": activity_type,
            "summary": summary,
            "details": details,
            "timestamp": timestamp.isoformat(),
            "timestamp_unix": timestamp.timestamp()
        }
        
        # Add to session memory
        if user_id not in self.session_activities:
            self.session_activities[user_id] = []
        
        self.session_activities[user_id].append(activity)
        
        # Keep only last 50 activities in session
        if len(self.session_activities[user_id]) > 50:
            self.session_activities[user_id] = self.session_activities[user_id][-50:]
        
        # Store in ChromaDB for semantic retrieval
        if activity_collection:
            try:
                # Create a rich document for embedding
                document = f"""
Security Activity: {activity_type}
Time: {timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
Summary: {summary}
Details: {str(details) if details else 'None'}
"""
                doc_id = f"activity-{user_id}-{timestamp.timestamp()}"
                
                activity_collection.add(
                    documents=[document],
                    metadatas=[{
                        "user_id": user_id,
                        "activity_type": activity_type,
                        "timestamp": timestamp.timestamp(),
                        "summary": summary
                    }],
                    ids=[doc_id]
                )
                logging.info(f"📝 Activity logged: {activity_type} for user {user_id}")
            except Exception as e:
                logging.warning(f"Failed to log activity to ChromaDB: {e}")
    
    def get_recent_activities(self, user_id: str, limit: int = 10) -> List[Dict]:
        """Get recent activities from session memory."""
        activities = self.session_activities.get(user_id, [])
        return activities[-limit:] if activities else []
    
    def get_activity_summary(self, user_id: str) -> Dict[str, Any]:
        """Get a summary of all user activities for security status report."""
        activities = self.session_activities.get(user_id, [])
        
        if not activities:
            return {
                "has_activities": False,
                "message": "No security activities recorded in this session."
            }
        
        # Count by type
        type_counts = {}
        for activity in activities:
            atype = activity.get('type', 'unknown')
            type_counts[atype] = type_counts.get(atype, 0) + 1
        
        # Get last activity of each type
        last_by_type = {}
        for activity in reversed(activities):
            atype = activity.get('type', 'unknown')
            if atype not in last_by_type:
                last_by_type[atype] = activity
        
        return {
            "has_activities": True,
            "total_activities": len(activities),
            "activity_counts": type_counts,
            "recent_activities": activities[-5:],
            "last_by_type": last_by_type
        }
    
    def search_activities(self, user_id: str, query: str, n_results: int = 5) -> List[Dict]:
        """Search activities using semantic search in ChromaDB."""
        if not activity_collection:
            return []
        
        try:
            results = activity_collection.query(
                query_texts=[query],
                n_results=n_results,
                where={"user_id": user_id}
            )
            
            # Parse results
            activities = []
            if results and results.get('metadatas'):
                for i, metadata in enumerate(results['metadatas'][0]):
                    activities.append({
                        "type": metadata.get('activity_type'),
                        "summary": metadata.get('summary'),
                        "timestamp": metadata.get('timestamp'),
                        "document": results['documents'][0][i] if results.get('documents') else None
                    })
            return activities
        except Exception as e:
            logging.warning(f"Activity search failed: {e}")
            return []
    
    def clear_activities(self, user_id: str):
        """Clear all activities for a user."""
        if user_id in self.session_activities:
            self.session_activities[user_id] = []
        
        if activity_collection:
            try:
                results = activity_collection.get(
                    where={"user_id": user_id},
                    include=[]
                )
                if results['ids']:
                    activity_collection.delete(ids=results['ids'])
            except Exception as e:
                logging.warning(f"Failed to clear activities: {e}")


# Singleton instance
_activity_tracker = None

def get_activity_tracker() -> ActivityTracker:
    """Get or create singleton ActivityTracker instance."""
    global _activity_tracker
    if _activity_tracker is None:
        _activity_tracker = ActivityTracker()
    return _activity_tracker

