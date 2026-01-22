"""Security AI Agent for Aegis DLP Platform."""
import logging
import json
import asyncio
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

# Try to import Groq
try:
    from groq import AsyncGroq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False
    logging.warning("groq not installed, AI features disabled")

from .memory import MemoryService
from .tools.search import WebSearchTool
from .tools.security import (
    AnomalyQueryTool,
    PhishingQueryTool,
    ClassificationQueryTool,
    SecuritySummaryTool
)

# Get API key from environment
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

# Singleton agent instance
_agent_instance = None


class SecurityAgent:
    """AI Agent specialized for Aegis DLP security queries."""
    
    def __init__(self):
        if not GROQ_AVAILABLE:
            raise ImportError("groq package not installed. Run: pip install groq")
        
        if not GROQ_API_KEY:
            logging.warning("GROQ_API_KEY not set - AI features will be limited")
        
        self.groq_client = AsyncGroq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None
        self.memory = MemoryService()
        
        # Initialize tools
        self.tools = [
            WebSearchTool(),
            AnomalyQueryTool(),
            PhishingQueryTool(),
            ClassificationQueryTool(),
            SecuritySummaryTool()
        ]
        self.tool_mapping = {tool.name: tool for tool in self.tools}
        
        logging.info("✅ SecurityAgent initialized")
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for the AI agent."""
        return """You are the Aegis DLP Security AI Assistant, an expert in cybersecurity and the Aegis DLP (Data Loss Prevention) platform.

Your role is to:
1. Answer questions about security threats detected by Aegis DLP
2. Explain anomaly detection results from the MLP neural network
3. Provide insights on phishing emails detected by RoBERTa + YARA analysis
4. Help users understand data classification results
5. Assist with file encryption features
6. Answer general security questions

Available tools you can use:
- anomaly_query: Query network anomaly detection logs and MLP predictions
- phishing_query: Search phishing email database for threats
- classification_query: Get data classification scan information
- security_summary: Get overall security status of the platform
- web_search: Search the web for security-related information

**CRITICAL INSTRUCTIONS:**
- ONLY use data provided in 'CURRENT PAGE CONTEXT' or 'Tool Results' sections
- NEVER make up or fabricate data, dates, statistics, or numbers
- If no context or tool results are provided, say "I don't have that data" and guide the user
- Always use the actual values from the provided context, not hypothetical examples

When answering:
- Be concise but informative
- Use bullet points for clarity
- Provide actionable recommendations when relevant
- Reference ONLY the specific data provided to you
- If you don't have data, guide users to the appropriate Aegis DLP feature

Always maintain a professional, helpful tone focused on security."""

    def _get_tool_descriptions(self) -> str:
        """Get formatted tool descriptions for the prompt."""
        descriptions = []
        for tool in self.tools:
            descriptions.append(f"- {tool.name}: {tool.description}")
        return "\n".join(descriptions)

    async def _analyze_query(self, query: str) -> Dict[str, Any]:
        """Analyze query to determine which tools to use."""
        query_lower = query.lower()
        
        tools_to_use = []
        
        # Security-specific keyword matching
        if any(word in query_lower for word in ['anomaly', 'intrusion', 'traffic', 'network', 'mlp', 'suspicious activity']):
            tools_to_use.append(("anomaly_query", {"query_type": "stats"}))
        
        if any(word in query_lower for word in ['phishing', 'email', 'spam', 'threat', 'scam', 'malicious email']):
            if 'search' in query_lower or 'find' in query_lower:
                tools_to_use.append(("phishing_query", {"query_type": "search"}))
            else:
                tools_to_use.append(("phishing_query", {"query_type": "stats"}))
        
        # Enhanced classification query detection
        if any(word in query_lower for word in ['classify', 'classification', 'sensitive', 'pii', 'scan', 'scanned', 'files']):
            # Determine the best query type based on the question
            if any(phrase in query_lower for phrase in ['most sensitive', 'highest confidence', 'top sensitive', 'most confident']):
                tools_to_use.append(("classification_query", {"query_type": "sensitive", "limit": 10}))
            elif any(phrase in query_lower for phrase in ['recent', 'latest', 'just scanned']):
                tools_to_use.append(("classification_query", {"query_type": "recent", "limit": 10}))
            else:
                tools_to_use.append(("classification_query", {"query_type": "stats"}))
        
        # Trigger security summary for status/page/screen queries
        if any(word in query_lower for word in ['status', 'summary', 'overview', 'security status', 'how is', 'what is my', 'seeing', 'see on', 'screen', 'page', 'dashboard']):
            tools_to_use.append(("security_summary", {}))
        
        if any(word in query_lower for word in ['search', 'find online', 'what is', 'explain', 'how to']) and not tools_to_use:
            tools_to_use.append(("web_search", {"query": query}))
        
        return {
            "tools": tools_to_use,
            "is_casual": len(tools_to_use) == 0 and any(word in query_lower for word in ['hi', 'hello', 'hey', 'help', 'thanks', 'bye'])
        }

    async def _execute_tools(self, tools_to_use: List[tuple], user_id: str = "default") -> Dict[str, Any]:
        """Execute tools and collect results."""
        results = {}
        
        for tool_name, params in tools_to_use:
            if tool_name in self.tool_mapping:
                try:
                    tool = self.tool_mapping[tool_name]
                    # Pass user_id to security_summary tool
                    if tool_name == 'security_summary':
                        params['user_id'] = user_id
                    result = await tool.execute(**params)
                    results[tool_name] = result
                except Exception as e:
                    logging.error(f"Tool {tool_name} failed: {e}")
                    results[tool_name] = {"error": str(e)}
        
        return results

    async def _generate_response(self, query: str, tool_results: Dict, conversation_history: List[Dict], is_casual: bool, page_context: Dict = None) -> str:
        """Generate response using Groq LLM."""
        if not self.groq_client:
            return "⚠️ AI features not available. Please set GROQ_API_KEY environment variable."
        
        if page_context is None:
            page_context = {}
        
        # Build messages
        messages = [
            {"role": "system", "content": self._get_system_prompt()}
        ]
        
        # Add page context if available (e.g., email details being viewed)
        if page_context:
            page_type = page_context.get('page_type', '')
            page_context_str = ""
            
            if page_type == 'email_details' and 'email' in page_context:
                email = page_context['email']
                page_context_str = f"""
CURRENT PAGE CONTEXT:
The user is currently viewing an email with the following details:
- Subject: {email.get('subject', 'N/A')}
- Sender: {email.get('sender', 'N/A')}
- Classification: {email.get('category', 'N/A')}
- Confidence Score: {email.get('confidence', 'N/A')}%
- Needs Review: {email.get('needs_review', False)}
- Body Preview: {email.get('body_preview', '')[:200]}

When the user asks about "this email", "this", or refers to the current email, use this information to answer their question.
"""
            
            elif page_type == 'anomaly_detection':
                stats = page_context.get('stats', {})
                page_context_str = f"""
CURRENT PAGE CONTEXT:
The user is on the Anomaly Detection / Intrusion Detection System page.
- Feature: {page_context.get('feature', 'Intrusion Detection System')}
- Model: {page_context.get('model', 'MLP Neural Network')}
- Current Stats:
  - Total Samples: {stats.get('total_samples', 0)}
  - Normal Traffic: {stats.get('normal_count', 0)}
  - Anomalies Detected: {stats.get('anomaly_count', 0)}
  - Monitoring Active: {stats.get('monitoring_active', False)}

When the user asks about "this page", current stats, or monitoring status, use this information.
"""
            
            elif page_type == 'data_classification':
                stats = page_context.get('stats', {})
                page_context_str = f"""
CURRENT PAGE CONTEXT:
The user is on the Data Classification Scanner page.
- Feature: {page_context.get('feature', 'Data Classification Scanner')}
- Model: {page_context.get('model', 'RoBERTa Transformer')}
- Current Scan Stats:
  - Total Files Scanned: {stats.get('total_files', 0)}
  - Sensitive Files: {stats.get('sensitive_count', 0)}
  - Non-Sensitive Files: {stats.get('non_sensitive_count', 0)}
  - Scan Active: {stats.get('scan_active', False)}

When the user asks about scan results or sensitive files, use this information.
"""
            
            elif page_type == 'phishing_detection':
                page_context_str = f"""
CURRENT PAGE CONTEXT:
The user is on the Phishing Detection setup page.
- Feature: {page_context.get('feature', 'Email Phishing Detection')}
- Model: {page_context.get('model', 'RoBERTa + YARA Rules')}
- Description: {page_context.get('description', 'Connect Gmail or Outlook to scan emails')}

This is where users connect their email accounts for phishing scanning.
"""
            
            elif page_type == 'phishing_dashboard':
                stats = page_context.get('stats', {})
                page_context_str = f"""
CURRENT PAGE CONTEXT:
The user is on the Phishing Detection Dashboard.
- Feature: {page_context.get('feature', 'Phishing Detection Dashboard')}
- Model: {page_context.get('model', 'RoBERTa + YARA Rules')}
- Connected Email: {page_context.get('user_email', 'N/A')}
- Current Stats:
  - Total Emails Analyzed: {stats.get('total_emails', 0)}
  - Safe Emails: {stats.get('safe_emails', 0)}
  - Phishing Detected: {stats.get('phishing_detected', 0)}
  - Needs Review: {stats.get('needs_review', 0)}

When the user asks about email threats or phishing stats, use this information.
"""
            
            elif page_type == 'file_encryption':
                page_context_str = f"""
CURRENT PAGE CONTEXT:
The user is on the File Encryption & Decryption page.
- Feature: {page_context.get('feature', 'File Encryption & Decryption')}
- Model: {page_context.get('model', 'AES-256 Fernet Encryption')}
- Description: {page_context.get('description', '')}
- Capabilities: {', '.join(page_context.get('capabilities', []))}

This page allows users to encrypt/decrypt files with password protection and time-based expiry.
"""
            
            if page_context_str:
                messages.append({"role": "system", "content": page_context_str})
        
        # Add conversation history (last 5 turns)
        for msg in conversation_history[-10:]:
            messages.append({
                "role": msg.get("role", "user"),
                "content": msg.get("content", "")
            })
        
        # Add tool results context
        if tool_results:
            context = f"\n\nTool Results:\n```json\n{json.dumps(tool_results, indent=2)}\n```"
            messages.append({
                "role": "system",
                "content": f"Use the following data to answer the user's question:{context}"
            })
        
        # Add user query
        messages.append({"role": "user", "content": query})
        
        try:
            response = await self.groq_client.chat.completions.create(
                model="llama-3.1-8b-instant",  # Fast model for chat
                messages=messages,
                max_tokens=1024,
                temperature=0.7
            )
            return response.choices[0].message.content
        except Exception as e:
            logging.error(f"Groq API error: {e}")
            return f"Sorry, I encountered an error: {str(e)}"

    async def chat(self, user_id: str, query: str, socketio=None, page_context: Dict = None) -> Dict[str, Any]:
        """Process a chat message and return response."""
        start_time = datetime.now()
        
        if page_context is None:
            page_context = {}
        
        # Emit status update
        if socketio:
            socketio.emit('chat_status', {"message": "🔍 Analyzing your query..."}, room=user_id)
        
        # Get conversation history
        history = self.memory.get_conversation_history(user_id)
        
        # Analyze query
        analysis = await self._analyze_query(query)
        
        # Execute tools if needed
        tool_results = {}
        if analysis["tools"]:
            if socketio:
                socketio.emit('chat_status', {"message": "🔧 Gathering security data..."}, room=user_id)
            tool_results = await self._execute_tools(analysis["tools"], user_id)
        
        # Generate response
        if socketio:
            socketio.emit('chat_status', {"message": "🤖 Generating response..."}, room=user_id)
        
        response = await self._generate_response(query, tool_results, history, analysis["is_casual"], page_context)
        
        # Store in memory
        self.memory.add_to_memory(user_id, query, response)
        
        # Calculate processing time
        processing_time = (datetime.now() - start_time).total_seconds()
        
        result = {
            "response": response,
            "tools_used": [t[0] for t in analysis["tools"]],
            "processing_time": round(processing_time, 2)
        }
        
        if socketio:
            socketio.emit('chat_response', result, room=user_id)
        
        return result

    def get_history(self, user_id: str) -> List[Dict]:
        """Get conversation history for user."""
        return self.memory.get_conversation_history(user_id)
    
    def clear_history(self, user_id: str):
        """Clear conversation history."""
        self.memory.clear_history(user_id)


def get_agent() -> Optional[SecurityAgent]:
    """Get or create singleton agent instance."""
    global _agent_instance
    
    if _agent_instance is None:
        try:
            _agent_instance = SecurityAgent()
        except Exception as e:
            logging.error(f"Failed to create SecurityAgent: {e}")
            return None
    
    return _agent_instance
