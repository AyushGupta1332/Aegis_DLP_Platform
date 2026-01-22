"""Web search tool using DuckDuckGo."""
import logging
from typing import List, Dict
import warnings
warnings.filterwarnings("ignore", category=RuntimeWarning, module="duckduckgo_search")

try:
    from duckduckgo_search import DDGS
    SEARCH_AVAILABLE = True
except ImportError:
    SEARCH_AVAILABLE = False
    logging.warning("duckduckgo-search not installed, web search disabled")

from .base import BaseTool

class WebSearchTool(BaseTool):
    """Tool for web search using DuckDuckGo."""
    
    def __init__(self):
        super().__init__(
            name="web_search",
            description="Search the web for information on any topic."
        )
    
    async def execute(self, query: str, num_results: int = 5) -> List[Dict[str, str]]:
        """Execute web search."""
        if not SEARCH_AVAILABLE:
            return [{"error": "Web search not available - duckduckgo-search not installed"}]
        
        logging.info(f"Executing web search for: {query}")
        try:
            with DDGS() as ddgs:
                results = [r for r in ddgs.text(
                    query,
                    max_results=num_results,
                    region='us-en',
                    safesearch='moderate'
                )]
                
                formatted_results = []
                for result in results:
                    formatted_results.append({
                        "title": result.get('title', ''),
                        "snippet": result.get('body', ''),
                        "url": result.get('href', '')
                    })
                
                return formatted_results if formatted_results else [{"error": "No results found"}]
        except Exception as e:
            logging.error(f"Web search error: {e}")
            return [{"error": str(e)}]
