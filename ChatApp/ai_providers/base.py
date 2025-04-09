"""
Base class for AI chat providers using the Strategy Pattern.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional


class AIChatProvider(ABC):
    """
    Abstract base class for AI chat providers (Strategy Pattern).
    Each concrete implementation handles API calls to a specific LLM provider.
    """
    
    @abstractmethod
    def chat(self, message: str, history: List[Dict[str, str]]) -> str:
        """
        Generate a chat response using the AI provider's API.
        
        Args:
            message: The user's message
            history: Previous messages in the conversation
            
        Returns:
            The text response from the AI model
        """
        pass
    
    @abstractmethod
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the AI model being used.
        
        Returns:
            Dictionary with model information
        """
        pass