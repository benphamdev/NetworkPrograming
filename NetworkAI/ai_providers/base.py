"""
Base classes for AI provider implementations using the Strategy Pattern.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional


class AIProvider(ABC):
    """
    Abstract base class for AI providers (Strategy Pattern).
    Each concrete implementation handles API calls to a specific LLM provider.
    """
    
    @abstractmethod
    def analyze_text(self, prompt: str, max_tokens: int = 1000, temperature: float = 0.7) -> str:
        """
        Analyze text using the AI provider's API.
        
        Args:
            prompt: The text prompt to analyze
            max_tokens: Maximum tokens in the response
            temperature: Temperature parameter for response randomness
            
        Returns:
            The text response from the AI model
        """
        pass
    
    @abstractmethod
    def generate_structured_analysis(self, 
                             data: Dict[str, Any], 
                             analysis_type: str,
                             instructions: str) -> Dict[str, Any]:
        """
        Generate structured analysis of network data.
        
        Args:
            data: Dictionary of data to analyze
            analysis_type: Type of analysis to perform (e.g., "security", "performance")
            instructions: Specific instructions for the analysis
            
        Returns:
            Dictionary containing the structured analysis results
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
