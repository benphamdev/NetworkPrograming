"""
Factory for creating AI provider instances (Factory Pattern).
"""
import os
from typing import Optional, Dict, Any

from .base import AIProvider
from .openai_provider import OpenAIProvider
from .groq_provider import GroqProvider


class AIProviderFactory:
    """
    Factory class for creating AI provider instances.
    Implements the Factory pattern to abstract provider creation.
    """
    
    @staticmethod
    def create_provider(provider_type: str, config: Optional[Dict[str, Any]] = None) -> AIProvider:
        """
        Create an AI provider instance based on the specified type.
        
        Args:
            provider_type: Type of provider ("openai", "groq")
            config: Optional configuration dictionary with API keys and models
            
        Returns:
            An AIProvider instance
            
        Raises:
            ValueError: If the specified provider type is not supported
        """
        config = config or {}
        
        if provider_type.lower() == "groq":
            api_key = config.get("api_key") or os.getenv("GROQ_API_KEY")
            model = config.get("model", "llama3-70b-8192")
            return GroqProvider(api_key=api_key, model=model)
            
        elif provider_type.lower() == "openai":
            api_key = config.get("api_key") or os.getenv("OPEN_AI_API_KEY")
            model = config.get("model", "gpt-3.5-turbo")
            return OpenAIProvider(api_key=api_key, model=model)
            
        else:
            raise ValueError(f"Unsupported AI provider type: {provider_type}")
    
    @staticmethod
    def get_default_provider() -> AIProvider:
        """
        Get the default AI provider based on available API keys.
        
        Returns:
            An AIProvider instance
            
        Raises:
            ValueError: If no API keys are available
        """
        # Check for Groq API key first
        if os.getenv("GROQ_API_KEY"):
            return AIProviderFactory.create_provider("groq")
        
        # Fall back to OpenAI if available
        elif os.getenv("OPEN_AI_API_KEY"):
            return AIProviderFactory.create_provider("openai")
        
        # No API keys found
        else:
            raise ValueError("No API keys found for any AI providers.")
