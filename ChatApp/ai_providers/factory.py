"""
Factory for creating AI chat provider instances (Factory Pattern).
"""
import os
import time
import openai
from groq import Groq
from typing import Optional, Dict, Any

from .base import AIChatProvider
from .openai_chat import OpenAIChatProvider
from .groq_chat import GroqChatProvider
from .gemini_chat import GeminiChatProvider


class AIChatProviderFactory:
    """
    Factory class for creating AI chat provider instances.
    Implements the Factory pattern to abstract provider creation.
    """
    
    @staticmethod
    def create_provider(provider_type: str, config: Optional[Dict[str, Any]] = None) -> AIChatProvider:
        """
        Create an AI chat provider instance based on the specified type.
        
        Args:
            provider_type: Type of provider ("openai", "groq", "gemini")
            config: Optional configuration dictionary with API keys and models
            
        Returns:
            An AIChatProvider instance
            
        Raises:
            ValueError: If the specified provider type is not supported
        """
        config = config or {}
        
        if provider_type.lower() == "groq":
            api_key = config.get("api_key") or os.getenv("GROQ_API_KEY")
            model = config.get("model", "llama3-70b-8192")
            return GroqChatProvider(api_key=api_key, model=model)
            
        elif provider_type.lower() == "openai":
            # Check both key formats (with and without underscore)
            api_key = config.get("api_key") or os.getenv("OPENAI_API_KEY") or os.getenv("OPEN_AI_API_KEY")
            model = config.get("model", "gpt-3.5-turbo")
            return OpenAIChatProvider(api_key=api_key, model=model)
        
        elif provider_type.lower() == "gemini":
            api_key = config.get("api_key") or os.getenv("GEMINI_API_KEY")
            model = config.get("model", "gemini-2.0-flash")  # Updated default model for Gemini free version
            return GeminiChatProvider(api_key=api_key, model=model)
            
        else:
            raise ValueError(f"Unsupported AI provider type: {provider_type}")
    
    @staticmethod
    def get_default_provider() -> AIChatProvider:
        """
        Get the default AI chat provider based on available API keys.
        
        Returns:
            An AIChatProvider instance
            
        Raises:
            ValueError: If no API keys are available
        """
        # Check for Gemini API key first (newest provider)
        if os.getenv("GEMINI_API_KEY"):
            return AIChatProviderFactory.create_provider("gemini")
            
        # Check for Groq API key next
        elif os.getenv("GROQ_API_KEY"):
            return AIChatProviderFactory.create_provider("groq")
        
        # Fall back to OpenAI if available (check both key formats)
        elif os.getenv("OPENAI_API_KEY") or os.getenv("OPEN_AI_API_KEY"):
            return AIChatProviderFactory.create_provider("openai")
        
        # No API keys found
        else:
            raise ValueError("No API keys found for any AI providers.")


class AIChatProvider:
    """Base class for AI chat providers"""
    
    def chat(self, message, history=None):
        """
        Send a message to the AI and get a response
        
        Args:
            message (str): The user message
            history (list): Optional list of previous messages
            
        Returns:
            str: The AI response
        """
        raise NotImplementedError("Subclasses must implement chat method")
    
    def stream_chat(self, message, history=None):
        """
        Stream the chat response word by word
        
        Args:
            message (str): The user message
            history (list): Optional list of previous messages
            
        Yields:
            str: Response chunks as they become available
        """
        try:
            # Default implementation for providers that don't support streaming
            response = self.chat(message, history)
            if not response:
                yield "I couldn't generate a response. Please try again."
                return
                
            # Split by spaces for word-by-word streaming simulation
            words = response.split(' ')
            
            for i, word in enumerate(words):
                yield word + (" " if i < len(words) - 1 else "")
                time.sleep(0.02)  # Faster delay for better user experience
        except Exception as e:
            yield f"Error: {str(e)}"
    
    def get_model_info(self):
        """Get information about the model being used"""
        raise NotImplementedError("Subclasses must implement get_model_info method")


class OpenAIChatProvider(AIChatProvider):
    """Provider for OpenAI's ChatGPT"""
    
    def __init__(self, api_key, model="gpt-3.5-turbo"):
        self.api_key = api_key
        self.model = model
    
    def chat(self, message, history=None):
        """Send a message to OpenAI and get a response"""
        messages = []
        
        # Add history if provided
        if history:
            messages.extend(history)
        
        # Add the current message
        messages.append({"role": "user", "content": message})
        
        # Call OpenAI API
        response = openai.chat.completions.create(
            model=self.model,
            messages=messages
        )
        
        return response.choices[0].message.content
    
    def stream_chat(self, message, history=None):
        """Stream chat completions from OpenAI API"""
        try:
            messages = []
            
            # Add history if provided
            if history:
                messages.extend(history)
            
            # Add the current message
            messages.append({"role": "user", "content": message})
            
            # Call OpenAI with streaming enabled
            stream = openai.chat.completions.create(
                model=self.model,
                messages=messages,
                stream=True
            )
            
            for chunk in stream:
                if chunk.choices and hasattr(chunk.choices[0].delta, 'content') and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
        except Exception as e:
            yield f"OpenAI error: {str(e)}"
    
    def get_model_info(self):
        return {"provider": "OpenAI", "model": self.model}


class GroqChatProvider(AIChatProvider):
    """Provider for Groq's LLM API"""
    
    def __init__(self, api_key, model="llama3-8b-8192"):
        self.client = Groq(api_key=api_key)
        self.model = model
    
    def chat(self, message, history=None):
        """Send a message to Groq and get a response"""
        messages = []
        
        # Add history if provided
        if history:
            messages.extend(history)
        
        # Add the current message
        messages.append({"role": "user", "content": message})
        
        # Call Groq API
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages
        )
        
        return response.choices[0].message.content
    
    def stream_chat(self, message, history=None):
        """Stream chat completions from Groq API"""
        try:
            messages = []
            
            # Add history if provided
            if history:
                messages.extend(history)
            
            # Add the current message
            messages.append({"role": "user", "content": message})
            
            # Call Groq with streaming enabled
            stream = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                stream=True
            )
            
            for chunk in stream:
                if chunk.choices and hasattr(chunk.choices[0].delta, 'content') and chunk.choices[0].delta.content is not None:
                    yield chunk.choices[0].delta.content
        except Exception as e:
            yield f"Groq error: {str(e)}"
    
    def get_model_info(self):
        return {"provider": "Groq", "model": self.model}