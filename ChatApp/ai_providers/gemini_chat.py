"""
Google Gemini API implementation for AI Chat Provider.
"""
import os
from typing import Dict, Any, List, Optional, Generator

# Import the Google Generative AI library with proper error handling
try:
    import google.generativeai as genai
except ImportError:
    raise ImportError("Google Generative AI package not installed. Install with 'pip install google-generativeai'")

from .base import AIChatProvider


class GeminiChatProvider(AIChatProvider):
    """
    Implementation of AIChatProvider using Google's Gemini API.
    """
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-2.0-flash"):
        """
        Initialize the Gemini provider.
        
        Args:
            api_key: Gemini API key (will use env var GEMINI_API_KEY if not provided)
            model: Model name to use (default: gemini-2.0-flash)
        """
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("Gemini API key not found. Set GEMINI_API_KEY environment variable or pass api_key parameter.")
        
        self.model = model
        
        # Map friendly model names to API model identifiers for free version only
        model_mapping = {
            "Gemini 2.0 Flash-Lite": "gemini-2.0-flash"
            # Removed "Gemini Pro" and "Gemini 1.5 Pro" for free version
        }
        
        # Get the API model identifier or use the provided model name as-is
        api_model = model_mapping.get(model, model)
        
        # Configure the Gemini API
        genai.configure(api_key=self.api_key)
        
        # Initialize the model with the correct API identifier
        self.gemini_model = genai.GenerativeModel(api_model)
        
    def chat(self, message: str, history: List[Dict[str, str]]) -> str:
        """
        Generate a chat response using Google's Gemini API.
        
        Args:
            message: The user's message
            history: Previous messages in the conversation
            
        Returns:
            The text response from the AI model
        """
        try:
            # Start a chat session
            chat_session = self.gemini_model.start_chat(history=self._convert_history_to_gemini_format(history))
            
            # Generate response
            response = chat_session.send_message(message)
            
            return response.text
            
        except Exception as e:
            print(f"Error calling Gemini API: {str(e)}")
            return f"Error: {str(e)}"
    
    def stream_chat(self, message: str, history: List[Dict[str, str]]) -> Generator[str, None, None]:
        """
        Stream a chat response from Gemini API.
        
        Args:
            message: The user's message
            history: Previous messages in the conversation
            
        Yields:
            Chunks of the response as they become available
        """
        try:
            # Start a chat session
            chat_session = self.gemini_model.start_chat(history=self._convert_history_to_gemini_format(history))
            
            # Generate streaming response
            response = chat_session.send_message(message, stream=True)
            
            # Yield chunks as they come
            for chunk in response:
                if chunk.text:
                    yield chunk.text
        except Exception as e:
            print(f"Error calling Gemini API: {str(e)}")
            yield f"Error: {str(e)}"
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the Gemini model being used.
        
        Returns:
            Dictionary with model information
        """
        return {
            "provider": "Google Gemini",
            "model": self.model,
            "capabilities": [
                "chat",
                "text generation",
                "reasoning"
            ]
        }
    
    def _convert_history_to_gemini_format(self, history: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Convert the standard chat history format to Gemini's format.
        
        Args:
            history: List of message dictionaries with 'role' and 'content'
            
        Returns:
            List of messages in Gemini's expected format
        """
        gemini_history = []
        
        if not history:
            return gemini_history
            
        for msg in history:
            role = "user" if msg["role"] == "user" else "model"
            gemini_history.append({
                "role": role,
                "parts": [{"text": msg["content"]}]
            })
        
        return gemini_history
