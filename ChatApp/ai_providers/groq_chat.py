"""
Groq API implementation for AI Chat Provider.
"""
import os
from typing import Dict, Any, List, Optional

# Import the Groq client with proper error handling
try:
    import groq
except ImportError:
    raise ImportError("Groq Python package not installed. Install with 'pip install groq'")

from .base import AIChatProvider


class GroqChatProvider(AIChatProvider):
    """
    Implementation of AIChatProvider using Groq's API.
    """
    
    def __init__(self, api_key: Optional[str] = None, model: str = "llama3-70b-8192"):
        """
        Initialize the Groq provider.
        
        Args:
            api_key: Groq API key (will use env var GROQ_API_KEY if not provided)
            model: Model name to use (default: llama3-70b-8192)
        """
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        if not self.api_key:
            raise ValueError("Groq API key not found. Set GROQ_API_KEY environment variable or pass api_key parameter.")
        
        self.model = model
        self.client = groq.Client(api_key=self.api_key)
        
    def chat(self, message: str, history: List[Dict[str, str]]) -> str:
        """
        Generate a chat response using Groq's API.
        
        Args:
            message: The user's message
            history: Previous messages in the conversation
            
        Returns:
            The text response from the AI model
        """
        try:
            # Convert the chat history to the format expected by Groq
            messages = [{"role": "system", "content": "You are a helpful assistant."}]
            
            # Add conversation history
            for msg in history:
                messages.append({"role": msg["role"], "content": msg["content"]})
            
            # Add the current user message
            messages.append({"role": "user", "content": message})
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=1000,
                temperature=0.7
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            print(f"Error calling Groq API: {str(e)}")
            return f"Error: {str(e)}"
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the Groq model being used.
        
        Returns:
            Dictionary with model information
        """
        return {
            "provider": "Groq",
            "model": self.model,
            "capabilities": [
                "chat",
                "text generation"
            ]
        }