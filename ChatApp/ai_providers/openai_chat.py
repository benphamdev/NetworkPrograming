"""
OpenAI API implementation for AI Chat Provider.
"""
import os
from typing import Dict, Any, List, Optional

# Import the OpenAI client
try:
    from openai import OpenAI
except ImportError:
    raise ImportError("OpenAI Python package not installed. Install with 'pip install openai'")

from .base import AIChatProvider


class OpenAIChatProvider(AIChatProvider):
    """
    Implementation of AIChatProvider using OpenAI's API.
    """
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-3.5-turbo"):
        """
        Initialize the OpenAI provider.
        
        Args:
            api_key: OpenAI API key (will use env var OPENAI_API_KEY if not provided)
            model: Model name to use (default: gpt-3.5-turbo)
        """
        # Check both key formats (with and without underscore)
        self.api_key = api_key or os.getenv("OPENAI_API_KEY") or os.getenv("OPEN_AI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key not found. Set OPEN_AI_API_KEY in .env file or pass api_key parameter.")
        
        self.model = model
        self.client = OpenAI(api_key=self.api_key)
        
    def chat(self, message: str, history: List[Dict[str, str]]) -> str:
        """
        Generate a chat response using OpenAI's API.
        
        Args:
            message: The user's message
            history: Previous messages in the conversation
            
        Returns:
            The text response from the AI model
        """
        try:
            # Convert the chat history to the format expected by OpenAI
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
            print(f"Error calling OpenAI API: {str(e)}")
            return f"Error: {str(e)}"
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the OpenAI model being used.
        
        Returns:
            Dictionary with model information
        """
        return {
            "provider": "OpenAI",
            "model": self.model,
            "capabilities": [
                "chat",
                "text generation"
            ]
        }