"""
OpenAI API implementation for AI Provider.
"""
import os
import json
from typing import Dict, Any, List, Optional

# Import the OpenAI client
try:
    from openai import OpenAI
except ImportError:
    raise ImportError("OpenAI Python package not installed. Install with 'pip install openai'")

from .base import AIProvider


class OpenAIProvider(AIProvider):
    """
    Implementation of AIProvider using OpenAI's API.
    """
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-3.5-turbo"):
        """
        Initialize the OpenAI provider.
        
        Args:
            api_key: OpenAI API key (will use env var OPEN_AI_API_KEY if not provided)
            model: Model name to use (default: gpt-3.5-turbo)
        """
        self.api_key = api_key or os.getenv("OPEN_AI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key not found. Set OPEN_AI_API_KEY environment variable or pass api_key parameter.")
        
        self.model = model
        self.client = OpenAI(api_key=self.api_key)
        
    def analyze_text(self, prompt: str, max_tokens: int = 1000, temperature: float = 0.7) -> str:
        """
        Analyze text using OpenAI's API.
        
        Args:
            prompt: The text prompt to analyze
            max_tokens: Maximum tokens in the response
            temperature: Temperature parameter for response randomness
            
        Returns:
            The text response from the AI model
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a network security analyst assistant."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_tokens,
                temperature=temperature
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            print(f"Error calling OpenAI API: {str(e)}")
            return f"Error: {str(e)}"
    
    def generate_structured_analysis(self, 
                             data: Dict[str, Any], 
                             analysis_type: str,
                             instructions: str) -> Dict[str, Any]:
        """
        Generate structured analysis of network data using OpenAI.
        
        Args:
            data: Dictionary of data to analyze
            analysis_type: Type of analysis to perform
            instructions: Specific instructions for the analysis
            
        Returns:
            Dictionary containing the structured analysis results
        """
        # Convert data to a formatted string representation
        data_str = json.dumps(data, indent=2)
        
        prompt = f"""
        Analysis type: {analysis_type}
        
        Instructions: {instructions}
        
        Data to analyze:
        ```
        {data_str}
        ```
        
        Provide a structured analysis in valid JSON format. Include sections for 'findings', 'risks', and 'recommendations'.
        """
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a network security analyst assistant that responds in JSON format."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=2000,
                temperature=0.3  # Lower temperature for more deterministic results
            )
            
            result_text = response.choices[0].message.content
            
            # Extract JSON from the response
            try:
                # Try to find JSON in the response if it's wrapped in markdown code blocks
                if "```json" in result_text:
                    json_part = result_text.split("```json")[1].split("```")[0].strip()
                elif "```" in result_text:
                    json_part = result_text.split("```")[1].split("```")[0].strip()
                else:
                    json_part = result_text.strip()
                
                return json.loads(json_part)
                
            except json.JSONDecodeError:
                return {
                    "error": "Failed to parse JSON response",
                    "raw_response": result_text
                }
                
        except Exception as e:
            print(f"Error generating structured analysis: {str(e)}")
            return {
                "error": str(e),
                "status": "failed"
            }
    
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
                "text generation",
                "network analysis",
                "security assessment"
            ]
        }
