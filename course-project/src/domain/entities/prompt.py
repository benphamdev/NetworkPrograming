"""
Module chứa các lớp entity liên quan đến prompt.
"""
from dataclasses import dataclass
from typing import Dict, Any, Optional


@dataclass
class Prompt:
    """
    Entity đại diện cho một prompt.
    """
    name: str
    content: str
    variables: Dict[str, Any]
    description: Optional[str] = None
    version: Optional[str] = None
    
    def format(self, context: Dict[str, Any]) -> str:
        """
        Format prompt với context được cung cấp.
        
        Args:
            context: Dictionary chứa các biến cần thay thế trong prompt
            
        Returns:
            Prompt đã được format
        """
        formatted_content = self.content
        
        # Thay thế biến trong context
        if "{{context}}" in formatted_content:
            formatted_content = formatted_content.replace("{{context}}", str(context.get("context", "")))
            
        # Thay thế các biến khác
        for key, value in context.items():
            placeholder = f"{{{{{key}}}}}"
            if placeholder in formatted_content:
                formatted_content = formatted_content.replace(placeholder, str(value))
                
        return formatted_content 