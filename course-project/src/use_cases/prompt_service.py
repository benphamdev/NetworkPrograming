"""
Module chứa service để sử dụng prompt.
"""
from typing import Dict, Any, Optional

from src.domain.repositories.prompt_repository import PromptRepository


class PromptService:
    """
    Service để sử dụng prompt.
    """
    
    def __init__(self, prompt_repository: PromptRepository):
        """
        Khởi tạo service.
        
        Args:
            prompt_repository: Repository để đọc prompt
        """
        self.prompt_repository = prompt_repository
    
    def get_formatted_prompt(self, prompt_name: str, context: Dict[str, Any], 
                            type_name: Optional[str] = None) -> str:
        """
        Lấy prompt đã được format với context.
        
        Args:
            prompt_name: Tên của prompt
            context: Dictionary chứa các biến cần thay thế trong prompt
            type_name: Tên loại prompt trong file (ví dụ: 'tcp_analysis' trong file protocol_analysis.yaml)
            
        Returns:
            Prompt đã được format
        """
        prompt = self.prompt_repository.get_prompt(prompt_name, type_name)
        return prompt.format(context)
    
    def get_prompt_config(self) -> Dict[str, Any]:
        """
        Lấy cấu hình chung cho prompt.
        
        Returns:
            Dictionary chứa cấu hình
        """
        return self.prompt_repository.get_prompt_config()
    
    def get_system_config(self) -> Dict[str, Any]:
        """
        Lấy cấu hình hệ thống cho prompt.
        
        Returns:
            Dictionary chứa cấu hình hệ thống
        """
        config = self.prompt_repository.get_prompt_config()
        return config.get("system", {}) 