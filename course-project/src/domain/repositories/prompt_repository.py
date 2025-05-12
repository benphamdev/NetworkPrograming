"""
Module chứa interface cho prompt repository.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from src.domain.entities.prompt import Prompt


class PromptRepository(ABC):
    """
    Interface cho prompt repository.
    """
    
    @abstractmethod
    def get_prompt(self, prompt_name: str, type_name: Optional[str] = None) -> Prompt:
        """
        Lấy prompt theo tên.
        
        Args:
            prompt_name: Tên của file prompt
            type_name: Tên loại prompt trong file (ví dụ: 'tcp_analysis' trong file protocol_analysis.yaml)
            
        Returns:
            Đối tượng Prompt
            
        Raises:
            ValueError: Nếu không tìm thấy prompt
        """
        pass
    
    @abstractmethod
    def get_prompt_config(self) -> Dict:
        """
        Lấy cấu hình chung cho prompt.
        
        Returns:
            Dictionary chứa cấu hình
        """
        pass
    
    @abstractmethod
    def list_prompts(self) -> List[str]:
        """
        Liệt kê tất cả các prompt có sẵn.
        
        Returns:
            Danh sách tên các prompt
        """
        pass 