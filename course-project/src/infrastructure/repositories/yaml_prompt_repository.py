"""
Module chứa triển khai repository để đọc prompt từ file YAML.
"""
import os
from typing import Dict, List, Optional, Any

import yaml

from src.domain.entities.prompt import Prompt
from src.domain.repositories.prompt_repository import PromptRepository


class YamlPromptRepository(PromptRepository):
    """
    Triển khai PromptRepository để đọc prompt từ file YAML.
    """
    
    def __init__(self, prompt_dir: str = "src/infrastructure/prompts"):
        """
        Khởi tạo repository.
        
        Args:
            prompt_dir: Đường dẫn đến thư mục chứa file prompt
        """
        self.prompt_dir = prompt_dir
        self.prompt_cache = {}
        self.config = self._load_config()
        
    def get_prompt(self, prompt_name: str, type_name: Optional[str] = None) -> Prompt:
        """
        Lấy prompt theo tên.
        
        Args:
            prompt_name: Tên của file prompt (không bao gồm phần mở rộng .yaml)
            type_name: Tên loại prompt trong file (ví dụ: 'tcp_analysis' trong file protocol_analysis.yaml)
            
        Returns:
            Đối tượng Prompt
            
        Raises:
            ValueError: Nếu không tìm thấy prompt
        """
        # Kiểm tra trong cache
        cache_key = f"{prompt_name}:{type_name if type_name else 'default'}"
        if cache_key in self.prompt_cache:
            return self.prompt_cache[cache_key]
        
        # Tải file YAML
        file_path = os.path.join(self.prompt_dir, f"{prompt_name}.yaml")
        if not os.path.exists(file_path):
            raise ValueError(f"Không tìm thấy file prompt: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as file:
            prompt_data = yaml.safe_load(file)
        
        # Lấy nội dung prompt
        if type_name and type_name in prompt_data:
            content = prompt_data[type_name]
        elif "prompt" in prompt_data:
            content = prompt_data["prompt"]
        else:
            # Tìm khóa đầu tiên có giá trị là string
            for key, value in prompt_data.items():
                if isinstance(value, str):
                    content = value
                    break
            else:
                raise ValueError(f"Không tìm thấy prompt trong file: {file_path}")
        
        # Tạo đối tượng Prompt
        prompt = Prompt(
            name=prompt_data.get("name", prompt_name),
            content=content,
            variables=prompt_data.get("variables", {}),
            description=prompt_data.get("description", ""),
            version=prompt_data.get("version", "1.0")
        )
        
        # Lưu vào cache
        self.prompt_cache[cache_key] = prompt
        
        return prompt
    
    def get_prompt_config(self) -> Dict:
        """
        Lấy cấu hình chung cho prompt.
        
        Returns:
            Dictionary chứa cấu hình
        """
        return self.config
    
    def list_prompts(self) -> List[str]:
        """
        Liệt kê tất cả các prompt có sẵn.
        
        Returns:
            Danh sách tên các prompt
        """
        prompt_files = []
        for file_name in os.listdir(self.prompt_dir):
            if file_name.endswith(".yaml") and file_name != "config.yaml":
                prompt_files.append(file_name[:-5])  # Loại bỏ phần mở rộng .yaml
        return prompt_files
    
    def _load_config(self) -> Dict[str, Any]:
        """
        Tải cấu hình từ file config.yaml.
        
        Returns:
            Dictionary chứa cấu hình
        """
        config_path = os.path.join(self.prompt_dir, "config.yaml")
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as file:
                return yaml.safe_load(file)
        return {} 