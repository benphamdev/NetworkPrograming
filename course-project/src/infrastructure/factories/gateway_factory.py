"""
Factory để tạo các gateway.
"""
from typing import Optional

from src.interfaces.gateways.smolagent_gateway import SmolagentGateway

class GatewayFactory:
    """
    Factory để tạo các gateway.
    """
    
    @staticmethod
    def create_smolagent_gateway(api_key: Optional[str] = None, 
                              prompt_dir: str = "src/infrastructure/prompts") -> SmolagentGateway:
        """
        Tạo đối tượng SmolagentGateway.
        
        Args:
            api_key: API key cho LLM service
            prompt_dir: Đường dẫn đến thư mục chứa file prompt
            
        Returns:
            Đối tượng SmolagentGateway
        """
        return SmolagentGateway(api_key, prompt_dir) 