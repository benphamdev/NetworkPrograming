"""
SmolagentGateway - Interface for integrating with smolagent framework for analysis.
"""
from typing import Dict, Any, Optional
import os
import json

from src.interfaces.gateways.response_extractor import ResponseExtractor
from src.interfaces.gateways.osi_analyzer import OSILayerAnalyzer
from smolagents import CodeAgent, ToolCallingAgent, LiteLLMModel
from dotenv import load_dotenv

from smolagents import (
    CodeAgent,
    ToolCallingAgent,
    DuckDuckGoSearchTool,
    VisitWebpageTool,
    LiteLLMModel,
)

class SmolagentGateway:
    """Gateway for interfacing with smolagent framework."""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the smolagent gateway.
        
        Args:
            api_key: API key for the LLM service. If None, will try to load from environment.
        """
        # Load environment variables
        load_dotenv()
        
        # Get API key from environment if not provided
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        if not self.api_key:
            raise ValueError("API key must be provided or set in DEEPSEEK_API_KEY environment variable")
        
        # Initialize LLM model
        self.model = self._initialize_model()
        
        # Initialize search agent with corrected tool classes
        self.search_agent = ToolCallingAgent(
            tools=[DuckDuckGoSearchTool(), VisitWebpageTool()],
            model=self.model,
            name="search_agent",
            description="This is an agent that can do web search."
        )
        
        # Initialize manager agent
        self.manager_agent = CodeAgent(
            tools=[],
            model=self.model,
            managed_agents=[self.search_agent],
            name="analyst_agent",
            description="This is an agent that analyzes network traffic patterns."
        )
        
        # Initialize helper classes
        self.response_extractor = ResponseExtractor()
        self.osi_analyzer = OSILayerAnalyzer(self.manager_agent)
    
    def _initialize_model(self) -> LiteLLMModel:
        """Initialize the LLM model."""
        return LiteLLMModel(
            model_id="deepseek/deepseek-chat",
            api_key=self.api_key,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a network security analyst capable of analyzing network traffic patterns. "
                        "You specialize in detecting and explaining network attacks like SYN floods, "
                        "port scans, ARP spoofing, and other anomalies. "
                        "When given network statistics, analyze them to identify potential security issues "
                        "and provide actionable recommendations."
                    )
                }
            ],
            temperature=0.1,
            max_tokens=1024,
            top_p=0.9,
            top_k=50,
            frequency_penalty=0.0,
            presence_penalty=0.0,
            stream=False,
            request_timeout=60
        )
    
    def analyze_traffic_pattern(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze traffic patterns using smolagent.
        
        Args:
            stats: Dictionary of traffic statistics.
        
        Returns:
            Analysis results from the agent.
        """
        # Convert stats to a prompt
        prompt = self._build_analysis_prompt(stats)
        
        # Query the agent
        response = self.manager_agent.run(prompt)
        
        # Parse the response (this would be more structured in a real implementation)
        try:
            # Try to parse as JSON if possible
            results = json.loads(response)
        except (json.JSONDecodeError, TypeError):
            # Otherwise, use the raw response
            results = {"analysis": response}
        
        return results
    
    def analyze_attack_indicators(self, indicators: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze potential attack indicators using smolagent.
        
        Args:
            indicators: Dictionary of attack indicators.
        
        Returns:
            Assessment of attack indicators.
        """
        # Convert indicators to a prompt
        prompt = self._build_attack_prompt(indicators)
        
        # Query the agent
        response = self.manager_agent.run(prompt)
        
        # Process the response
        try:
            results = json.loads(response)
        except (json.JSONDecodeError, TypeError):
            results = {
                "attack_detected": self.response_extractor.extract_attack_detection(response),
                "attack_type": self.response_extractor.extract_attack_type(response),
                "confidence": self.response_extractor.extract_confidence(response),
                "recommendations": self.response_extractor.extract_recommendations(response),
                "analysis": response
            }
        
        return results
    
    def _build_analysis_prompt(self, stats: Dict[str, Any]) -> str:
        """
        Build a prompt for traffic pattern analysis.
        
        Args:
            stats: Dictionary of traffic statistics.
            
        Returns:
            Analysis prompt string.
        """
        prompt = "Analyze the following network traffic statistics for potential security issues:\n\n"
        
        # Add flow statistics
        if "flow_statistics" in stats:
            flow_stats = stats["flow_statistics"]
            prompt += "Flow Statistics:\n"
            for key, value in flow_stats.items():
                prompt += f"- {key}: {value}\n"
        
        # Add protocol statistics if available
        if "protocol_statistics" in stats:
            proto_stats = stats["protocol_statistics"]
            prompt += "\nProtocol Statistics:\n"
            for proto, count in proto_stats.items():
                prompt += f"- {proto}: {count} packets\n"
        
        # Add packet counts if available
        if "packet_counts" in stats:
            packet_counts = stats["packet_counts"]
            prompt += "\nPacket Counts:\n"
            for packet_type, count in packet_counts.items():
                prompt += f"- {packet_type}: {count}\n"
        
        # Request specific analysis points
        prompt += "\nPlease analyze this traffic data and provide:\n"
        prompt += "1. An assessment of whether the traffic patterns look normal or suspicious\n"
        prompt += "2. Identification of any potential security issues\n"
        prompt += "3. Recommendations for mitigating any identified issues\n"
        prompt += "4. A confidence score (0-1) for your assessment\n"
        
        return prompt
    
    def _build_attack_prompt(self, indicators: Dict[str, Any]) -> str:
        """
        Build a prompt for attack indicator analysis.
        
        Args:
            indicators: Dictionary of attack indicators.
            
        Returns:
            Attack analysis prompt string.
        """
        prompt = "Analyze the following network attack indicators:\n\n"
        
        # Add general indicators
        prompt += "Traffic Indicators:\n"
        for key, value in indicators.items():
            if key not in ["tcp_flags", "arp_mapping", "icmp_stats"]:
                prompt += f"- {key}: {value}\n"
        
        # Add TCP flag information if available
        if "tcp_flags" in indicators:
            tcp_flags = indicators["tcp_flags"]
            prompt += "\nTCP Flag Distribution:\n"
            for flag, count in tcp_flags.items():
                prompt += f"- {flag}: {count}\n"
        
        # Add ARP mapping information if available
        if "arp_mapping" in indicators:
            arp_mapping = indicators["arp_mapping"]
            prompt += "\nARP IP-MAC Mappings:\n"
            for ip, mac_list in arp_mapping.items():
                if len(mac_list) > 1:
                    prompt += f"- {ip} has multiple MACs: {', '.join(mac_list)}\n"
        
        # Add ICMP statistics if available
        if "icmp_stats" in indicators:
            icmp_stats = indicators["icmp_stats"]
            prompt += "\nICMP Statistics:\n"
            for key, value in icmp_stats.items():
                prompt += f"- {key}: {value}\n"
        
        # Request specific analysis points
        prompt += "\nBased on these indicators, please provide:\n"
        prompt += "1. A determination of whether an attack is likely occurring (yes/no/maybe)\n"
        prompt += "2. The type of attack if one is detected\n"
        prompt += "3. A confidence score (0-1) for your detection\n"
        prompt += "4. Specific recommendations for addressing the attack\n"
        prompt += "5. A detailed explanation of your reasoning\n"
        
        return prompt
    
    def direct_query(self, query: str) -> str:
        """
        Xử lý trực tiếp câu hỏi từ người dùng khi không liên quan đến phân tích mạng.
        
        Args:
            query: Câu hỏi của người dùng
            
        Returns:
            Câu trả lời trực tiếp từ model
        """
        try:
            # Gọi trực tiếp đến manager_agent với câu hỏi của người dùng
            response = self.manager_agent.run(query)
            return response
        except Exception as e:
            return f"Xin lỗi, tôi không thể xử lý câu hỏi của bạn lúc này. Lỗi: {str(e)}"
    
    def analyze_osi_layers(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Phân tích lưu lượng mạng theo các tầng của mô hình OSI sử dụng multiagent.
        
        Args:
            results: Dictionary chứa kết quả phân tích gói tin.
        
        Returns:
            Kết quả phân tích theo mô hình OSI.
        """
        return self.osi_analyzer.analyze(results)