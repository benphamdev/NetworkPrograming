"""
SmolagentGateway - Interface for integrating with smolagent framework for analysis.
It provides methods to analyze network traffic patterns and attack indicators using a multi-agent architecture.
"""
from typing import Dict, Any, Optional
import os
import json

from src.interfaces.gateways.response_extractor import ResponseExtractor
from src.interfaces.gateways.osi_analyzer import OSILayerAnalyzer
from dotenv import load_dotenv

from smolagents import (
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
        
        # Initialize các agent chuyên biệt
        self._initialize_agents()
        
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
                        "Bạn là một kỹ sư mạng (Network Engineer) chuyên nghiệp với kinh nghiệm phân tích gói tin và điều tra lỗi mạng. "
                        "Nhiệm vụ của bạn là: "
                        "\n1. Phát hiện rủi ro bảo mật tiềm ẩn mà hacker có thể khai thác trong mạng "
                        "\n2. Phân tích gói tin để debug các vấn đề kết nối như thiết bị không ping được nhau "
                        "\n3. Xác định chính xác nguyên nhân gốc rễ của vấn đề (định tuyến, tường lửa, DNS, ARP, v.v.) "
                        "\n4. Đề xuất các biện pháp khắc phục cụ thể cho từng loại lỗi "
                        "\n5. Phân tích lưu lượng mạng theo thời gian thực để tìm các bất thường "
                        "\n\nKhi phân tích, hãy tập trung vào: "
                        "\n- Kiểm tra lỗi ở từng tầng trong mô hình OSI (vật lý, liên kết, mạng, giao vận...) "
                        "\n- Phân tích các giao thức quan trọng (ICMP, ARP, TCP/IP, UDP, DNS) "
                        "\n- Xác định chính xác các dấu hiệu tấn công (port scan, ARP spoofing, DDoS, brute force) "
                        "\n- Đưa ra quy trình debug có hệ thống và các lệnh đề xuất "
                        "\n\nHiển thị kết quả một cách rõ ràng, súc tích, và thực tế, giúp network engineer dễ dàng hiểu vấn đề và áp dụng giải pháp."
                    )
                }
            ],
            temperature=0.1,
            max_tokens=2048,
            top_p=0.9,
            top_k=50,
            frequency_penalty=0.0,
            presence_penalty=0.0,
            stream=False,
            request_timeout=120
        )

    def _initialize_agents(self):
        """Khởi tạo các agent chuyên biệt cho phân tích mạng."""
        # Search agent
        self.search_agent = ToolCallingAgent(
            tools=[DuckDuckGoSearchTool(), VisitWebpageTool()],
            model=self.model,
            name="search_agent",
            description="This agent performs web searches to get up-to-date information about network protocols and vulnerabilities."
        )
        
        # Packet analyzer agent
        self.packet_analyzer_agent = ToolCallingAgent(
            tools=[],
            model=self.model,
            name="packet_analyzer_agent",
            description="This agent specializes in detailed packet inspection, analyzing protocol headers, flags, and payload data to identify anomalies."
        )
        
        # TCP agent
        self.tcp_agent = ToolCallingAgent(
            tools=[],
            model=self.model,
            name="tcp_agent",
            description="This agent specializes in TCP protocol analysis, focusing on handshake analysis, flags, sequence numbers, and potential TCP-specific attacks."
        )
        
        # ARP agent
        self.arp_agent = ToolCallingAgent(
            tools=[],
            model=self.model,
            name="arp_agent",
            description="This agent specializes in ARP protocol analysis, focusing on ARP spoofing detection, MAC-IP mapping conflicts, and ARP cache poisoning."
        )
        
        # ICMP agent
        self.icmp_agent = ToolCallingAgent(
            tools=[],
            model=self.model,
            name="icmp_agent",
            description="This agent specializes in ICMP protocol analysis, focusing on unusual echo patterns, tunnel detection, and ICMP flooding."
        )
        
        # Attack detection agent
        self.attack_agent = ToolCallingAgent(
            tools=[],
            model=self.model,
            name="attack_agent",
            description="This agent specializes in correlating evidence from multiple sources to identify attack patterns and provide threat intelligence."
        )
        
        # Manager agent - giám sát và điều phối các agent khác
        self.manager_agent = ToolCallingAgent(
            tools=[],
            model=self.model,
            name="analyst_agent",
            description="This is the main coordinator that analyzes network traffic patterns and synthesizes findings."
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
        
        # Add TCP flag information if available
        if "tcp_flags" in stats:
            tcp_flags = stats["tcp_flags"]
            prompt += "\nTCP Flag Distribution:\n"
            for flag, count in tcp_flags.items():
                prompt += f"- {flag}: {count} packets\n"
            
            # Calculate and add TCP flag ratios
            total_flags = sum(tcp_flags.values())
            if total_flags > 0:
                prompt += "\nTCP Flag Ratios:\n"
                for flag, count in tcp_flags.items():
                    percentage = (count / total_flags) * 100
                    prompt += f"- {flag}: {percentage:.2f}%\n"
        
        # Add connection issues if available
        if "connection_issues" in stats:
            conn_issues = stats["connection_issues"]
            prompt += "\nConnection Issues:\n"
            for issue_type, details in conn_issues.items():
                prompt += f"- {issue_type}: {details['count']} connections\n"
                if "examples" in details and details["examples"]:
                    prompt += "  Examples:\n"
                    for example in details["examples"][:3]:  # Limit to 3 examples
                        prompt += f"  * {example}\n"
        
        # Request specific analysis points
        prompt += "\nPlease analyze this traffic data and provide:\n"
        prompt += "1. An assessment of whether the traffic patterns look normal or suspicious\n"
        prompt += "2. Identification of any potential security issues\n"
        prompt += "3. Analysis of TCP flags and what they might indicate (e.g., RST flags suggesting firewall blocks)\n"
        prompt += "4. Potential scenarios that could explain the observed patterns\n"
        prompt += "5. Recommendations for mitigating any identified issues\n"
        prompt += "6. A confidence score (0-1) for your assessment\n"
        
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
            if key not in ["tcp_flags", "arp_mapping", "icmp_stats", "connection_issues", "ip_fragmentation"]:
                prompt += f"- {key}: {value}\n"
        
        # Add TCP flag information if available
        if "tcp_flags" in indicators:
            tcp_flags = indicators["tcp_flags"]
            prompt += "\nTCP Flag Distribution:\n"
            for flag, count in tcp_flags.items():
                prompt += f"- {flag}: {count}\n"
            
            # Calculate and add TCP flag ratios
            total_flags = sum(tcp_flags.values())
            if total_flags > 0:
                prompt += "\nTCP Flag Ratios:\n"
                for flag, count in tcp_flags.items():
                    percentage = (count / total_flags) * 100
                    prompt += f"- {flag}: {percentage:.2f}%\n"
        
        # Add ARP mapping information if available
        if "arp_mapping" in indicators:
            arp_mapping = indicators["arp_mapping"]
            prompt += "\nARP IP-MAC Mappings:\n"
            for ip, mac_list in arp_mapping.items():
                if len(mac_list) > 1:
                    prompt += f"- {ip} has multiple MACs: {', '.join(mac_list)}\n"
                else:
                    prompt += f"- {ip}: {mac_list[0]}\n"
        
        # Add ICMP statistics if available
        if "icmp_stats" in indicators:
            icmp_stats = indicators["icmp_stats"]
            prompt += "\nICMP Statistics:\n"
            for key, value in icmp_stats.items():
                prompt += f"- {key}: {value}\n"
        
        # Add IP fragmentation information if available
        if "ip_fragmentation" in indicators:
            ip_frag = indicators["ip_fragmentation"]
            prompt += "\nIP Fragmentation:\n"
            for key, value in ip_frag.items():
                prompt += f"- {key}: {value}\n"
        
        # Add connection issues if available
        if "connection_issues" in indicators:
            conn_issues = indicators["connection_issues"]
            prompt += "\nConnection Issues:\n"
            for issue_type, details in conn_issues.items():
                prompt += f"- {issue_type}: {details['count']} connections\n"
                if "examples" in details and details["examples"]:
                    prompt += "  Examples:\n"
                    for example in details["examples"][:3]:  # Limit to 3 examples
                        prompt += f"  * {example}\n"
        
        # Request specific analysis points
        prompt += "\nBased on these indicators, please provide:\n"
        prompt += "1. A determination of whether an attack is likely occurring (yes/no/maybe)\n"
        prompt += "2. The type of attack if one is detected\n"
        prompt += "3. Potential network issues that could explain the patterns (e.g., firewall blocks, router issues)\n"
        prompt += "4. Analysis of TCP flags and what they indicate about the traffic\n"
        prompt += "5. A confidence score (0-1) for your detection\n"
        prompt += "6. Specific recommendations for addressing the attack or network issues\n"
        prompt += "7. A detailed explanation of your reasoning\n"
        
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