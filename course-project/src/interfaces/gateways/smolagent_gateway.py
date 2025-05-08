"""
SmolagentGateway - Interface for integrating with smolagent framework for analysis.
"""
from typing import Dict, Any, List, Optional
import os
import json
import re

from smolagents import CodeAgent, ToolCallingAgent, LiteLLMModel
# Updated import statements to match the actual package structure
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
                "attack_detected": self._extract_attack_detection(response),
                "attack_type": self._extract_attack_type(response),
                "confidence": self._extract_confidence(response),
                "recommendations": self._extract_recommendations(response),
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
    
    def _extract_attack_detection(self, response: str) -> bool:
        """
        Extract attack detection from text response.
        
        This is a simple heuristic - in a real implementation, this would be more sophisticated.
        """
        response_lower = response.lower()
        
        # Look for positive indicators
        positive_indicators = [
            "attack detected", "attack is detected", "attack is occurring",
            "attack is likely", "attack is happening", "attack in progress",
            "malicious activity", "suspicious activity"
        ]
        
        # Look for negative indicators
        negative_indicators = [
            "no attack detected", "not an attack", "normal traffic",
            "benign traffic", "legitimate traffic", "false positive"
        ]
        
        # Check for positive indicators first
        for indicator in positive_indicators:
            if indicator in response_lower:
                return True
        
        # Then check for negative indicators
        for indicator in negative_indicators:
            if indicator in response_lower:
                return False
        
        # Default to False if uncertain
        return False
    
    def _extract_attack_type(self, response: str) -> Optional[str]:
        """
        Extract attack type from text response.
        
        This is a simple heuristic - in a real implementation, this would be more sophisticated.
        """
        response_lower = response.lower()
        
        # Common attack types to look for
        attack_types = {
            "syn flood": "SYN_FLOOD",
            "arp spoof": "ARP_SPOOFING",
            "icmp flood": "ICMP_FLOOD",
            "port scan": "PORT_SCAN",
            "tcp hijack": "TCP_HIJACKING",
            "rst attack": "RST_ATTACK",
            "denial of service": "DOS",
            "ddos": "DDOS"
        }
        
        for key, value in attack_types.items():
            if key in response_lower:
                return value
        
        return None
    
    def _extract_confidence(self, response: str) -> float:
        """
        Extract confidence score from text response.
        
        This is a simple regex approach - in a real implementation, this would be more sophisticated.
        """
        import re
        
        # Look for confidence score patterns
        confidence_patterns = [
            r'confidence[:\s]+(\d+\.?\d*)',
            r'confidence[:\s]+(\d+)%',
            r'confidence[:\s]+(high|medium|low)',
            r'confidence[:\s]+(high|medium|low)',
            r'confidence score[:\s]+(\d+\.?\d*)'
        ]
        
        for pattern in confidence_patterns:
            matches = re.search(pattern, response.lower())
            if matches:
                value = matches.group(1)
                if value.replace('.', '', 1).isdigit():
                    # Numeric confidence
                    confidence = float(value)
                    if confidence > 1 and confidence <= 100:  # Percentage
                        return confidence / 100
                    return min(1.0, max(0.0, confidence))  # Ensure 0-1 range
                else:
                    # Text-based confidence
                    if value == 'high':
                        return 0.9
                    elif value == 'medium':
                        return 0.6
                    elif value == 'low':
                        return 0.3
        
        # Default confidence
        return 0.5
    
    def _extract_recommendations(self, response: str) -> List[str]:
        """
        Extract recommendations from text response.
        
        This is a simple heuristic - in a real implementation, this would be more sophisticated.
        """
        recommendations = []
        lines = response.split('\n')
        
        # Keywords that often indicate recommendations
        recommendation_indicators = [
            "recommend", "suggestion", "advice", "should", "could", "mitigate",
            "prevent", "block", "filter", "implement", "enable", "configure",
            "set up", "install"
        ]
        
        in_recommendation_section = False
        
        for line in lines:
            line = line.strip()
            
            # Check if we're in a recommendation section
            if "recommend" in line.lower() or "mitigat" in line.lower() or "action" in line.lower():
                in_recommendation_section = True
                if ":" in line:
                    recommendations.append(line.split(":", 1)[1].strip())
                continue
            
            # If we're in a recommendation section or the line has recommendation indicators
            if in_recommendation_section or any(indicator in line.lower() for indicator in recommendation_indicators):
                # Check if this is a bullet point or numbered item
                if line.startswith("-") or line.startswith("*") or re.match(r"^\d+\.", line):
                    recommendations.append(line.strip("- *").strip())
        
        return recommendations

    def analyze_osi_layers(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Phân tích lưu lượng mạng theo các tầng của mô hình OSI sử dụng multiagent.
        
        Args:
            results: Dictionary chứa kết quả phân tích gói tin.
        
        Returns:
            Kết quả phân tích theo mô hình OSI.
        """
        # Xây dựng prompt theo mô hình OSI
        prompt = self._build_osi_analysis_prompt(results)
        
        # Truy vấn agent
        response = self.manager_agent.run(prompt)
        
        # Xử lý phản hồi
        try:
            # Cố gắng phân tích JSON nếu có thể
            analyzed_results = json.loads(response)
        except (json.JSONDecodeError, TypeError):
            # Nếu không, sử dụng phản hồi gốc
            analyzed_results = {"analysis": response}
        
        return analyzed_results
    
    def _build_osi_analysis_prompt(self, results: Dict[str, Any]) -> str:
        """
        Xây dựng prompt để phân tích lưu lượng mạng theo mô hình OSI.
        
        Args:
            results: Dictionary chứa kết quả phân tích gói tin.
            
        Returns:
            Prompt string.
        """
        prompt = """
Là một chuyên gia điều tra số trong lĩnh vực mạng (Network Forensics Expert), hãy phân tích chi tiết lưu lượng mạng dưới đây theo mô hình OSI (7 tầng). 
Phân tích sâu về các dấu hiệu bất thường và các vấn đề bảo mật tiềm ẩn ở mỗi tầng.

Dưới đây là dữ liệu lưu lượng mạng cần phân tích:
"""
        
        # Thêm thống kê giao thức nếu có
        if "protocol_statistics" in results:
            proto_stats = results["protocol_statistics"]
            prompt += "\n## Thống kê giao thức:\n"
            for proto, count in proto_stats.items():
                prompt += f"- {proto}: {count} gói tin\n"
        
        # Thêm thống kê luồng nếu có
        if "flow_statistics" in results:
            flow_stats = results["flow_statistics"]
            prompt += "\n## Thống kê luồng:\n"
            for key, value in flow_stats.items():
                prompt += f"- {key}: {value}\n"
        
        # Thêm thông tin tấn công nếu có
        if "attacks" in results:
            attacks = results["attacks"]
            prompt += f"\n## Các cuộc tấn công đã phát hiện ({len(attacks)}):\n"
            for attack in attacks[:5]:  # Giới hạn 5 tấn công để tránh prompt quá dài
                attack_type = attack.get("attack_type", "Unknown")
                severity = attack.get("severity", 0)
                src = attack.get("src_ip", "unknown")
                dst = attack.get("dst_ip", "unknown")
                prompt += f"- {attack_type} (độ nghiêm trọng: {severity}/10): {src} -> {dst}\n"
            
            if len(attacks) > 5:
                prompt += f"- ... và {len(attacks) - 5} tấn công khác\n"
        
        # Thêm hướng dẫn phân tích theo mô hình OSI
        prompt += """
\nHãy phân tích dữ liệu trên theo 7 tầng của mô hình OSI như sau:

1. Tầng Vật lý (Physical Layer):
   - Phân tích các vấn đề liên quan đến phương tiện truyền dẫn, tín hiệu.

2. Tầng Liên kết dữ liệu (Data Link Layer):
   - Phân tích frame, ARP, MAC, các vấn đề về chuyển mạch.
   - Xác định dấu hiệu tấn công như ARP spoofing, MAC flooding.

3. Tầng Mạng (Network Layer):
   - Phân tích gói tin IP, định tuyến, phân mảnh.
   - Xác định dấu hiệu tấn công như IP spoofing, ICMP flood.

4. Tầng Giao vận (Transport Layer):
   - Phân tích kết nối TCP/UDP, port.
   - Xác định dấu hiệu tấn công như SYN flood, port scanning.

5. Tầng Phiên (Session Layer):
   - Phân tích phiên làm việc, các giao thức phiên.
   - Xác định dấu hiệu tấn công như session hijacking.

6. Tầng Trình diễn (Presentation Layer):
   - Phân tích mã hóa, nén, chuẩn hóa dữ liệu.
   - Xác định dấu hiệu tấn công như SSL exploitation.

7. Tầng Ứng dụng (Application Layer):
   - Phân tích giao thức ứng dụng (HTTP, DNS, FTP...).
   - Xác định dấu hiệu tấn công như DDoS, injection attacks.

Cho mỗi tầng, hãy:
1. Mô tả chi tiết các phát hiện chính
2. Xác định các dấu hiệu bất thường và mức độ nghiêm trọng (thấp/trung bình/cao)
3. Cung cấp các khuyến nghị bảo mật cụ thể
4. Liên kết các phát hiện với các kỹ thuật tấn công đã biết (nếu có)

Định dạng phân tích theo Markdown, với các đề mục rõ ràng và phân cấp phù hợp. Tập trung vào phân tích chuyên sâu nhưng ngắn gọn.
"""
        
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