"""
Protocol Analyzer - Specialized module for protocol-specific analysis within the SmolagentGateway.
Provides methods for analyzing network protocols using specialized agents.
"""
from typing import Dict, Any, List, Optional

from src.infrastructure.repositories.yaml_prompt_repository import YamlPromptRepository
from src.use_cases.prompt_service import PromptService


class ProtocolAnalyzer:
    """Analyzer for network protocols using specialized agents from SmolagentGateway."""

    def __init__(self, smolagent_gateway):
        """
        Initialize the Protocol Analyzer.
        
        Args:
            smolagent_gateway: SmolagentGateway instance containing specialized agents
        """
        self.smolagent_gateway = smolagent_gateway
        self.prompt_repository = PromptService(prompt_repository=YamlPromptRepository())

        self.protocol_agents = {
            # Map protocols to their respective agents
            "TCP": self.smolagent_gateway.tcp_agent,
            "UDP": self.smolagent_gateway.udp_agent,
            "ICMP": self.smolagent_gateway.icmp_agent,
            "IP": self.smolagent_gateway.ip_agent,
            "ARP": self.smolagent_gateway.arp_agent,
            "DNS": self.smolagent_gateway.dns_agent,
            "HTTP": self.smolagent_gateway.http_agent,
            "TLS": self.smolagent_gateway.tls_agent,
            "HTTPS": self.smolagent_gateway.http_agent,  # Same agent handles HTTP/HTTPS
            "Ethernet": self.smolagent_gateway.ethernet_agent,
        }

    def analyze_protocol(self, protocol: str, packets: List, analysis_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze packets for a specific protocol using the specialized agent.
        
        Args:
            protocol: Protocol to analyze (e.g., "TCP", "UDP", "DNS")
            packets: List of packet objects to analyze
            analysis_type: Type of analysis to perform (optional)
            
        Returns:
            Dictionary containing analysis results
        """
        # Ensure we"re working with a proper list of packets
        if not packets or not isinstance(packets, list):
            return {
                "analysis": f"Không có dữ liệu gói tin hợp lệ để phân tích giao thức {protocol}.",
                "status": "no_data"
            }

        # Debug logging 
        print(f"DEBUG: Analyzing {protocol} protocol. Total packets: {len(packets)}")
        protocol_types = set(p.protocol for p in packets if hasattr(p, "protocol"))
        print(f"DEBUG: Protocol types in packets: {protocol_types}")

        # Filter packets for the specified protocol
        filtered_packets = [p for p in packets if hasattr(p, "protocol") and p.protocol.upper() == protocol.upper()]

        # Log filtered results
        print(f"DEBUG: Found {len(filtered_packets)} {protocol} packets after filtering")

        if not filtered_packets:
            return {
                "analysis": f"Không tìm thấy gói tin {protocol} trong dữ liệu đã phân tích.",
                "status": "no_data"
            }

        # Get specialized agent for this protocol
        agent = self.protocol_agents.get(protocol.upper())
        if not agent:
            # Use the packet analyzer agent as fallback
            agent = self.smolagent_gateway.packet_analyzer_agent

        # Build prompt based on analysis type
        prompt = self._build_protocol_analysis_prompt(protocol, filtered_packets, analysis_type)

        # Execute analysis with the specialized agent
        try:
            response = agent.run(prompt)
            return {
                "analysis": response,
                "status": "success",
                "packet_count": len(filtered_packets)
            }
        except Exception as e:
            return {
                "analysis": f"Lỗi khi phân tích giao thức {protocol}: {str(e)}",
                "status": "error"
            }

    def analyze_protocol_distribution(self, packets: List) -> Dict[str, Any]:
        """
        Analyze the distribution of protocols in the packet data.

        Args:
            packets: List of packet objects to analyze

        Returns:
            Dictionary containing protocol distribution and analysis
        """
        # Count protocols
        protocol_counts = {}
        for packet in packets:
            if hasattr(packet, "protocol"):
                proto = packet.protocol.upper()
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

        # Generate text analysis of distribution
        total_packets = len(packets)
        distribution_analysis = "## Phân tích phân bố giao thức\n\n"

        if not protocol_counts:
            return {
                "analysis": "Không thể xác định giao thức từ các gói tin.",
                "status": "no_data"
            }

        distribution_analysis += "| Giao thức | Số lượng gói tin | Tỉ lệ |\n"
        distribution_analysis += "|-----------|-----------------|-------|\n"

        for proto, count in sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_packets) * 100
            distribution_analysis += f"| {proto} | {count} | {percentage:.2f}% |\n"

        distribution_analysis += f"\n**Tổng số gói tin:** {total_packets}\n\n"

        # Add basic interpretation
        distribution_analysis += "### Phân tích\n\n"

        # Find dominant protocol
        dominant_proto = max(protocol_counts.items(), key=lambda x: x[1])[0]
        dominant_percentage = (protocol_counts[dominant_proto] / total_packets) * 100

        distribution_analysis += f"- Giao thức chiếm ưu thế là **{dominant_proto}** với {dominant_percentage:.2f}% tổng số gói tin.\n"

        # Comment on the diversity
        if len(protocol_counts) > 5:
            distribution_analysis += "- Lưu lượng mạng đa dạng với nhiều giao thức khác nhau, cho thấy nhiều loại ứng dụng và dịch vụ đang hoạt động.\n"
        elif len(protocol_counts) <= 2:
            distribution_analysis += "- Lưu lượng mạng khá đơn điệu, chỉ tập trung vào một vài giao thức chính.\n"

        return {
            "analysis": distribution_analysis,
            "distribution": protocol_counts,
            "total_packets": total_packets,
            "status": "success"
        }

    def _build_protocol_analysis_prompt(self, protocol: str, packets: List, analysis_type: Optional[str] = None) -> str:
        """
        Build a specialized prompt for protocol analysis.
        
        Args:
            protocol: Protocol to analyze
            packets: Filtered packets for this protocol
            analysis_type: Type of analysis to perform
            
        Returns:
            Specialized prompt for the agent
        """
        # Common header
        prompt = f"""
        Là một chuyên gia phân tích mạng, hãy phân tích chi tiết các gói tin {protocol} trong dữ liệu, 
        tập trung vào cấu trúc gói tin, cách thức hoạt động, và phát hiện các vấn đề hoặc bất thường.
        
        Số lượng gói tin {protocol}: {len(packets)}
        """

        # Add protocol-specific prompts
        if protocol.upper() == "TCP":
            prompt += PromptService.get_formatted_prompt(
                prompt_name="protocol_analysis",
                type_name="tcp_analysis",
                context={"packets": packets},
                self=self.prompt_repository
            )
        elif protocol.upper() == "UDP":
            prompt += PromptService.get_formatted_prompt(
                prompt_name="protocol_analysis",
                type_name="udp_analysis",
                context={"packets": packets},
                self=self.prompt_repository
            )
        elif protocol.upper() == "ICMP":
            prompt += PromptService.get_formatted_prompt(
                prompt_name="protocol_analysis",
                type_name="icmp_analysis",
                context={"packets": packets},
                self=self.prompt_repository
            )
        elif protocol.upper() == "IP":
            prompt += PromptService.get_formatted_prompt(
                prompt_name="protocol_analysis",
                type_name="ip_analysis",
                context={"packets": packets},
                self=self.prompt_repository
            )
        elif protocol.upper() == "ARP":
            prompt += PromptService.get_formatted_prompt(
                prompt_name="protocol_analysis",
                type_name="arp_analysis",
                context={"packets": packets},
                self=self.prompt_repository
            )
        elif protocol.upper() == "DNS":
            prompt += PromptService.get_formatted_prompt(
                prompt_name="protocol_analysis",
                type_name="dns_analysis",
                context={"packets": packets},
                self=self.prompt_repository
            )
        elif protocol.upper() in ["HTTP", "HTTPS"]:
            prompt += PromptService.get_formatted_prompt(
                prompt_name="protocol_analysis",
                type_name="http_analysis",
                context={"packets": packets},
                self=self.prompt_repository
            )
        elif protocol.upper() == "TLS":
            prompt += PromptService.get_formatted_prompt(
                prompt_name="protocol_analysis",
                type_name="tls_analysis",
                context={"packets": packets},
                self=self.prompt_repository
            )
        elif protocol.upper() == "ETHERNET":
            prompt += PromptService.get_formatted_prompt(
                prompt_name="protocol_analysis",
                type_name="ethernet_analysis",
                context={"packets": packets},
                self=self.prompt_repository
            )
        else:
            # Fallback for any unhandled protocols
            prompt += f"""
            Hãy phân tích các khía cạnh sau:
            1. Thống kê chung (số lượng, kích thước, phân bố thời gian)
            2. Các trường header quan trọng và ý nghĩa của chúng
            3. Luồng dữ liệu và mối quan hệ giữa các gói tin
            4. Bất thường hoặc điểm đáng chú ý
            5. Đánh giá hiệu suất và độ tin cậy
            6. Các vấn đề bảo mật tiềm ẩn (nếu có)

            Chi tiết gói tin:
            {packets[:5] if len(packets) > 5 else packets}
            """

        # Add analysis type-specific instructions if provided
        if analysis_type:
            if analysis_type.lower() == "security":
                prompt += "\nTập trung phân tích các khía cạnh bảo mật, phát hiện dấu hiệu tấn công, quét, hoặc hành vi bất thường."
            elif analysis_type.lower() == "performance":
                prompt += "\nTập trung phân tích hiệu suất, độ trễ, tỷ lệ lỗi, và các vấn đề ảnh hưởng đến hiệu quả truyền thông."
            elif analysis_type.lower() == "troubleshooting":
                prompt += "\nTập trung phân tích các lỗi kết nối, vấn đề cấu hình, và đề xuất các giải pháp khắc phục."
            elif analysis_type.lower() == "forensics":
                prompt += "\nTập trung vào điều tra chuyên sâu, dấu vết hoạt động, và tái tạo các sự kiện từ dữ liệu gói tin."

        return prompt
