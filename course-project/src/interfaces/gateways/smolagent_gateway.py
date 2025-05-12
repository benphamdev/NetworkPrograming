"""
SmolagentGateway - Interface for integrating with smolagent framework for analysis.
It provides methods to analyze network traffic patterns and attack indicators using a multi-agent architecture.
"""
import json
import os
from typing import Dict, Any, Optional, List

from dotenv import load_dotenv
from smolagents import (
    ToolCallingAgent,
    DuckDuckGoSearchTool,
    VisitWebpageTool,
    LiteLLMModel,
)

from src.infrastructure.repositories.yaml_prompt_repository import YamlPromptRepository
from src.interfaces.gateways.osi_analyzer import OSILayerAnalyzer
from src.interfaces.gateways.response_extractor import ResponseExtractor
from src.use_cases.prompt_service import PromptService


class SmolagentGateway:
    """Gateway for interfacing with smolagent framework."""

    def __init__(self, api_key: Optional[str] = None, prompt_dir: str = "src/infrastructure/prompts"):
        """
        Initialize the smolagent gateway.
        
        Args:
            api_key: API key for the LLM service. If None, will try to load from environment.
            prompt_dir: Đường dẫn đến thư mục chứa file prompt
        """
        # Load environment variables
        load_dotenv()

        # Get API key from environment if not provided
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        if not self.api_key:
            raise ValueError("API key must be provided or set in DEEPSEEK_API_KEY environment variable")

        # Khởi tạo PromptService
        prompt_repository = YamlPromptRepository(prompt_dir)
        self.prompt_service = PromptService(prompt_repository)

        # Initialize LLM model
        self.model = self._initialize_model()

        # Initialize các agent chuyên biệt
        self._initialize_agents()

        # Initialize helper classes
        self.response_extractor = ResponseExtractor()
        self.osi_analyzer = OSILayerAnalyzer(self.manager_agent)

    def _initialize_model(self) -> LiteLLMModel:
        """Initialize the LLM model."""
        # Lấy cấu hình từ prompt service
        system_config = self.prompt_service.get_system_config()
        temperature = system_config.get("temperature", 0.1)
        max_tokens = system_config.get("max_tokens", 2048)
        model_name = system_config.get("model", "deepseek/deepseek-chat")
        top_p = system_config.get("top_p", 0.9)
        top_k = system_config.get("top_k", 50)
        frequency_penalty = system_config.get("frequency_penalty", 0.0)
        presence_penalty = system_config.get("presence_penalty", 0.0)
        stream = system_config.get("stream", False)
        request_timeout = system_config.get("request_timeout", 120)

        return LiteLLMModel(
            model_id=model_name,
            api_key=self.api_key,
            messages=[
                {
                    "role": "system",
                    "content": self.prompt_service.get_formatted_prompt(
                        "network_engineer_prompt",
                        {},
                        "system_prompt"
                    )
                }
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            top_p=top_p,
            top_k=top_k,
            frequency_penalty=frequency_penalty,
            presence_penalty=presence_penalty,
            stream=stream,
            request_timeout=request_timeout
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

    def _format_stats_to_context(self, stats: Dict[str, Any]) -> str:
        """
        Format traffic statistics to context string for prompt.
        
        Args:
            stats: Dictionary of traffic statistics.
            
        Returns:
            Formatted context string.
        """
        context = "Thống kê lưu lượng mạng:\n\n"

        # Add flow statistics
        if "flow_statistics" in stats:
            flow_stats = stats["flow_statistics"]
            context += "Thống kê luồng:\n"
            for key, value in flow_stats.items():
                context += f"- {key}: {value}\n"

        # Add protocol statistics if available
        if "protocol_statistics" in stats:
            proto_stats = stats["protocol_statistics"]
            context += "\nThống kê giao thức:\n"
            for proto, count in proto_stats.items():
                context += f"- {proto}: {count} gói tin\n"

        # Add packet counts if available
        if "packet_counts" in stats:
            packet_counts = stats["packet_counts"]
            context += "\nSố lượng gói tin:\n"
            for packet_type, count in packet_counts.items():
                context += f"- {packet_type}: {count}\n"

        # Add TCP flag distribution if available
        if "tcp_flags" in stats:
            tcp_flags = stats["tcp_flags"]
            context += "\nPhân bố cờ TCP:\n"
            for flag, count in tcp_flags.items():
                context += f"- {flag}: {count} gói tin\n"

        # Add TCP flag ratios if available
        if "tcp_flag_ratios" in stats:
            tcp_ratios = stats["tcp_flag_ratios"]
            context += "\nTỷ lệ cờ TCP:\n"
            for flag, percentage in tcp_ratios.items():
                context += f"- {flag}: {percentage:.2f}%\n"

        # Add connection issues if available
        if "connection_issues" in stats:
            issues = stats["connection_issues"]
            context += "\nVấn đề kết nối:\n"
            for issue_type, details in issues.items():
                context += f"- {issue_type}: {details['count']} kết nối\n"
                if "examples" in details and details["examples"]:
                    context += "  Ví dụ:\n"
                    for example in details["examples"][:3]:  # Limit to 3 examples
                        context += f"  * {example}\n"

        # Request specific analysis points
        context += "\nPlease analyze this traffic data and provide:\n"
        context += "1. An assessment of whether the traffic patterns look normal or suspicious\n"
        context += "2. Identification of any potential security issues\n"
        context += "3. Analysis of TCP flags and what they might indicate (e.g., RST flags suggesting firewall blocks)\n"
        context += "4. Potential scenarios that could explain the observed patterns\n"
        context += "5. Recommendations for mitigating any identified issues\n"
        context += "6. A confidence score (0-1) for your assessment\n"
        return context

    def _format_indicators_to_context(self, indicators: Dict[str, Any]) -> str:
        """
        Format attack indicators to context string for prompt.
        
        Args:
            indicators: Dictionary of attack indicators.
            
        Returns:
            Formatted context string.
        """
        context = "Chỉ số tấn công mạng:\n\n"

        # Add traffic indicators if they exist specifically
        if "traffic_indicators" in indicators:
            traffic_indicators = indicators["traffic_indicators"]
            context += "Chỉ số lưu lượng:\n"
            for key, value in traffic_indicators.items():
                context += f"- {key}: {value}\n"
        # Otherwise add generic indicators that are not specific categories
        else:
            context += "Chỉ số lưu lượng:\n"
            for key, value in indicators.items():
                if key not in ["tcp_flags", "arp_mapping", "icmp_stats", "connection_issues", "ip_fragmentation"]:
                    context += f"- {key}: {value}\n"

        # Add TCP flag distribution if available
        if "tcp_flags" in indicators:
            tcp_flags = indicators["tcp_flags"]
            context += "\nPhân bố cờ TCP:\n"
            for flag, count in tcp_flags.items():
                context += f"- {flag}: {count}\n"

        # Add TCP flag ratios if available
        if "tcp_flag_ratios" in indicators:
            tcp_ratios = indicators["tcp_flag_ratios"]
            context += "\nTỷ lệ cờ TCP:\n"
            for flag, percentage in tcp_ratios.items():
                context += f"- {flag}: {percentage:.2f}%\n"
        else:
            # Calculate ratios if they weren't provided but tcp_flags is available
            if "tcp_flags" in indicators:
                tcp_flags = indicators["tcp_flags"]
                total_flags = sum(tcp_flags.values())
                if total_flags > 0:
                    context += "\nTỷ lệ cờ TCP:\n"
                    for flag, count in tcp_flags.items():
                        percentage = (count / total_flags) * 100
                        context += f"- {flag}: {percentage:.2f}%\n"

        # Add ARP mappings if available
        if "arp_mapping" in indicators:
            arp_mappings = indicators["arp_mapping"]
            context += "\nÁnh xạ ARP IP-MAC:\n"
            for ip, mac_list in arp_mappings.items():
                if len(mac_list) > 1:
                    context += f"- {ip} có nhiều MAC: {', '.join(mac_list)}\n"
                else:
                    context += f"- {ip}: {mac_list[0]}\n"

        # Add ICMP statistics if available
        if "icmp_stats" in indicators:
            icmp_stats = indicators["icmp_stats"]
            context += "\nThống kê ICMP:\n"
            for key, value in icmp_stats.items():
                context += f"- {key}: {value}\n"

        # Add IP fragmentation if available
        if "ip_fragmentation" in indicators:
            ip_frag = indicators["ip_fragmentation"]
            context += "\nPhân mảnh IP:\n"
            for key, value in ip_frag.items():
                context += f"- {key}: {value}\n"

        # Add connection issues if available
        if "connection_issues" in indicators:
            issues = indicators["connection_issues"]
            context += "\nVấn đề kết nối:\n"
            for issue_type, details in issues.items():
                context += f"- {issue_type}: {details['count']} kết nối\n"
                if "examples" in details and details["examples"]:
                    context += "  Ví dụ:\n"
                    for example in details["examples"][:3]:  # Limit to 3 examples
                        context += f"  * {example}\n"

        return context

    def _build_analysis_prompt(self, stats: Dict[str, Any]) -> str:
        """
        Build a prompt for traffic pattern analysis.
        
        Args:
            stats: Dictionary of traffic statistics.
            
        Returns:
            Analysis prompt string.
        """
        # Sử dụng prompt từ file YAML
        return self.prompt_service.get_formatted_prompt(
            "raw_packet_analysis",
            {"context": self._format_stats_to_context(stats)},
            "traffic_pattern_analysis"
        )

    def _build_attack_prompt(self, indicators: Dict[str, Any]) -> str:
        """
        Build a prompt for attack indicator analysis.
        
        Args:
            indicators: Dictionary of attack indicators.
            
        Returns:
            Attack analysis prompt string.
        """
        # Sử dụng prompt từ file YAML
        return self.prompt_service.get_formatted_prompt(
            "raw_packet_analysis",
            {"context": self._format_indicators_to_context(indicators)},
            "attack_analysis"
        )

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

    def analyze_raw_packets(self, packets: List, custom_prompt: str = None) -> Dict[str, Any]:
        """
        Phân tích trực tiếp danh sách gói tin thô thay vì sử dụng kết quả phân tích.
        
        Args:
            packets: Danh sách các gói tin thô cần phân tích
            custom_prompt: Prompt tùy chỉnh để hướng dẫn AI phân tích. Nếu None, sẽ dùng prompt mặc định
            
        Returns:
            Kết quả phân tích từ AI
        """
        if not packets:
            return {"analysis": "Không có gói tin nào để phân tích."}

        # Xây dựng prompt từ raw packets
        prompt = self._build_raw_packets_prompt(packets, custom_prompt)

        # Gọi manager_agent để phân tích
        try:
            response = self.manager_agent.run(prompt)

            # Xử lý phản hồi
            try:
                # Thử phân tích JSON nếu có thể
                result = json.loads(response)
            except (json.JSONDecodeError, TypeError):
                # Nếu không, sử dụng phản hồi dạng văn bản
                result = {"analysis": response}

            return result
        except Exception as e:
            return {"analysis": f"Lỗi khi phân tích gói tin: {str(e)}"}

    def _build_raw_packets_prompt(self, packets: List, custom_prompt: str = None) -> str:
        """
        Xây dựng prompt từ danh sách gói tin thô.
        
        Args:
            packets: Danh sách các gói tin thô
            custom_prompt: Prompt tùy chỉnh của người dùng
            
        Returns:
            Prompt để gửi đến LLM
        """
        # Tạo thông tin gói tin theo định dạng hiện tại
        formatted_info = self._format_packets_info(packets)

        if custom_prompt:
            # Nếu có prompt tùy chỉnh, sử dụng nó với thông tin gói tin
            return custom_prompt + "\n\n" + formatted_info
        else:
            # Sử dụng prompt từ file YAML
            return self.prompt_service.get_formatted_prompt(
                "raw_packet_analysis",
                {"context": formatted_info}
            )

    def _format_packets_info(self, packets: List) -> str:
        """
        Định dạng thông tin gói tin theo cách hiện tại.
        
        Args:
            packets: Danh sách các gói tin
            
        Returns:
            Chuỗi thông tin được định dạng
        """
        # Nếu không có gói tin, trả về thông báo trống
        if not packets:
            return "Không có gói tin nào để phân tích."

        # Định dạng thông tin theo định dạng hiện tại
        base_prompt = ""

        # Thêm thông tin tổng quan về các gói tin
        base_prompt += f"## Tổng quan\n"
        base_prompt += f"- Tổng số gói tin: {len(packets)}\n"

        # Phân loại gói tin theo giao thức
        protocols = {}
        for packet in packets:
            proto = getattr(packet, 'protocol', 'Unknown')
            protocols[proto] = protocols.get(proto, 0) + 1

        base_prompt += "\n## Phân bố giao thức\n"
        for proto, count in protocols.items():
            base_prompt += f"- {proto}: {count} gói tin\n"

        # Thêm thông tin chi tiết về một số gói tin (giới hạn để tránh prompt quá dài)
        base_prompt += "\n## Chi tiết các gói tin mẫu\n"
        sample_count = min(20, len(packets))  # Tăng số lượng gói tin mẫu lên 20

        for i, packet in enumerate(packets[:sample_count]):
            base_prompt += f"\n### Gói tin #{i + 1}\n"

            # Thông tin cơ bản về gói
            for attr in ['protocol', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'timestamp', 'length']:
                if hasattr(packet, attr):
                    base_prompt += f"- {attr}: {getattr(packet, attr)}\n"

            # Thông tin chi tiết cho từng loại gói
            if hasattr(packet, 'protocol'):
                if packet.protocol == 'TCP':
                    # Thông tin TCP flags
                    if hasattr(packet, 'flags'):
                        base_prompt += f"- TCP flags: {packet.flags}\n"
                    # TCP sequence và ack number
                    for attr in ['seq_num', 'ack_num', 'window_size']:
                        if hasattr(packet, attr):
                            base_prompt += f"- {attr}: {getattr(packet, attr)}\n"
                    # Thử truy cập các phương thức cụ thể nếu có
                    for method in ['is_syn', 'is_ack', 'is_rst', 'is_fin', 'is_psh', 'is_urg']:
                        if hasattr(packet, method) and callable(getattr(packet, method)):
                            base_prompt += f"- {method}: {getattr(packet, method)()}\n"

                elif packet.protocol == 'ICMP':
                    # Thông tin ICMP
                    for attr in ['icmp_type', 'icmp_code', 'icmp_id', 'icmp_seq']:
                        if hasattr(packet, attr):
                            base_prompt += f"- {attr}: {getattr(packet, attr)}\n"
                    # Thử truy cập các phương thức cụ thể
                    for method in ['is_echo_request', 'is_echo_reply', 'is_unreachable', 'is_redirect']:
                        if hasattr(packet, method) and callable(getattr(packet, method)):
                            base_prompt += f"- {method}: {getattr(packet, method)()}\n"

                elif packet.protocol == 'ARP':
                    # Thông tin ARP
                    for attr in ['src_mac', 'dst_mac', 'sender_ip', 'sender_mac', 'target_ip', 'target_mac',
                                 'operation']:
                        if hasattr(packet, attr):
                            base_prompt += f"- {attr}: {getattr(packet, attr)}\n"
                    # Thử phương thức
                    for method in ['is_request', 'is_reply', 'is_announcement']:
                        if hasattr(packet, method) and callable(getattr(packet, method)):
                            base_prompt += f"- {method}: {getattr(packet, method)()}\n"

                elif packet.protocol == 'UDP':
                    # Thông tin UDP
                    for attr in ['length', 'checksum', 'payload_length']:
                        if hasattr(packet, attr):
                            base_prompt += f"- {attr}: {getattr(packet, attr)}\n"

                elif packet.protocol == 'DNS':
                    # Thông tin DNS
                    for attr in ['query_name', 'query_type', 'answer', 'response_code']:
                        if hasattr(packet, attr):
                            base_prompt += f"- {attr}: {getattr(packet, attr)}\n"
                    # Thử phương thức
                    for method in ['is_query', 'is_response', 'has_answers']:
                        if hasattr(packet, method) and callable(getattr(packet, method)):
                            base_prompt += f"- {method}: {getattr(packet, method)()}\n"

                elif packet.protocol == 'DHCP':
                    # Thông tin DHCP
                    for attr in ['message_type', 'client_mac', 'requested_ip', 'client_ip', 'server_ip']:
                        if hasattr(packet, attr):
                            base_prompt += f"- {attr}: {getattr(packet, attr)}\n"

        if len(packets) > sample_count:
            base_prompt += f"\n*...và {len(packets) - sample_count} gói tin khác...*\n"

        # Yêu cầu cụ thê hơn về phân tích

        base_prompt += "\n## Yêu cầu phân tích chi tiết\n"
        base_prompt += "Dựa trên các gói tin trên, hãy phân tích:\n"
        base_prompt += "1. Các vấn đề kết nối mạng hiện tại hoặc tiềm ẩn\n"
        base_prompt += "2. Dấu hiệu cụ thể của các cuộc tấn công nếu có\n"
        base_prompt += "3. Phân tích theo mô hình OSI - xác định vấn đề ở từng tầng\n"
        base_prompt += "4. Đánh giá tỷ lệ các gói tin TCP reset, retransmission và failed connections\n"
        base_prompt += "5. Phân tích timeout hoặc latency bất thường\n"
        base_prompt += "6. Đề xuất giải pháp và các lệnh debug cụ thể\n"
        base_prompt += "7. Kết luận về nguyên nhân gốc rễ của vấn đề\n"

        return base_prompt

    def analyze_osi_raw_packets(self, packets: List, custom_prompt: str = None) -> Dict[str, Any]:
        """
        Phân tích danh sách gói tin thô theo mô hình OSI.
        
        Args:
            packets: Danh sách các gói tin thô cần phân tích
            custom_prompt: Prompt tùy chỉnh. Nếu None, sẽ dùng prompt mặc định
            
        Returns:
            Kết quả phân tích theo mô hình OSI
        """
        if not packets:
            return {"analysis": "Không có gói tin nào để phân tích theo mô hình OSI."}

        # Sử dụng osi_analyzer để phân tích
        return self.osi_analyzer.analyze_raw_packets(packets, custom_prompt)
