"""
SmolagentGateway - Interface for integrating with smolagent framework for analysis.
It provides methods to analyze network traffic patterns and attack indicators using a multi-agent architecture.
"""
from typing import Dict, Any, Optional, List
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
                        "Bạn là một kỹ sư mạng (Network Engineer) chuyên nghiệp với kinh nghiệm phân tích gói tin và điều tra sự cố mạng. "
                        "\n\n## Nhiệm vụ chính của bạn:"
                        "\n1. Debug vấn đề kết nối mạng - phân tích tại sao các thiết bị không ping được đến nhau hoặc không thể truy cập dịch vụ"
                        "\n2. Xác định chính xác nguyên nhân của sự cố (vấn đề ở Router, Switch, Firewall, DNS, v.v.)"
                        "\n3. Phát hiện dấu hiệu tấn công mạng thông qua phân tích mẫu lưu lượng và hành vi bất thường"
                        "\n4. Thực hiện phân tích sâu theo mô hình OSI để xác định các vấn đề ở từng tầng"
                        "\n5. Đề xuất hướng khắc phục và phòng ngừa chính xác cho từng loại vấn đề"
                        
                        "\n\n## Các loại tấn công cần phân tích:"
                        "\n- ARP: Spoofing, Poisoning, Man-in-the-Middle"
                        "\n- DHCP: Spoofing, Starvation, DOS, Rogue DHCP Server"
                        "\n- DNS: Cache Poisoning, Tunneling, Spoofing, Amplification"
                        "\n- ICMP: Ping Flooding, Tunneling, Smurf Attack"
                        "\n- TCP/IP: SYN Flood, RST Attack, Session Hijacking, Port Scanning"
                        "\n- DDoS: Reflection/Amplification, Slowloris, HTTP Flooding"
                        "\n- Reconnaissance: Passive, Active, Port Scanning, OS Fingerprinting"
                        
                        "\n\n## Phương pháp phân tích:"
                        "\n1. Kiểm tra theo mô hình OSI từ tầng thấp đến cao"
                        "\n   - Tầng vật lý: Lỗi cáp, port, tín hiệu"
                        "\n   - Tầng liên kết dữ liệu: Xung đột MAC, ARP poisoning, VLAN issues"
                        "\n   - Tầng mạng: IP routing, ICMP, fragmentation, TTL issues"
                        "\n   - Tầng giao vận: TCP handshake, RST packets, port availability"
                        "\n   - Tầng ứng dụng: DNS resolution, HTTP errors, TLS issues"
                        "\n2. Phân tích cờ TCP (SYN, ACK, RST, FIN, PSH, URG) để xác định tình trạng kết nối"
                        "\n3. Kiểm tra thời gian phản hồi (RTT) và timeout patterns"
                        "\n4. Phân tích thay đổi bất thường trong ARP cache"
                        "\n5. Xác định luồng dữ liệu bất thường hoặc asymmetric routing"
                        
                        "\n\n## Khi đưa ra phân tích:"
                        "\n- Đề xuất các lệnh debug và công cụ phù hợp (tcpdump, Wireshark, netstat, ping, traceroute, v.v.)"
                        "\n- Cung cấp quy trình kiểm tra có hệ thống và có thể thực hiện được"
                        "\n- Mô tả chính xác về dấu hiệu của từng loại tấn công hoặc vấn đề"
                        "\n- Đề xuất giải pháp ngắn hạn và dài hạn"
                        "\n- Đánh giá mức độ nghiêm trọng và tác động tiềm tàng"
                        
                        "\nHiển thị kết quả một cách rõ ràng, súc tích, và thực tế, tập trung vào nguyên nhân gốc rễ và các giải pháp để network engineer có thể áp dụng ngay lập tức."
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
        if custom_prompt:
            base_prompt = custom_prompt
        else:
            base_prompt = """
            Là kỹ sư mạng (Network Engineer) chuyên nghiệp, hãy phân tích chi tiết các gói tin dưới đây:

            ## Yêu cầu phân tích:
            1. Phân tích tình trạng kết nối mạng và xác định các vấn đề tiềm ẩn:
               - Xác định thiết bị nào không ping được đến nhau hoặc không thể truy cập dịch vụ
               - Phân tích lỗi ở các thiết bị mạng (Router, Switch, Firewall, v.v.)
               - Kiểm tra vấn đề routing, NAT, và các policy ngăn chặn
            
            2. Phát hiện các dấu hiệu tấn công mạng:
               - ARP: Spoofing, Poisoning, Man-in-the-Middle
               - DHCP: Spoofing, Starvation, DOS, Rogue DHCP Server
               - DNS: Cache Poisoning, Tunneling, Spoofing, Amplification
               - ICMP: Ping Flooding, Tunneling, Smurf Attack
               - TCP/IP: SYN Flood, RST Attack, Session Hijacking, Port Scanning
               - DDoS: Reflection/Amplification, Slowloris, HTTP Flooding
            
            3. Phân tích theo mô hình OSI (xác định vấn đề ở từng tầng):
               - Tầng liên kết dữ liệu: Xung đột MAC, ARP poisoning, VLAN issues
               - Tầng mạng: IP routing, ICMP, fragmentation, TTL issues
               - Tầng giao vận: TCP handshake, RST packets, port availability
               - Tầng ứng dụng: DNS resolution, HTTP errors, TLS issues
            
            4. Đề xuất giải pháp:
               - Các lệnh và công cụ debug phù hợp (tcpdump, Wireshark, netstat, ping, v.v.)
               - Quy trình kiểm tra có hệ thống
               - Giải pháp khắc phục ngắn hạn và dài hạn
               - Đánh giá mức độ nghiêm trọng và tác động
            """
        
        prompt = f"{base_prompt}\n\n"
        
        # Thêm thông tin tổng quan về các gói tin
        prompt += f"## Tổng quan\n"
        prompt += f"- Tổng số gói tin: {len(packets)}\n"
        
        # Phân loại gói tin theo giao thức
        protocols = {}
        for packet in packets:
            proto = getattr(packet, 'protocol', 'Unknown')
            protocols[proto] = protocols.get(proto, 0) + 1
        
        prompt += "\n## Phân bố giao thức\n"
        for proto, count in protocols.items():
            prompt += f"- {proto}: {count} gói tin\n"
        
        # Thêm thông tin chi tiết về một số gói tin (giới hạn để tránh prompt quá dài)
        prompt += "\n## Chi tiết các gói tin mẫu\n"
        sample_count = min(20, len(packets))  # Tăng số lượng gói tin mẫu lên 20
        
        for i, packet in enumerate(packets[:sample_count]):
            prompt += f"\n### Gói tin #{i+1}\n"
            
            # Thông tin cơ bản về gói
            for attr in ['protocol', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'timestamp', 'length']:
                if hasattr(packet, attr):
                    prompt += f"- {attr}: {getattr(packet, attr)}\n"
            
            # Thông tin chi tiết cho từng loại gói
            if hasattr(packet, 'protocol'):
                if packet.protocol == 'TCP':
                    # Thông tin TCP flags
                    if hasattr(packet, 'flags'):
                        prompt += f"- TCP flags: {packet.flags}\n"
                    # TCP sequence và ack number
                    for attr in ['seq_num', 'ack_num', 'window_size']:
                        if hasattr(packet, attr):
                            prompt += f"- {attr}: {getattr(packet, attr)}\n"
                    # Thử truy cập các phương thức cụ thể nếu có
                    for method in ['is_syn', 'is_ack', 'is_rst', 'is_fin', 'is_psh', 'is_urg']:
                        if hasattr(packet, method) and callable(getattr(packet, method)):
                            prompt += f"- {method}: {getattr(packet, method)()}\n"
                
                elif packet.protocol == 'ICMP':
                    # Thông tin ICMP
                    for attr in ['icmp_type', 'icmp_code', 'icmp_id', 'icmp_seq']:
                        if hasattr(packet, attr):
                            prompt += f"- {attr}: {getattr(packet, attr)}\n"
                    # Thử truy cập các phương thức cụ thể
                    for method in ['is_echo_request', 'is_echo_reply', 'is_unreachable', 'is_redirect']:
                        if hasattr(packet, method) and callable(getattr(packet, method)):
                            prompt += f"- {method}: {getattr(packet, method)()}\n"
                
                elif packet.protocol == 'ARP':
                    # Thông tin ARP
                    for attr in ['src_mac', 'dst_mac', 'sender_ip', 'sender_mac', 'target_ip', 'target_mac', 'operation']:
                        if hasattr(packet, attr):
                            prompt += f"- {attr}: {getattr(packet, attr)}\n"
                    # Thử phương thức
                    for method in ['is_request', 'is_reply', 'is_announcement']:
                        if hasattr(packet, method) and callable(getattr(packet, method)):
                            prompt += f"- {method}: {getattr(packet, method)()}\n"
                
                elif packet.protocol == 'UDP':
                    # Thông tin UDP
                    for attr in ['length', 'checksum', 'payload_length']:
                        if hasattr(packet, attr):
                            prompt += f"- {attr}: {getattr(packet, attr)}\n"
                
                elif packet.protocol == 'DNS':
                    # Thông tin DNS
                    for attr in ['query_name', 'query_type', 'answer', 'response_code']:
                        if hasattr(packet, attr):
                            prompt += f"- {attr}: {getattr(packet, attr)}\n"
                    # Thử phương thức
                    for method in ['is_query', 'is_response', 'has_answers']:
                        if hasattr(packet, method) and callable(getattr(packet, method)):
                            prompt += f"- {method}: {getattr(packet, method)()}\n"
                
                elif packet.protocol == 'DHCP':
                    # Thông tin DHCP
                    for attr in ['message_type', 'client_mac', 'requested_ip', 'client_ip', 'server_ip']:
                        if hasattr(packet, attr):
                            prompt += f"- {attr}: {getattr(packet, attr)}\n"
        
        if len(packets) > sample_count:
            prompt += f"\n*...và {len(packets) - sample_count} gói tin khác...*\n"
            
        # Yêu cầu cụ thể hơn về phân tích
        prompt += "\n## Yêu cầu phân tích chi tiết\n"
        prompt += "Dựa trên các gói tin trên, hãy phân tích:\n"
        prompt += "1. Các vấn đề kết nối mạng hiện tại hoặc tiềm ẩn\n"
        prompt += "2. Dấu hiệu cụ thể của các cuộc tấn công nếu có\n"
        prompt += "3. Phân tích theo mô hình OSI - xác định vấn đề ở từng tầng\n"
        prompt += "4. Đánh giá tỷ lệ các gói tin TCP reset, retransmission và failed connections\n"
        prompt += "5. Phân tích timeout hoặc latency bất thường\n"
        prompt += "6. Đề xuất giải pháp và các lệnh debug cụ thể\n"
        prompt += "7. Kết luận về nguyên nhân gốc rễ của vấn đề\n"
        
        return prompt
    
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