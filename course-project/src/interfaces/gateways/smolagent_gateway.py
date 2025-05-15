"""
SmolagentGateway - Interface for integrating with smolagent framework for analysis.
It provides methods to analyze network traffic patterns and attack indicators using a multi-agent architecture.
"""
import json
import os
from typing import Dict, Any, Optional, List

from dotenv import load_dotenv
from openinference.instrumentation.smolagents import SmolagentsInstrumentor
from phoenix.otel import register
from smolagents import (
    ToolCallingAgent,
    DuckDuckGoSearchTool,
    VisitWebpageTool,
    LiteLLMModel, CodeAgent,
)

from src.infrastructure.repositories.yaml_prompt_repository import YamlPromptRepository
from src.interfaces.gateways.osi_analyzer import OSILayerAnalyzer
from src.interfaces.gateways.response_extractor import ResponseExtractor
from src.use_cases.prompt_service import PromptService

register()
SmolagentsInstrumentor().instrument()

# Biến toàn cục để lưu kết quả markdown cuối cùng
LATEST_ANALYSIS_MARKDOWN = ""

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
        """Initialize specialized agents for network analysis."""
        # Search agent (support utility)
        self.search_agent = ToolCallingAgent(
            tools=[DuckDuckGoSearchTool(), VisitWebpageTool()],
            model=self.model,
            name="search_agent",
            description="This agent performs web searches to get up-to-date information about network protocols and vulnerabilities."
        )

        # Packet analyzer agent (general packet analysis agent)
        self.packet_analyzer_agent = ToolCallingAgent(
            tools=[],
            model=self.model,
            name="packet_analyzer_agent",
            description="This agent specializes in detailed packet inspection, analyzing protocol headers, flags, and payload data to identify anomalies.",
            managed_agents=[self.search_agent]
        )

        # LAYER 2 - DATA LINK
        # Ethernet agent (Layer 2)
        self.ethernet_agent = ToolCallingAgent(
            tools=[],
            model=self.model,
            name="ethernet_agent",
            description="This agent specializes in Ethernet frame analysis, focusing on MAC addressing, VLAN tagging, and layer 2 collisions or errors.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # ARP agent (Layer 2-3)
        self.arp_agent = ToolCallingAgent(
            tools=[],
            model=self.model,
            name="arp_agent",
            description="This agent specializes in ARP protocol analysis, focusing on ARP spoofing detection, MAC-IP mapping conflicts, and ARP cache poisoning.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # LAYER 3 - NETWORK
        # IPv4/IPv6 agent (Layer 3)
        self.ip_agent = ToolCallingAgent(
            tools=[],
            model=self.model,
            name="ip_agent",
            description="This agent specializes in IP protocol analysis, focusing on IP fragmentation, TTL issues, routing problems, and IPv4/IPv6 specific features.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # ICMP agent (Layer 3)
        self.icmp_agent = ToolCallingAgent(
            tools=[],
            model=self.model,
            name="icmp_agent",
            description="This agent specializes in ICMP protocol analysis, focusing on unusual echo patterns, tunnel detection, and ICMP flooding.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # LAYER 4 - TRANSPORT
        # TCP agent (Layer 4)
        self.tcp_agent = ToolCallingAgent(
            tools=[],
            model=self.model,
            name="tcp_agent",
            description="This agent specializes in TCP protocol analysis, focusing on handshake analysis, flags, sequence numbers, and potential TCP-specific attacks.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # UDP agent (Layer 4)
        self.udp_agent = ToolCallingAgent(
            tools=[],
            model=self.model,
            name="udp_agent",
            description="This agent specializes in UDP protocol analysis, focusing on connectionless communication, datagram issues, and UDP-specific attacks.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # LAYER 5 - SESSION
        # Session agent (Layer 5)
        self.session_agent = ToolCallingAgent(
            tools=[],
            model=self.model,
            name="session_agent",
            description="This agent specializes in Session layer protocols analysis, focusing on session establishment, management, and termination. Analyzes protocols like SIP, NetBIOS, RPC, and SMB.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # LAYER 6 - PRESENTATION
        # TLS/SSL agent (Layer 6)
        self.tls_agent = ToolCallingAgent(
            tools=[],
            model=self.model,
            name="tls_agent",
            description="This agent specializes in TLS/SSL protocol analysis, focusing on handshake issues, certificate validation, cipher suites, and encryption vulnerabilities.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # LAYER 7 - APPLICATION
        # DNS agent (Layer 7)
        self.dns_agent = ToolCallingAgent(
            tools=[],
            model=self.model,
            name="dns_agent",
            description="This agent specializes in DNS protocol analysis, focusing on DNS queries/responses, cache poisoning, tunneling, and zone transfers.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # HTTP/HTTPS agent (Layer 7)
        self.http_agent = ToolCallingAgent(
            tools=[],
            model=self.model,
            name="http_agent",
            description="This agent specializes in HTTP/HTTPS protocol analysis, focusing on request/response patterns, status codes, headers, and web-based attacks.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # ATTACK DETECTION AGENT
        # Attack detection agent
        self.attack_agent = ToolCallingAgent(
            tools=[],
            model=self.model,
            name="attack_agent",
            description="This agent specializes in correlating evidence from multiple sources to identify attack patterns and provide threat intelligence.",
            managed_agents=[self.ethernet_agent, self.arp_agent,
                            self.ip_agent, self.icmp_agent,
                            self.tcp_agent, self.udp_agent,
                            self.session_agent, self.tls_agent,
                            self.dns_agent, self.http_agent]
        )

        # MAIN COORDINATOR AGENT
        # Manager agent - supervises and coordinates other agents
        self.manager_agent = CodeAgent(
            tools=[],
            model=self.model,
            name="analyst_agent",
            description="This is the main coordinator that analyzes network traffic patterns and synthesizes findings.",
            managed_agents=[self.packet_analyzer_agent, self.search_agent]
        )

    def format_result_to_markdown(self, result: Dict[str, Any]) -> str:
        """
        Chuyển đổi kết quả từ dict sang chuỗi markdown để hiển thị trong Gradio.

        Args:
            result: Dictionary kết quả phân tích hoặc chuỗi JSON

        Returns:
            Chuỗi markdown chứa kết quả phân tích
        """
        global LATEST_ANALYSIS_MARKDOWN
        
        if not result:
            return "Không có kết quả phân tích."

        # Nếu đã là chuỗi, kiểm tra xem có phải JSON không
        if isinstance(result, str):
            # Kiểm tra và xử lý chuỗi kết quả có format đặc biệt "Out - Final answer:"
            if "Out - Final answer:" in result:
                full_content = result.split("Out - Final answer:")[0].strip()
                if full_content:
                    # Nếu có nội dung trước "Out - Final answer:", giữ lại toàn bộ nội dung
                    return full_content

            try:
                # Thử chuyển đổi chuỗi thành JSON
                result_dict = json.loads(result)
                # Nếu thành công, sử dụng dict này để format
                result = result_dict
            except json.JSONDecodeError:
                # Nếu không phải JSON, trả về chuỗi nguyên bản
                return result

        # Xử lý nếu analysis chứa "Out - Final answer:"
        if isinstance(result, dict) and "analysis" in result and isinstance(result["analysis"], str):
            if "Out - Final answer:" in result["analysis"]:
                # Lấy phần nội dung trước "Out - Final answer:"
                full_content = result["analysis"].split("Out - Final answer:")[0].strip()
                if full_content:
                    result["analysis"] = full_content

        markdown = "# Kết quả phân tích mạng\n\n"

        # Xử lý trường hợp phân tích OSI Layer mới
        if isinstance(result, dict) and "OSI Layer Analysis" in result:
            markdown += "## Phân tích theo mô hình OSI\n\n"
            osi_layers = result["OSI Layer Analysis"]

            # Duyệt qua từng tầng OSI
            for layer, layer_info in osi_layers.items():
                markdown += f"### {layer}\n\n"

                if isinstance(layer_info, dict):
                    # Phân tích 
                    if "analysis" in layer_info:
                        markdown += f"**Phân tích:** {layer_info['analysis']}\n\n"

                    # Security issues
                    if "security_issues" in layer_info:
                        markdown += "**Vấn đề bảo mật:**\n\n"
                        for issue in layer_info["security_issues"]:
                            markdown += f"- {issue}\n"
                        markdown += "\n"

                    # Severity
                    if "severity" in layer_info:
                        markdown += f"**Mức độ nghiêm trọng:** {layer_info['severity']}/10\n\n"

                    # Recommendations
                    if "recommendation" in layer_info:
                        markdown += "**Khuyến nghị:**\n\n"
                        recommendations = layer_info["recommendation"]
                        if isinstance(recommendations, list):
                            for rec in recommendations:
                                markdown += f"- {rec}\n"
                        else:
                            markdown += f"{recommendations}\n"
                        markdown += "\n"
                else:
                    markdown += f"{layer_info}\n\n"

            # Conclusion nếu có
            if "Conclusion" in result:
                markdown += "## Kết luận\n\n"
                markdown += f"{result['Conclusion']}\n\n"

            # New Detection Use Cases nếu có
            if "New Detection Use Cases" in result:
                markdown += "## Các trường hợp phát hiện mới\n\n"
                use_cases = result["New Detection Use Cases"]
                if isinstance(use_cases, list):
                    for case in use_cases:
                        markdown += f"- {case}\n"
                else:
                    markdown += f"{use_cases}\n"
                markdown += "\n"

            # Lưu kết quả vào biến toàn cục
            LATEST_ANALYSIS_MARKDOWN = markdown
            return markdown

        # Xử lý các trường hợp khác
        if not isinstance(result, dict):
            # Nếu kết quả không phải là từ điển hoặc chuỗi, chuyển về chuỗi và trả về
            return f"## Phân tích\n\n{str(result)}\n\n"
            
        # Thêm tóm tắt nếu có
        if "summary" in result:
            markdown += f"## Tóm tắt\n\n{result['summary']}\n\n"

        # Thêm phân tích chung nếu có
        if "analysis" in result:
            markdown += f"## Phân tích chi tiết\n\n{result['analysis']}\n\n"

        # Thêm phát hiện chi tiết nếu có
        if "findings" in result:
            markdown += f"## Phát hiện chi tiết\n\n"

            findings = result["findings"]
            if isinstance(findings, dict):
                markdown += "| Vấn đề | Mức độ rủi ro | Mô tả | Giải pháp |\n"
                markdown += "| --- | --- | --- | --- |\n"

                for issue, details in findings.items():
                    risk = details.get("risk", "N/A")
                    description = details.get("description", "Không có mô tả")
                    solution = details.get("solution", "Không có giải pháp")

                    # Format tên vấn đề
                    issue_name = issue.replace("_", " ").title()

                    markdown += f"| **{issue_name}** | {risk} | {description} | {solution} |\n"
            else:
                markdown += f"{findings}\n\n"

        # Thêm thông tin về cuộc tấn công nếu có
        if "attack_detected" in result:
            attack_detected = result["attack_detected"]
            attack_type = result.get("attack_type", "Không xác định")
            confidence = result.get("confidence", "Không xác định")

            markdown += f"## Phát hiện tấn công\n\n"
            markdown += f"- **Phát hiện tấn công:** {'Có' if attack_detected else 'Không'}\n"
            if attack_detected:
                markdown += f"- **Loại tấn công:** {attack_type}\n"
                markdown += f"- **Độ tin cậy:** {confidence}\n\n"

        # Thêm khuyến nghị nếu có
        if "recommendations" in result:
            markdown += f"## Khuyến nghị\n\n"

            recommendations = result["recommendations"]
            if isinstance(recommendations, list):
                for i, rec in enumerate(recommendations, 1):
                    markdown += f"{i}. {rec}\n"
            else:
                markdown += f"{recommendations}\n\n"

        # Thêm phân tích OSI nếu có
        if "osi_layers" in result:
            markdown += f"## Phân tích theo mô hình OSI\n\n"

            osi_layers = result["osi_layers"]
            if isinstance(osi_layers, dict):
                for layer, analysis in osi_layers.items():
                    layer_name = layer.replace("_", " ").title()
                    markdown += f"### Tầng {layer_name}\n\n"

                    if isinstance(analysis, str):
                        markdown += f"{analysis}\n\n"
                    elif isinstance(analysis, dict):
                        # Format dictionary phân tích tầng OSI
                        if "issues" in analysis:
                            markdown += "#### Vấn đề phát hiện\n\n"
                            issues = analysis["issues"]
                            if isinstance(issues, list):
                                for issue in issues:
                                    markdown += f"- {issue}\n"
                            else:
                                markdown += f"{issues}\n\n"

                        if "recommendations" in analysis:
                            markdown += "\n#### Đề xuất xử lý\n\n"
                            recommendations = analysis["recommendations"]
                            if isinstance(recommendations, list):
                                for rec in recommendations:
                                    markdown += f"- {rec}\n"
                            else:
                                markdown += f"{recommendations}\n\n"

                        # Format các thông tin khác
                        for key, value in analysis.items():
                            if key not in ["issues", "recommendations"]:
                                title = key.replace("_", " ").title()
                                markdown += f"\n#### {title}\n\n"
                                if isinstance(value, list):
                                    for item in value:
                                        markdown += f"- {item}\n"
                                elif isinstance(value, dict):
                                    markdown += "```json\n"
                                    markdown += json.dumps(value, indent=2, ensure_ascii=False)
                                    markdown += "\n```\n\n"
                                else:
                                    markdown += f"{value}\n\n"
            else:
                markdown += f"{osi_layers}\n\n"

        # Thêm phân tích giao thức cụ thể
        for protocol in ["tcp", "udp", "icmp", "arp", "dns", "http"]:
            if f"{protocol}_analysis" in result:
                protocol_upper = protocol.upper()
                markdown += f"## Phân tích {protocol_upper}\n\n"

                analysis = result[f"{protocol}_analysis"]
                if isinstance(analysis, dict):
                    for key, value in analysis.items():
                        title = key.replace("_", " ").title()
                        markdown += f"### {title}\n\n"

                        if isinstance(value, list):
                            for item in value:
                                markdown += f"- {item}\n"
                        elif isinstance(value, dict):
                            markdown += "```json\n"
                            markdown += json.dumps(value, indent=2, ensure_ascii=False)
                            markdown += "\n```\n\n"
                        else:
                            markdown += f"{value}\n\n"
                else:
                    markdown += f"{analysis}\n\n"

        # Thêm các thông tin khác
        for key, value in result.items():
            if key not in ["summary", "analysis", "findings", "attack_detected", "attack_type",
                          "confidence", "recommendations", "osi_layers", "tcp_analysis",
                          "udp_analysis", "icmp_analysis", "arp_analysis", "dns_analysis",
                          "http_analysis", "OSI Layer Analysis", "Conclusion", "New Detection Use Cases"]:

                title = key.replace("_", " ").title()
                markdown += f"## {title}\n\n"

                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        sub_title = sub_key.replace("_", " ").title()
                        markdown += f"### {sub_title}\n\n"

                        if isinstance(sub_value, list):
                            for item in sub_value:
                                markdown += f"- {item}\n"
                            markdown += "\n"
                        elif isinstance(sub_value, dict):
                            markdown += "```json\n"
                            markdown += json.dumps(sub_value, indent=2, ensure_ascii=False)
                            markdown += "\n```\n\n"
                        else:
                            markdown += f"{sub_value}\n\n"
                elif isinstance(value, list):
                    if all(isinstance(item, str) for item in value):
                        for item in value:
                            markdown += f"- {item}\n"
                        markdown += "\n"
                    else:
                        markdown += "```json\n"
                        markdown += json.dumps(value, indent=2, ensure_ascii=False)
                        markdown += "\n```\n\n"
                else:
                    markdown += f"{value}\n\n"

        # Lưu kết quả vào biến toàn cục
        LATEST_ANALYSIS_MARKDOWN = markdown
        return markdown

    def analyze_traffic_pattern(self, stats: Dict[str, Any]) -> str:
        """
        Analyze traffic patterns using smolagent.
        
        Args:
            stats: Dictionary of traffic statistics.
        
        Returns:
            Analysis results from the agent as markdown string.
        """
        # Convert stats to a prompt
        prompt = self._build_analysis_prompt(stats)

        # Query the agent
        response = self.manager_agent.run(prompt)

        # Parse the response
        try:
            # Try to parse as JSON if possible
            results = json.loads(response)
        except (json.JSONDecodeError, TypeError):
            # Check if the response is already formatted nicely
            if response.startswith("# ") or response.startswith("## ") or response.startswith("TỔNG HỢP PHÂN TÍCH"):
                return response
            # Otherwise, use the raw response
            results = {"analysis": response}

        # Chuyển đổi kết quả thành chuỗi markdown
        return self.format_result_to_markdown(results)

    def analyze_attack_indicators(self, indicators: Dict[str, Any]) -> str:
        """
        Analyze potential attack indicators using smolagent.
        
        Args:
            indicators: Dictionary of attack indicators.
        
        Returns:
            Assessment of attack indicators as markdown string.
        """
        # Convert indicators to a prompt
        prompt = self._build_attack_prompt(indicators)

        # Query the agent
        response = self.manager_agent.run(prompt)

        # Process the response
        try:
            # Try to parse as JSON if possible
            results = json.loads(response)
        except (json.JSONDecodeError, TypeError):
            # Check if the response is already formatted nicely
            if response.startswith("# ") or response.startswith("## ") or response.startswith("TỔNG HỢP PHÂN TÍCH"):
                return response

            # Try to extract structured data from text response
            results = {
                "attack_detected": self.response_extractor.extract_attack_detection(response),
                "attack_type": self.response_extractor.extract_attack_type(response),
                "confidence": self.response_extractor.extract_confidence(response),
                "recommendations": self.response_extractor.extract_recommendations(response),
                "analysis": response
            }

        # Chuyển đổi kết quả thành chuỗi markdown
        return self.format_result_to_markdown(results)

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

            # Kiểm tra xem phản hồi có phải là JSON không
            try:
                json_result = json.loads(response)
                return self.format_result_to_markdown(json_result)
            except json.JSONDecodeError:
                # Nếu đã định dạng tốt, trả về nguyên bản
                if response.startswith("# ") or response.startswith("## ") or response.startswith("TỔNG HỢP PHÂN TÍCH"):
                    return response
                return response

        except Exception as e:
            return f"Xin lỗi, tôi không thể xử lý câu hỏi của bạn lúc này. Lỗi: {str(e)}"

    def analyze_osi_layers(self, results: Dict[str, Any]) -> str:
        """
        Phân tích lưu lượng mạng theo các tầng của mô hình OSI sử dụng multiagent.
        
        Args:
            results: Dictionary chứa kết quả phân tích gói tin.
        
        Returns:
            Kết quả phân tích theo mô hình OSI.
        """
        osi_results = self.osi_analyzer.analyze(results)

        # Nếu kết quả là chuỗi và đã định dạng tốt, trả về ngay
        if isinstance(osi_results, str):
            if osi_results.startswith("# ") or osi_results.startswith("## ") or osi_results.startswith(
                    "TỔNG HỢP PHÂN TÍCH"):
                return osi_results

        return self.format_result_to_markdown(osi_results)

    def analyze_raw_packets(self, packets: List, custom_prompt: str = None) -> str:
        """
        Phân tích trực tiếp danh sách gói tin thô thay vì sử dụng kết quả phân tích.
        
        Args:
            packets: Danh sách các gói tin thô cần phân tích
            custom_prompt: Prompt tùy chỉnh để hướng dẫn AI phân tích. Nếu None, sẽ dùng prompt mặc định
            
        Returns:
            Kết quả phân tích từ AI
        """
        if not packets:
            return "Không có gói tin nào để phân tích."

        # Xây dựng prompt từ raw packets
        prompt = self._build_raw_packets_prompt(packets, custom_prompt)

        # Gọi manager_agent để phân tích
        try:
            response = self.manager_agent.run(prompt)

            # Kiểm tra nếu phản hồi đã được định dạng tốt
            if response.startswith("# ") or response.startswith("## ") or response.startswith("TỔNG HỢP PHÂN TÍCH"):
                return response

            # Xử lý phản hồi
            try:
                # Thử phân tích JSON nếu có thể
                result = json.loads(response)
            except (json.JSONDecodeError, TypeError):
                # Nếu không, sử dụng phản hồi dạng văn bản
                result = {"analysis": response}

            # Chuyển đổi kết quả thành chuỗi markdown
            return self.format_result_to_markdown(result)
        except Exception as e:
            return f"Lỗi khi phân tích gói tin: {str(e)}"

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

    def analyze_osi_raw_packets(self, packets: List, custom_prompt: str = None) -> str:
        """
        Phân tích danh sách gói tin thô theo mô hình OSI.
        
        Args:
            packets: Danh sách các gói tin thô cần phân tích
            custom_prompt: Prompt tùy chỉnh. Nếu None, sẽ dùng prompt mặc định
            
        Returns:
            Kết quả phân tích theo mô hình OSI
        """
        if not packets:
            return "Không có gói tin nào để phân tích theo mô hình OSI."

        # Sử dụng osi_analyzer để phân tích
        result = self.osi_analyzer.analyze_raw_packets(packets, custom_prompt)

        # Kiểm tra nếu kết quả đã là chuỗi định dạng tốt
        if isinstance(result, str):
            if result.startswith("# ") or result.startswith("## ") or result.startswith("TỔNG HỢP PHÂN TÍCH"):
                return result

        return self.format_result_to_markdown(result)
