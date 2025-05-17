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
        tools = [
            DuckDuckGoSearchTool(),
            VisitWebpageTool(),
            # Add other tools as needed
        ]
        # Search agent (support utility)
        self.search_agent = ToolCallingAgent(
            tools=tools,
            model=self.model,
            name="search_agent",
            description="This agent performs web searches to get up-to-date information about network protocols and vulnerabilities."
        )

        # Packet analyzer agent (general packet analysis agent)
        self.packet_analyzer_agent = ToolCallingAgent(
            tools=tools,
            model=self.model,
            name="packet_analyzer_agent",
            description="This agent specializes in detailed packet inspection, analyzing protocol headers, flags, and payload data to identify anomalies.",
            managed_agents=[self.search_agent]
        )

        # LAYER 2 - DATA LINK
        # Ethernet agent (Layer 2)
        self.ethernet_agent = ToolCallingAgent(
            tools=tools,
            model=self.model,
            name="ethernet_agent",
            description="This agent specializes in Ethernet frame analysis, focusing on MAC addressing, VLAN tagging, and layer 2 collisions or errors.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # ARP agent (Layer 2-3)
        self.arp_agent = ToolCallingAgent(
            tools=tools,
            model=self.model,
            name="arp_agent",
            description="This agent specializes in ARP protocol analysis, focusing on ARP spoofing detection, MAC-IP mapping conflicts, and ARP cache poisoning.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # LAYER 3 - NETWORK
        # IPv4/IPv6 agent (Layer 3)
        self.ip_agent = ToolCallingAgent(
            tools=tools,
            model=self.model,
            name="ip_agent",
            description="This agent specializes in IP protocol analysis, focusing on IP fragmentation, TTL issues, routing problems, and IPv4/IPv6 specific features.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # ICMP agent (Layer 3)
        self.icmp_agent = ToolCallingAgent(
            tools=tools,
            model=self.model,
            name="icmp_agent",
            description="This agent specializes in ICMP protocol analysis, focusing on unusual echo patterns, tunnel detection, and ICMP flooding.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # LAYER 4 - TRANSPORT
        # TCP agent (Layer 4)
        self.tcp_agent = ToolCallingAgent(
            tools=tools,
            model=self.model,
            name="tcp_agent",
            description="This agent specializes in TCP protocol analysis, focusing on handshake analysis, flags, sequence numbers, and potential TCP-specific attacks.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # UDP agent (Layer 4)
        self.udp_agent = ToolCallingAgent(
            tools=tools,
            model=self.model,
            name="udp_agent",
            description="This agent specializes in UDP protocol analysis, focusing on connectionless communication, datagram issues, and UDP-specific attacks.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # LAYER 5 - SESSION
        # Session agent (Layer 5)
        self.session_agent = ToolCallingAgent(
            tools=tools,
            model=self.model,
            name="session_agent",
            description="This agent specializes in Session layer protocols analysis, focusing on session establishment, management, and termination. Analyzes protocols like SIP, NetBIOS, RPC, and SMB.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # LAYER 6 - PRESENTATION
        # TLS/SSL agent (Layer 6)
        self.tls_agent = ToolCallingAgent(
            tools=tools,
            model=self.model,
            name="tls_agent",
            description="This agent specializes in TLS/SSL protocol analysis, focusing on handshake issues, certificate validation, cipher suites, and encryption vulnerabilities.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # LAYER 7 - APPLICATION
        # DNS agent (Layer 7)
        self.dns_agent = ToolCallingAgent(
            tools=tools,
            model=self.model,
            name="dns_agent",
            description="This agent specializes in DNS protocol analysis, focusing on DNS queries/responses, cache poisoning, tunneling, and zone transfers.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # HTTP/HTTPS agent (Layer 7)
        self.http_agent = ToolCallingAgent(
            tools=tools,
            model=self.model,
            name="http_agent",
            description="This agent specializes in HTTP/HTTPS protocol analysis, focusing on request/response patterns, status codes, headers, and web-based attacks.",
            managed_agents=[self.packet_analyzer_agent]
        )

        # ATTACK DETECTION AGENT
        # Attack detection agent
        self.attack_agent = ToolCallingAgent(
            tools=tools,
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
            managed_agents=[self.ethernet_agent, self.arp_agent,
                            self.ip_agent, self.icmp_agent,
                            self.tcp_agent, self.udp_agent,
                            self.session_agent, self.tls_agent,
                            self.dns_agent, self.http_agent]
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
                {"context": formatted_info},
                "osi_analysis"
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
            base_prompt += f"- {proto}: {count} gói tin ({(count / len(packets)) * 100:.2f}%)\n"

        # Thêm thông tin chi tiết về một số gói tin (giới hạn để tránh prompt quá dài)
        base_prompt += "\n## Chi tiết các gói tin mẫu\n"

        # Cải tiến cách lấy mẫu: Nếu có nhiều hơn 25 gói tin, lấy mẫu đầu, giữa và cuối
        MAX_SAMPLES = 30
        if len(packets) <= MAX_SAMPLES:
            sample_packets = packets
        else:
            # Lấy mẫu: đầu, giữa và cuối
            head_count = MAX_SAMPLES // 3
            mid_count = MAX_SAMPLES // 3
            tail_count = MAX_SAMPLES - head_count - mid_count

            head_packets = packets[:head_count]
            mid_start = max(head_count, len(packets) // 2 - mid_count // 2)
            mid_packets = packets[mid_start:mid_start + mid_count]
            tail_packets = packets[max(mid_start + mid_count, len(packets) - tail_count):]

            sample_packets = head_packets + mid_packets + tail_packets
            base_prompt += f"*Ghi chú: Hiển thị {MAX_SAMPLES} gói tin mẫu từ đầu, giữa và cuối để đại diện cho {len(packets)} gói tin*\n\n"

        # Lấy thống kê về giao thức của các gói tin mẫu
        sample_protocols = {}
        for packet in sample_packets:
            proto = getattr(packet, 'protocol', 'Unknown')
            sample_protocols[proto] = sample_protocols.get(proto, 0) + 1

        if len(packets) > MAX_SAMPLES:
            base_prompt += f"Phân bố giao thức trong mẫu: "
            proto_list = [f"{proto}: {count} gói tin" for proto, count in sample_protocols.items()]
            base_prompt += ", ".join(proto_list) + "\n\n"

        for i, packet in enumerate(sample_packets):
            # Hiển thị thông tin về vị trí của gói tin trong danh sách gốc nếu là mẫu
            packet_idx = packets.index(packet) if len(packets) > MAX_SAMPLES else i
            base_prompt += f"\n### Gói tin #{packet_idx + 1}\n"

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

        if len(packets) > MAX_SAMPLES:
            base_prompt += f"\n*Ghi chú: Đã lấy mẫu {len(sample_packets)} gói tin từ tổng số {len(packets)} gói tin.*\n"

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

    def export_packets_to_csv(self, packets: List, output_file: str = "data/packets/packets_analysis.csv") -> str:
        """
        Xuất danh sách gói tin sang file CSV để xử lý dữ liệu lớn.
        
        Args:
            packets: Danh sách các gói tin cần xuất
            output_file: Đường dẫn đến file CSV đầu ra
            
        Returns:
            Đường dẫn đến file CSV đã tạo
        """
        import csv
        import os

        # Đảm bảo thư mục tồn tại
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        # Xác định tất cả các trường có thể có
        all_fields = set(['protocol', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'timestamp', 'length'])

        # Thêm các trường đặc biệt cho từng giao thức
        protocol_fields = {
            'TCP': ['flags', 'seq_num', 'ack_num', 'window_size'],
            'ICMP': ['icmp_type', 'icmp_code', 'icmp_id', 'icmp_seq'],
            'ARP': ['src_mac', 'dst_mac', 'sender_ip', 'sender_mac', 'target_ip', 'target_mac', 'operation'],
            'UDP': ['length', 'checksum', 'payload_length'],
            'DNS': ['query_name', 'query_type', 'answer', 'response_code'],
            'DHCP': ['message_type', 'client_mac', 'requested_ip', 'client_ip', 'server_ip']
        }

        # Thu thập tất cả các trường từ tất cả các gói
        for packet in packets:
            proto = getattr(packet, 'protocol', 'Unknown')
            if proto in protocol_fields:
                for field in protocol_fields[proto]:
                    all_fields.add(field)

            # Thêm bất kỳ trường nào khác mà gói tin có thể có
            for attr in dir(packet):
                if not attr.startswith('_') and not callable(getattr(packet, attr)):
                    all_fields.add(attr)

        # Chuyển thành list để có thứ tự cố định
        fieldnames = sorted(list(all_fields))

        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for packet in packets:
                row = {}
                # Điền các giá trị có sẵn
                for field in fieldnames:
                    if hasattr(packet, field):
                        value = getattr(packet, field)
                        if callable(value):
                            continue
                        row[field] = value
                    else:
                        row[field] = None

                # Thêm các phương thức boolean nếu có
                if hasattr(packet, 'protocol'):
                    if packet.protocol == 'TCP':
                        for method in ['is_syn', 'is_ack', 'is_rst', 'is_fin', 'is_psh', 'is_urg']:
                            if hasattr(packet, method) and callable(getattr(packet, method)):
                                try:
                                    row[method] = getattr(packet, method)()
                                except:
                                    pass
                    elif packet.protocol == 'ICMP':
                        for method in ['is_echo_request', 'is_echo_reply', 'is_unreachable', 'is_redirect']:
                            if hasattr(packet, method) and callable(getattr(packet, method)):
                                try:
                                    row[method] = getattr(packet, method)()
                                except:
                                    pass
                    elif packet.protocol == 'ARP':
                        for method in ['is_request', 'is_reply', 'is_announcement']:
                            if hasattr(packet, method) and callable(getattr(packet, method)):
                                try:
                                    row[method] = getattr(packet, method)()
                                except:
                                    pass
                    elif packet.protocol == 'DNS':
                        for method in ['is_query', 'is_response', 'has_answers']:
                            if hasattr(packet, method) and callable(getattr(packet, method)):
                                try:
                                    row[method] = getattr(packet, method)()
                                except:
                                    pass

                writer.writerow(row)

        print(f"Đã xuất {len(packets)} gói tin sang file CSV: {output_file}")
        return output_file

    def _convert_df_to_packets(self, df):
        """
        Chuyển DataFrame thành danh sách đối tượng gói tin.
        
        Args:
            df: DataFrame chứa dữ liệu gói tin
            
        Returns:
            Danh sách đối tượng gói tin dạng SimpleNamespace
        """
        from types import SimpleNamespace

        packets = []
        for _, row in df.iterrows():
            # Loại bỏ các giá trị NaN
            clean_dict = {}
            for key, value in row.items():
                # Kiểm tra nếu giá trị không phải NaN
                import pandas as pd
                import numpy as np
                if not (pd.isna(value) or (isinstance(value, float) and np.isnan(value))):
                    clean_dict[key] = value

            # Tạo đối tượng từ dict đã làm sạch
            packet = SimpleNamespace(**clean_dict)
            packets.append(packet)

        return packets

    def _combine_chunk_results(self, results, overall_stats, total_count):
        """
        Tổng hợp kết quả từ các phần thành kết quả cuối cùng.
        
        Args:
            results: Danh sách kết quả từ các phần
            overall_stats: Thống kê tổng quan về gói tin
            total_count: Tổng số gói tin đã phân tích
            
        Returns:
            Kết quả phân tích tổng hợp
        """
        if not results:
            return {"analysis": "Không có kết quả phân tích."}

        # Khởi tạo kết quả tổng hợp
        combined = {
            "summary": f"Phân tích tổng cộng {total_count} gói tin",
            "OSI Layer Analysis": {}
        }

        # Phân bố giao thức
        combined["protocol_distribution"] = overall_stats["protocols"]

        # Tổng hợp phân tích OSI Layer
        osi_layers = [
            "Physical Layer",
            "Data Link Layer",
            "Network Layer",
            "Transport Layer",
            "Session Layer",
            "Presentation Layer",
            "Application Layer"
        ]

        # Tổng hợp các vấn đề bảo mật theo tầng
        security_issues_by_layer = {layer: [] for layer in osi_layers}
        severity_by_layer = {layer: [] for layer in osi_layers}
        recommendations_by_layer = {layer: [] for layer in osi_layers}

        for result in results:
            if isinstance(result, dict) and "OSI Layer Analysis" in result:
                for layer, layer_info in result["OSI Layer Analysis"].items():
                    if layer not in combined["OSI Layer Analysis"]:
                        combined["OSI Layer Analysis"][layer] = {
                            "analysis": "",
                            "security_issues": [],
                            "severity": 0,
                            "recommendation": []
                        }

                    # Thêm vào phân tích
                    if isinstance(layer_info, dict) and "analysis" in layer_info:
                        current_analysis = combined["OSI Layer Analysis"][layer]["analysis"]
                        new_analysis = layer_info["analysis"]
                        if current_analysis and new_analysis:
                            # Chỉ thêm nếu phân tích mới khác với phân tích hiện tại
                            if new_analysis not in current_analysis:
                                combined["OSI Layer Analysis"][layer]["analysis"] += " " + new_analysis
                        elif new_analysis:
                            combined["OSI Layer Analysis"][layer]["analysis"] = new_analysis

                    # Thu thập vấn đề bảo mật
                    if isinstance(layer_info, dict) and "security_issues" in layer_info:
                        issues = layer_info["security_issues"]
                        if isinstance(issues, list):
                            for issue in issues:
                                if issue not in security_issues_by_layer[layer]:
                                    security_issues_by_layer[layer].append(issue)
                        elif isinstance(issues, str) and issues not in security_issues_by_layer[layer]:
                            security_issues_by_layer[layer].append(issues)

                    # Thu thập mức độ nghiêm trọng
                    if isinstance(layer_info, dict) and "severity" in layer_info:
                        try:
                            severity = float(layer_info["severity"])
                            severity_by_layer[layer].append(severity)
                        except (ValueError, TypeError):
                            pass

                    # Thu thập khuyến nghị
                    if isinstance(layer_info, dict) and "recommendation" in layer_info:
                        recommendations = layer_info["recommendation"]
                        if isinstance(recommendations, list):
                            for rec in recommendations:
                                if rec not in recommendations_by_layer[layer]:
                                    recommendations_by_layer[layer].append(rec)
                        elif isinstance(recommendations, str) and recommendations not in recommendations_by_layer[
                            layer]:
                            recommendations_by_layer[layer].append(recommendations)

        # Cập nhật các giá trị tổng hợp vào kết quả cuối cùng
        for layer in osi_layers:
            if layer in combined["OSI Layer Analysis"]:
                # Cập nhật vấn đề bảo mật
                combined["OSI Layer Analysis"][layer]["security_issues"] = security_issues_by_layer[layer]

                # Tính trung bình mức độ nghiêm trọng
                if severity_by_layer[layer]:
                    combined["OSI Layer Analysis"][layer]["severity"] = round(
                        sum(severity_by_layer[layer]) / len(severity_by_layer[layer]), 1
                    )

                # Cập nhật khuyến nghị
                combined["OSI Layer Analysis"][layer]["recommendation"] = recommendations_by_layer[layer]

        # Thu thập kết luận và trường hợp phát hiện mới
        conclusions = []
        new_detection_cases = []

        for result in results:
            if isinstance(result, dict):
                # Thu thập kết luận
                if "Conclusion" in result:
                    conclusion = result["Conclusion"]
                    if conclusion and conclusion not in conclusions:
                        conclusions.append(conclusion)

                # Thu thập trường hợp phát hiện mới
                if "New Detection Use Cases" in result:
                    cases = result["New Detection Use Cases"]
                    if isinstance(cases, list):
                        for case in cases:
                            if case not in new_detection_cases:
                                new_detection_cases.append(case)
                    elif isinstance(cases, str) and cases not in new_detection_cases:
                        new_detection_cases.append(cases)

        # Thêm kết luận và trường hợp phát hiện mới vào kết quả cuối cùng
        if conclusions:
            combined["Conclusion"] = " ".join(conclusions)

        if new_detection_cases:
            combined["New Detection Use Cases"] = new_detection_cases

        return combined

    def analyze_csv_chunks(self, csv_file: str, chunk_size: int = 1000, custom_prompt: str = None,
                           save_interim_results: bool = False, result_dir: str = "data/analysis_results") -> str:
        """
        Phân tích file CSV chứa dữ liệu gói tin theo từng phần nhỏ.
        
        Args:
            csv_file: Đường dẫn đến file CSV
            chunk_size: Số lượng gói tin xử lý mỗi lần
            custom_prompt: Prompt tùy chỉnh
            save_interim_results: Lưu kết quả phân tích tạm thời của từng chunk
            result_dir: Thư mục lưu kết quả tạm thời
            
        Returns:
            Kết quả phân tích tổng hợp dạng markdown
        """
        try:
            import pandas as pd
            import json
            import time
            import os
            from datetime import datetime

            # Tạo thư mục lưu kết quả nếu cần
            if save_interim_results:
                os.makedirs(result_dir, exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                analysis_dir = os.path.join(result_dir, f"analysis_{timestamp}")
                os.makedirs(analysis_dir, exist_ok=True)
                print(f"Kết quả phân tích tạm thời sẽ được lưu tại: {analysis_dir}")

            start_time = time.time()
            print(f"Bắt đầu phân tích file CSV: {csv_file} với kích thước chunk: {chunk_size}")

            # Đếm tổng số dòng trong file CSV
            total_rows = sum(1 for _ in open(csv_file, 'r', encoding='utf-8')) - 1  # Trừ header
            print(f"Tổng số gói tin trong file: {total_rows}")

            # Đọc từng phần của CSV
            results = []
            overall_stats = {"protocols": {}}
            packet_count = 0
            chunk_count = 0

            # Đọc file theo từng phần
            for chunk in pd.read_csv(csv_file, chunksize=chunk_size):
                chunk_count += 1
                chunk_start = time.time()
                print(
                    f"Đang xử lý chunk {chunk_count}/{(total_rows + chunk_size - 1) // chunk_size} ({chunk.shape[0]} gói tin)...")

                # Chuyển DataFrame thành danh sách đối tượng gói tin
                packets = self._convert_df_to_packets(chunk)
                packet_count += len(packets)

                # Cập nhật thống kê giao thức
                for packet in packets:
                    proto = getattr(packet, 'protocol', 'Unknown')
                    overall_stats["protocols"][proto] = overall_stats["protocols"].get(proto, 0) + 1

                # Phân tích phần này
                chunk_result = self.analyze_raw_packets(packets, custom_prompt)

                # Lưu kết quả phân tích tạm thời nếu cần
                if save_interim_results:
                    chunk_result_file = os.path.join(analysis_dir, f"chunk_{chunk_count}_result.json")
                    chunk_markdown_file = os.path.join(analysis_dir, f"chunk_{chunk_count}_result.md")

                    # Lưu kết quả dạng JSON
                    try:
                        # Nếu kết quả là chuỗi, thử parse thành JSON
                        if isinstance(chunk_result, str):
                            try:
                                chunk_dict = json.loads(chunk_result)
                                with open(chunk_result_file, 'w', encoding='utf-8') as f:
                                    json.dump(chunk_dict, f, ensure_ascii=False, indent=2)
                            except json.JSONDecodeError:
                                # Nếu không parse được, lưu nguyên dạng
                                with open(chunk_result_file, 'w', encoding='utf-8') as f:
                                    json.dump({"analysis": chunk_result}, f, ensure_ascii=False, indent=2)
                        else:
                            with open(chunk_result_file, 'w', encoding='utf-8') as f:
                                json.dump(chunk_result, f, ensure_ascii=False, indent=2)
                    except Exception as e:
                        print(f"Lỗi khi lưu kết quả JSON của chunk {chunk_count}: {str(e)}")

                    # Lưu kết quả dạng Markdown
                    try:
                        markdown_result = self.format_result_to_markdown(chunk_result)
                        with open(chunk_markdown_file, 'w', encoding='utf-8') as f:
                            f.write(markdown_result)
                    except Exception as e:
                        print(f"Lỗi khi lưu kết quả Markdown của chunk {chunk_count}: {str(e)}")

                # Lưu kết quả phần này để tổng hợp
                try:
                    # Thử chuyển về dict nếu là JSON
                    if isinstance(chunk_result, str):
                        try:
                            chunk_dict = json.loads(chunk_result)
                            results.append(chunk_dict)
                        except json.JSONDecodeError:
                            # Nếu không phải JSON, lưu nguyên dạng
                            results.append({"analysis": chunk_result})
                    else:
                        results.append(chunk_result)
                except Exception as e:
                    print(f"Lỗi khi xử lý kết quả chunk {chunk_count}: {str(e)}")
                    results.append({"analysis": f"Lỗi xử lý chunk {chunk_count}: {str(e)}"})

                chunk_end = time.time()
                print(f"Hoàn thành chunk {chunk_count} trong {chunk_end - chunk_start:.2f} giây")

            # Tổng hợp kết quả từ tất cả các phần
            print(f"Tổng hợp kết quả từ {chunk_count} chunks...")
            final_result = self._combine_chunk_results(results, overall_stats, packet_count)

            end_time = time.time()
            total_time = end_time - start_time
            print(
                f"Hoàn thành phân tích {packet_count} gói tin trong {total_time:.2f} giây ({total_time / 60:.2f} phút)")

            # Lưu kết quả tổng hợp nếu cần
            if save_interim_results:
                final_result_file = os.path.join(analysis_dir, "final_result.json")
                final_markdown_file = os.path.join(analysis_dir, "final_result.md")

                try:
                    with open(final_result_file, 'w', encoding='utf-8') as f:
                        json.dump(final_result, f, ensure_ascii=False, indent=2)
                except Exception as e:
                    print(f"Lỗi khi lưu kết quả tổng hợp dạng JSON: {str(e)}")

                # Định dạng kết quả thành markdown và lưu
                final_markdown = self.format_result_to_markdown(final_result)
                try:
                    with open(final_markdown_file, 'w', encoding='utf-8') as f:
                        f.write(final_markdown)
                except Exception as e:
                    print(f"Lỗi khi lưu kết quả tổng hợp dạng Markdown: {str(e)}")

                print(f"Đã lưu kết quả tổng hợp tại: {final_markdown_file}")

            # Định dạng và trả về kết quả
            return self.format_result_to_markdown(final_result)

        except Exception as e:
            error_msg = f"Lỗi khi phân tích file CSV: {str(e)}"
            print(error_msg)
            return error_msg

    def stream_csv_to_ai(self, csv_file: str, chunk_size: int = 500, custom_final_prompt: str = None) -> str:
        """
        Phương pháp mới: Đưa dữ liệu từ CSV vào context của AI dần dần,
        sau đó yêu cầu phân tích sau khi đã đưa tất cả dữ liệu.
        
        Args:
            csv_file: Đường dẫn đến file CSV chứa gói tin
            chunk_size: Số lượng gói tin mỗi lần gửi vào context
            custom_final_prompt: Prompt tùy chỉnh để gửi sau khi đã đưa toàn bộ dữ liệu
            
        Returns:
            Kết quả phân tích cuối cùng
        """
        try:
            import pandas as pd
            import time
            import os
            from datetime import datetime

            start_time = time.time()
            print(f"Bắt đầu đưa dữ liệu từ {csv_file} vào context của AI...")

            # Đếm tổng số dòng trong file CSV
            total_rows = sum(1 for _ in open(csv_file, 'r', encoding='utf-8')) - 1  # Trừ header
            print(f"Tổng số gói tin cần đưa vào context: {total_rows}")

            # Dữ liệu tổng hợp
            protocol_stats = {}
            total_packets = 0
            chunk_count = 0

            # Đọc từng phần và gửi vào context của AI
            for chunk in pd.read_csv(csv_file, chunksize=chunk_size):
                chunk_count += 1
                chunk_start = time.time()

                print(f"Đang đưa chunk {chunk_count}/{(total_rows + chunk_size - 1) // chunk_size} " +
                      f"({chunk.shape[0]} gói tin) vào context...")

                # Chuyển DataFrame thành danh sách gói tin
                packets = self._convert_df_to_packets(chunk)
                total_packets += len(packets)

                # Cập nhật thống kê giao thức
                for packet in packets:
                    proto = getattr(packet, 'protocol', 'Unknown')
                    protocol_stats[proto] = protocol_stats.get(proto, 0) + 1

                # Tạo summary của chunk này để đưa vào context
                chunk_summary = self._create_chunk_summary(packets, chunk_count, total_packets, protocol_stats)

                # Gửi dữ liệu vào context của AI mà KHÔNG yêu cầu phân tích ngay
                prompt = f"""
                # Chunk dữ liệu mạng #{chunk_count} - CHỈ LƯU VÀO CONTEXT, KHÔNG PHÂN TÍCH

                Đây là phần dữ liệu thứ {chunk_count} từ tổng số dữ liệu.
                Hãy ghi nhớ thông tin này nhưng KHÔNG phân tích ngay. Chỉ trả lời "Đã ghi nhớ dữ liệu chunk {chunk_count}".
                Bạn sẽ được yêu cầu phân tích sau khi nhận tất cả dữ liệu.

                {chunk_summary}
                """

                # Gọi AI để ghi nhớ context (không yêu cầu phân tích)
                response = self.manager_agent.run(prompt)

                chunk_end = time.time()
                print(f"Đã ghi nhớ chunk {chunk_count} vào context trong {chunk_end - chunk_start:.2f} giây")
                print(f"Phản hồi: {response}")

            # Khi đã đưa tất cả dữ liệu vào context, yêu cầu phân tích
            print("\nĐã đưa tất cả dữ liệu vào context. Yêu cầu phân tích...")
            final_analysis_start = time.time()

            # Tạo tóm tắt tổng thể
            overall_summary = self._create_overall_summary(total_packets, protocol_stats)

            # Tạo prompt cuối cùng để yêu cầu phân tích
            if custom_final_prompt:
                final_prompt = custom_final_prompt
            else:
                final_prompt = f"""
                # YÊU CẦU PHÂN TÍCH TOÀN BỘ DỮ LIỆU

                Bạn đã được cung cấp {chunk_count} chunk dữ liệu gói tin mạng, tổng cộng {total_packets} gói tin.
                Hãy sử dụng tất cả dữ liệu đó để phân tích và trả lời theo mô hình OSI:

                {overall_summary}

                Yêu cầu:
                1. Phân tích từng tầng trong mô hình OSI, từ tầng vật lý đến tầng ứng dụng
                2. Xác định các vấn đề bảo mật tiềm ẩn trong dữ liệu mạng
                3. Đánh giá mức độ nghiêm trọng (1-10) cho mỗi vấn đề
                4. Đề xuất giải pháp và khuyến nghị
                5. Đưa ra kết luận tổng thể về tình trạng mạng

                Hãy cung cấp kết quả phân tích theo định dạng JSON như sau:
                ```json
                {{
                  "OSI Layer Analysis": {{
                    "Physical Layer": {{
                      "analysis": "...",
                      "security_issues": ["...", "..."],
                      "severity": 5,
                      "recommendation": ["...", "..."]
                    }},
                    "Data Link Layer": {{
                      // Tương tự như trên
                    }},
                    // Các tầng khác...
                  }},
                  "Conclusion": "Kết luận tổng thể về tình trạng mạng",
                  "New Detection Use Cases": ["Use case 1", "Use case 2"]
                }}
                ```
                """

            # Gọi AI để phân tích
            final_result = self.manager_agent.run(final_prompt)

            final_analysis_end = time.time()
            total_time = final_analysis_end - start_time
            analysis_time = final_analysis_end - final_analysis_start

            print(f"Đã hoàn thành phân tích {total_packets} gói tin sau {total_time:.2f} giây")
            print(f"Thời gian đưa dữ liệu vào context: {final_analysis_start - start_time:.2f} giây")
            print(f"Thời gian phân tích cuối cùng: {analysis_time:.2f} giây")

            # Định dạng và trả về kết quả
            try:
                # Thử chuyển về dict nếu là JSON
                import json
                result_dict = json.loads(final_result)
                return self.format_result_to_markdown(result_dict)
            except (json.JSONDecodeError, TypeError):
                # Nếu không phải JSON, trả về nguyên bản
                return final_result

        except Exception as e:
            error_msg = f"Lỗi khi stream dữ liệu vào AI: {str(e)}"
            print(error_msg)
            return error_msg

    def _create_chunk_summary(self, packets, chunk_num, total_packets_so_far, protocol_stats):
        """
        Tạo tóm tắt cho một chunk dữ liệu để đưa vào context.
        
        Args:
            packets: Danh sách gói tin trong chunk
            chunk_num: Số thứ tự của chunk
            total_packets_so_far: Tổng số gói tin đã xử lý
            protocol_stats: Thống kê giao thức đến hiện tại
            
        Returns:
            Chuỗi tóm tắt về chunk
        """
        # Tạo tóm tắt về phân bố giao thức trong chunk
        chunk_protocols = {}
        for packet in packets:
            proto = getattr(packet, 'protocol', 'Unknown')
            chunk_protocols[proto] = chunk_protocols.get(proto, 0) + 1

        # Thống kê các thuộc tính quan trọng theo giao thức
        tcp_flags = {}
        icmp_types = {}
        arp_operations = {}
        source_ips = set()
        dest_ips = set()

        for packet in packets:
            # Thu thập IPs
            if hasattr(packet, 'src_ip'):
                source_ips.add(packet.src_ip)
            if hasattr(packet, 'dst_ip'):
                dest_ips.add(packet.dst_ip)

            # Thu thập thông tin theo giao thức
            if hasattr(packet, 'protocol'):
                # TCP Flags
                if packet.protocol == 'TCP' and hasattr(packet, 'flags'):
                    flags = packet.flags
                    if flags:
                        for flag in flags.split():
                            tcp_flags[flag] = tcp_flags.get(flag, 0) + 1

                # ICMP Types
                elif packet.protocol == 'ICMP' and hasattr(packet, 'icmp_type'):
                    icmp_type = packet.icmp_type
                    icmp_types[icmp_type] = icmp_types.get(icmp_type, 0) + 1

                # ARP Operations
                elif packet.protocol == 'ARP' and hasattr(packet, 'operation'):
                    operation = packet.operation
                    arp_operations[operation] = arp_operations.get(operation, 0) + 1

        # Tạo chuỗi tóm tắt
        summary = f"""
        ## Tóm tắt chunk #{chunk_num}
        - Số lượng gói tin trong chunk: {len(packets)}
        - Tổng số gói tin đã xử lý: {total_packets_so_far}
        
        ### Phân bố giao thức trong chunk này:
        {', '.join([f"{proto}: {count} gói tin" for proto, count in chunk_protocols.items()])}
        
        ### Phân bố giao thức tổng thể:
        {', '.join([f"{proto}: {count} gói tin" for proto, count in protocol_stats.items()])}
        
        ### Địa chỉ IP:
        - Số lượng IP nguồn khác nhau: {len(source_ips)}
        - Số lượng IP đích khác nhau: {len(dest_ips)}
        """

        # Thêm thông tin TCP flags nếu có
        if tcp_flags:
            summary += "\n### TCP Flags:\n"
            summary += ', '.join([f"{flag}: {count}" for flag, count in tcp_flags.items()])

        # Thêm thông tin ICMP types nếu có
        if icmp_types:
            summary += "\n### ICMP Types:\n"
            summary += ', '.join([f"Type {icmp_type}: {count}" for icmp_type, count in icmp_types.items()])

        # Thêm thông tin ARP operations nếu có
        if arp_operations:
            summary += "\n### ARP Operations:\n"
            summary += ', '.join([f"{op}: {count}" for op, count in arp_operations.items()])

        # Thêm mẫu một số gói tin đại diện
        sample_size = min(5, len(packets))
        if sample_size > 0:
            summary += "\n\n### Mẫu gói tin đại diện:\n"

            # Chọn một số gói tin đại diện từ mỗi giao thức
            protocol_samples = {}
            for packet in packets:
                proto = getattr(packet, 'protocol', 'Unknown')
                if proto not in protocol_samples:
                    protocol_samples[proto] = []
                if len(protocol_samples[proto]) < 2:  # Tối đa 2 mẫu mỗi giao thức
                    protocol_samples[proto].append(packet)

            # Thêm thông tin chi tiết về các gói tin mẫu
            sample_count = 0
            for proto, samples in protocol_samples.items():
                for packet in samples:
                    if sample_count >= sample_size:
                        break

                    summary += f"\n#### Gói tin {proto} #{sample_count + 1}:\n"

                    # Thêm các thuộc tính cơ bản
                    for attr in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'timestamp', 'length']:
                        if hasattr(packet, attr):
                            summary += f"- {attr}: {getattr(packet, attr)}\n"

                    # Thêm thông tin đặc thù theo giao thức
                    if proto == 'TCP' and hasattr(packet, 'flags'):
                        summary += f"- flags: {packet.flags}\n"
                    elif proto == 'ICMP' and hasattr(packet, 'icmp_type'):
                        summary += f"- icmp_type: {packet.icmp_type}\n"
                        if hasattr(packet, 'icmp_code'):
                            summary += f"- icmp_code: {packet.icmp_code}\n"
                    elif proto == 'ARP' and hasattr(packet, 'operation'):
                        summary += f"- operation: {packet.operation}\n"
                        if hasattr(packet, 'sender_ip') and hasattr(packet, 'sender_mac'):
                            summary += f"- sender: {packet.sender_ip} / {packet.sender_mac}\n"
                        if hasattr(packet, 'target_ip') and hasattr(packet, 'target_mac'):
                            summary += f"- target: {packet.target_ip} / {packet.target_mac}\n"

                    sample_count += 1

        return summary

    def _create_overall_summary(self, total_packets, protocol_stats):
        """
        Tạo tóm tắt tổng thể cho toàn bộ dữ liệu.
        
        Args:
            total_packets: Tổng số gói tin
            protocol_stats: Thống kê giao thức
            
        Returns:
            Chuỗi tóm tắt tổng thể
        """
        summary = f"""
        ## Tóm tắt dữ liệu tổng thể
        
        ### Thống kê cơ bản:
        - Tổng số gói tin: {total_packets}
        
        ### Phân bố giao thức:
        """

        for proto, count in protocol_stats.items():
            percentage = (count / total_packets) * 100 if total_packets > 0 else 0
            summary += f"- {proto}: {count} gói tin ({percentage:.2f}%)\n"

        summary += """
        ## Hướng dẫn phân tích

        Dựa trên tất cả các chunk dữ liệu đã được cung cấp, hãy phân tích:
        
        1. Các pranh vi và cường độ lưu lượng mạng
        2. Tỷ lệ của các loại giao thức và ý nghĩa của chúng
        3. Các dấu hiệu bất thường hoặc tấn công tiềm ẩn
        4. Các mẫu lưu lượng đáng nghi ngờ
        5. Phân tích theo từng tầng OSI
        """

        return summary
