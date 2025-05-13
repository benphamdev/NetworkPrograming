"""
OSILayerAnalyzer - Specialized analyzer for OSI model layers in network traffic.
It children the base class Analyzer and implements the analyze method to provide
"""
import json
from typing import Dict, Any, List

from src.infrastructure.repositories.yaml_prompt_repository import YamlPromptRepository
from src.use_cases.prompt_service import PromptService


class OSILayerAnalyzer:
    """Analyzer for network traffic according to the 7-layer OSI model."""

    def __init__(self, manager_agent):
        """
        Initialize the OSI layer analyzer.
        
        Args:
            manager_agent: Agent to use for generating analysis.
        """
        self.manager_agent = manager_agent

    def analyze(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Phân tích lưu lượng mạng theo các tầng của mô hình OSI.
        
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

            # Kiểm tra xem có phải là định dạng OSI Layer Analysis mới không
            # Nếu không, chuyển đổi sang định dạng mới
            if "OSI Layer Analysis" not in analyzed_results:
                # Tạo cấu trúc mới với định dạng phân tích OSI
                new_format = {
                    "OSI Layer Analysis": {}
                }

                # Xử lý kết quả phân tích hiện có
                if "osi_layers" in analyzed_results:
                    # Chuyển đổi từ định dạng osi_layers hiện tại sang OSI Layer Analysis mới
                    osi_data = analyzed_results["osi_layers"]

                    # Map các tầng từ định dạng cũ sang mới
                    layer_mapping = {
                        "physical": "Layer 1 (Physical)",
                        "data_link": "Layer 2 (Data Link)",
                        "network": "Layer 3 (Network)",
                        "transport": "Layer 4 (Transport)",
                        "session": "Layer 5 (Session)",
                        "presentation": "Layer 6 (Presentation)",
                        "application": "Layer 7 (Application)",
                        # Hỗ trợ các biến thể khác
                        "layer_1": "Layer 1 (Physical)",
                        "layer_2": "Layer 2 (Data Link)",
                        "layer_3": "Layer 3 (Network)",
                        "layer_4": "Layer 4 (Transport)",
                        "layer_5": "Layer 5 (Session)",
                        "layer_6": "Layer 6 (Presentation)",
                        "layer_7": "Layer 7 (Application)",
                        "layer1": "Layer 1 (Physical)",
                        "layer2": "Layer 2 (Data Link)",
                        "layer3": "Layer 3 (Network)",
                        "layer4": "Layer 4 (Transport)",
                        "layer5": "Layer 5 (Session)",
                        "layer6": "Layer 6 (Presentation)",
                        "layer7": "Layer 7 (Application)",
                    }

                    # Chuyển đổi dữ liệu từ định dạng cũ sang mới
                    for old_key, layer_data in osi_data.items():
                        # Xác định tên tầng mới
                        new_key = layer_mapping.get(old_key.lower(), old_key)

                        # Khởi tạo dict cho tầng này nếu chưa có
                        if new_key not in new_format["OSI Layer Analysis"]:
                            new_format["OSI Layer Analysis"][new_key] = {}

                        # Chuyển đổi dữ liệu
                        if isinstance(layer_data, str):
                            new_format["OSI Layer Analysis"][new_key]["analysis"] = layer_data
                        elif isinstance(layer_data, dict):
                            # Xử lý các trường dữ liệu từ định dạng cũ
                            if "analysis" in layer_data:
                                new_format["OSI Layer Analysis"][new_key]["analysis"] = layer_data["analysis"]

                            if "issues" in layer_data and layer_data["issues"]:
                                new_format["OSI Layer Analysis"][new_key]["security_issues"] = layer_data[
                                    "issues"] if isinstance(layer_data["issues"], list) else [layer_data["issues"]]

                            if "recommendations" in layer_data:
                                new_format["OSI Layer Analysis"][new_key]["recommendation"] = layer_data[
                                    "recommendations"]
                else:
                    # Nếu không có định dạng osi_layers, tạo cấu trúc mặc định
                    # Phân tích từ nội dung response
                    if "analysis" in analyzed_results:
                        # Chia thành các tầng thông dụng
                        new_format["OSI Layer Analysis"]["Layer 1 (Physical)"] = {
                            "analysis": "Không có dữ liệu cụ thể về tầng vật lý trong log mạng cung cấp",
                            "recommendation": "Kiểm tra chất lượng cáp, tín hiệu và thiết bị vật lý nếu có vấn đề kết nối"
                        }

                        new_format["OSI Layer Analysis"]["Layer 2 (Data Link)"] = {
                            "analysis": "Cần phân tích thêm dữ liệu ARP, MAC để đánh giá tầng này",
                            "recommendation": "Kiểm tra switch, đảm bảo router cấu hình đúng"
                        }

                        new_format["OSI Layer Analysis"]["Layer 3 (Network)"] = {
                            "analysis": "Cần phân tích IP, ICMP và định tuyến để đánh giá tầng này",
                            "recommendation": "Kiểm tra cấu hình định tuyến và firewall"
                        }

                        new_format["OSI Layer Analysis"]["Layer 4 (Transport)"] = {
                            "analysis": "Cần phân tích TCP, UDP để đánh giá tầng này",
                            "recommendation": "Kiểm tra kết nối TCP và UDP, port filtering"
                        }

                        new_format["OSI Layer Analysis"]["Layer 5-7 (Session-Presentation-Application)"] = {
                            "analysis": "Không có đủ dữ liệu để phân tích các tầng cao hơn",
                            "recommendation": ["Thu thập thêm log ứng dụng nếu cần phân tích sâu",
                                               "Kiểm tra các giao thức HTTP/DNS nếu có trong traffic"]
                        }

                        # Thêm thông tin kết luận
                        new_format[
                            "Conclusion"] = "Cần thêm dữ liệu để phân tích chính xác vấn đề mạng. Hãy thu thập thêm packet capture và log từ các thiết bị."

                # Kiểm tra xem có recommendations không
                if "recommendations" in analyzed_results:
                    new_format["New Detection Use Cases"] = analyzed_results["recommendations"]

                return new_format

            # Nếu đã có định dạng OSI Layer Analysis thì trả về trực tiếp
            return analyzed_results

        except (json.JSONDecodeError, TypeError):
            # Nếu không thể parse JSON, tạo cấu trúc mới
            default_result = {
                "OSI Layer Analysis": {
                    "Layer 1 (Physical)": {
                        "analysis": "Không có dữ liệu cụ thể về tầng vật lý trong log mạng cung cấp",
                        "recommendation": "Kiểm tra chất lượng cáp, tín hiệu và thiết bị vật lý nếu có vấn đề kết nối"
                    },
                    "Layer 2 (Data Link)": {
                        "analysis": response,
                        "recommendation": ["Phân tích sâu hơn các gói tin ARP/MAC",
                                           "Kiểm tra switch configuration"]
                    },
                    "Layer 3-7": {
                        "analysis": "Cần phân tích thêm",
                        "recommendation": "Thu thập thêm log ứng dụng"
                    }
                },
                "Conclusion": "Phân tích này chỉ là bước đầu, cần thu thập thêm dữ liệu để phân tích đầy đủ."
            }
            return default_result

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
                
                Định dạng phân tích theo Markdown, với các đề mục rõ ràng và phân cấp phù hợp. Tập trung vào phân tích chuyên sâu.
                """

        return prompt

    def analyze_raw_packets(self, packets: List, custom_prompt: str = None) -> Dict[str, Any]:
        """
        Phân tích danh sách gói tin thô theo mô hình OSI.
        
        Args:
            packets: Danh sách các gói tin cần phân tích
            custom_prompt: Prompt tùy chỉnh để hướng dẫn AI phân tích. Nếu None, sẽ sử dụng prompt mặc định
            
        Returns:
            Kết quả phân tích theo mô hình OSI
        """
        # Tạo prompt từ thông tin gói tin
        prompt = self._build_raw_packet_osi_prompt(packets, custom_prompt)

        # Truy vấn agent
        response = self.manager_agent.run(prompt)

        # Xử lý phản hồi
        try:
            # Cố gắng phân tích JSON nếu có thể
            analyzed_results = json.loads(response)

            # Kiểm tra xem có phải là định dạng OSI Layer Analysis mới không
            # Nếu không, chuyển đổi sang định dạng mới
            if "OSI Layer Analysis" not in analyzed_results:
                # Tạo cấu trúc mới với định dạng phân tích OSI
                new_format = {
                    "OSI Layer Analysis": {}
                }

                # Xử lý kết quả phân tích hiện có
                if "osi_layers" in analyzed_results:
                    # Chuyển đổi từ định dạng osi_layers hiện tại sang OSI Layer Analysis mới
                    osi_data = analyzed_results["osi_layers"]

                    # Map các tầng từ định dạng cũ sang mới
                    layer_mapping = {
                        "physical": "Layer 1 (Physical)",
                        "data_link": "Layer 2 (Data Link)",
                        "network": "Layer 3 (Network)",
                        "transport": "Layer 4 (Transport)",
                        "session": "Layer 5 (Session)",
                        "presentation": "Layer 6 (Presentation)",
                        "application": "Layer 7 (Application)",
                        # Hỗ trợ các biến thể khác
                        "layer_1": "Layer 1 (Physical)",
                        "layer_2": "Layer 2 (Data Link)",
                        "layer_3": "Layer 3 (Network)",
                        "layer_4": "Layer 4 (Transport)",
                        "layer_5": "Layer 5 (Session)",
                        "layer_6": "Layer 6 (Presentation)",
                        "layer_7": "Layer 7 (Application)",
                        "layer1": "Layer 1 (Physical)",
                        "layer2": "Layer 2 (Data Link)",
                        "layer3": "Layer 3 (Network)",
                        "layer4": "Layer 4 (Transport)",
                        "layer5": "Layer 5 (Session)",
                        "layer6": "Layer 6 (Presentation)",
                        "layer7": "Layer 7 (Application)",
                    }

                    # Chuyển đổi dữ liệu từ định dạng cũ sang mới
                    for old_key, layer_data in osi_data.items():
                        # Xác định tên tầng mới
                        new_key = layer_mapping.get(old_key.lower(), old_key)

                        # Khởi tạo dict cho tầng này nếu chưa có
                        if new_key not in new_format["OSI Layer Analysis"]:
                            new_format["OSI Layer Analysis"][new_key] = {}

                        # Chuyển đổi dữ liệu
                        if isinstance(layer_data, str):
                            new_format["OSI Layer Analysis"][new_key]["analysis"] = layer_data
                        elif isinstance(layer_data, dict):
                            # Xử lý các trường dữ liệu từ định dạng cũ
                            if "analysis" in layer_data:
                                new_format["OSI Layer Analysis"][new_key]["analysis"] = layer_data["analysis"]

                            if "issues" in layer_data and layer_data["issues"]:
                                new_format["OSI Layer Analysis"][new_key]["security_issues"] = layer_data[
                                    "issues"] if isinstance(layer_data["issues"], list) else [layer_data["issues"]]

                            if "recommendations" in layer_data:
                                new_format["OSI Layer Analysis"][new_key]["recommendation"] = layer_data[
                                    "recommendations"]
                else:
                    # Nếu không có định dạng osi_layers, phân tích từ nội dung phân tích gói tin

                    # Tạo cấu trúc mẫu cho phân tích gói tin
                    protocols = set()
                    for packet in packets:
                        if hasattr(packet, 'protocol'):
                            protocols.add(packet.protocol)

                    # Thông tin mặc định cho tầng Physical
                    new_format["OSI Layer Analysis"]["Layer 1 (Physical)"] = {
                        "analysis": "Không có dữ liệu cụ thể về tầng vật lý trong các gói tin cung cấp",
                        "recommendation": "Kiểm tra chất lượng cáp, tín hiệu và thiết bị vật lý nếu có vấn đề kết nối"
                    }

                    # Mức độ nghiêm trọng mặc định, sẽ được điều chỉnh theo số lượng vấn đề phát hiện
                    default_severity = 3

                    # Kiểm tra ARP
                    if 'ARP' in protocols:
                        new_format["OSI Layer Analysis"]["Layer 2 (Data Link)"] = {
                            "analysis": "Phân tích gói ARP",
                            "security_issues": ["Kiểm tra các gói ARP để xác định dấu hiệu ARP spoofing"],
                            "severity": default_severity + 1,
                            "recommendation": ["Kiểm tra các gói ARP request/reply",
                                               "Triển khai ARP spoofing detection"]
                        }
                    else:
                        new_format["OSI Layer Analysis"]["Layer 2 (Data Link)"] = {
                            "analysis": "Không tìm thấy gói ARP trong dữ liệu",
                            "recommendation": "Kiểm tra switch configuration và MAC address tables"
                        }

                    # Kiểm tra IP/ICMP
                    ip_issues = []
                    if 'ICMP' in protocols:
                        ip_issues.append("Kiểm tra các gói ICMP để xác định vấn đề kết nối")

                    new_format["OSI Layer Analysis"]["Layer 3 (Network)"] = {
                        "analysis": "Phân tích traffic IP",
                        "security_issues": ip_issues if ip_issues else ["Phân tích routing và firewall configuration"],
                        "severity": default_severity if not ip_issues else default_severity + 2,
                        "recommendation": ["Kiểm tra cấu hình routing và ICMP filtering"]
                    }

                    # Kiểm tra TCP/UDP
                    transport_issues = []
                    if 'TCP' in protocols:
                        transport_issues.append("Phân tích TCP handshake và TCP flags")
                    if 'UDP' in protocols:
                        transport_issues.append("Kiểm tra UDP traffic và port availability")

                    new_format["OSI Layer Analysis"]["Layer 4 (Transport)"] = {
                        "analysis": "Phân tích gói tin TCP/UDP",
                        "security_issues": transport_issues if transport_issues else [
                            "Kiểm tra trạng thái port và kết nối"],
                        "severity": default_severity if not transport_issues else default_severity + 1,
                        "recommendation": ["Kiểm tra firewall stateful inspection", "Phân tích TCP state machine"]
                    }

                    # Thông tin mặc định cho tầng cao hơn
                    new_format["OSI Layer Analysis"]["Layer 5-7 (Session-Presentation-Application)"] = {
                        "analysis": "Không có đủ dữ liệu để phân tích các tầng cao hơn",
                        "recommendation": ["Thu thập thêm log ứng dụng nếu cần phân tích sâu",
                                           "Kiểm tra các giao thức HTTP/DNS nếu có trong traffic"]
                    }

                    # Nếu có phân tích trong kết quả, thêm vào kết luận
                    if "analysis" in analyzed_results:
                        new_format["Conclusion"] = analyzed_results["analysis"]
                    else:
                        new_format["Conclusion"] = "Cần phân tích sâu hơn để xác định chính xác vấn đề mạng"

                # Thêm Use Cases nếu có recommendations
                if "recommendations" in analyzed_results:
                    new_format["New Detection Use Cases"] = analyzed_results["recommendations"]
                else:
                    new_format["New Detection Use Cases"] = [
                        "Tự động phát hiện ARP spoofing từ packet capture",
                        "Phát hiện port scan từ phân tích TCP flags",
                        "Phân tích ICMP Unreachable messages để phát hiện network scanning",
                        "Xây dựng baseline behavior để phát hiện connection anomalies"
                    ]

                # Thêm kết luận nếu chưa có
                if "Conclusion" not in new_format and "summary" in analyzed_results:
                    new_format["Conclusion"] = analyzed_results["summary"]

                return new_format

            # Nếu đã có định dạng OSI Layer Analysis thì trả về trực tiếp
            return analyzed_results

        except (json.JSONDecodeError, TypeError):
            # Nếu không thể parse JSON, sử dụng phản hồi dạng văn bản để tạo cấu trúc mới
            default_result = {
                "OSI Layer Analysis": {
                    "Layer 1 (Physical)": {
                        "analysis": "Không có dữ liệu cụ thể về tầng vật lý trong các gói tin cung cấp",
                        "recommendation": "Kiểm tra chất lượng cáp, tín hiệu và thiết bị vật lý nếu có vấn đề kết nối"
                    },
                    "Layer 2 (Data Link)": {
                        "analysis": "Phân tích gói tin Data Link",
                        "security_issues": ["Kiểm tra ARP spoofing", "Kiểm tra MAC flooding"],
                        "severity": 4,
                        "recommendation": ["Triển khai ARP inspection", "Bảo mật switch port"]
                    },
                    "Layer 3 (Network)": {
                        "analysis": "Phân tích gói tin Network",
                        "security_issues": ["Kiểm tra IP spoofing", "Phân tích ICMP Unreachable"],
                        "severity": 5,
                        "recommendation": ["Triển khai anti-spoofing", "Kiểm tra cấu hình firewall"]
                    },
                    "Layer 4 (Transport)": {
                        "analysis": "Phân tích gói tin Transport",
                        "security_issues": ["Kiểm tra TCP scan", "Phân tích UDP traffic"],
                        "severity": 4,
                        "recommendation": ["Kiểm tra TCP state", "Giám sát UDP traffic"]
                    },
                    "Layer 5-7 (Session-Presentation-Application)": {
                        "analysis": "Không có đủ dữ liệu để phân tích các tầng cao hơn",
                        "recommendation": ["Thu thập thêm log ứng dụng nếu cần phân tích sâu"]
                    }
                },
                "Conclusion": "Cần phân tích thêm để xác định chính xác vấn đề. Phát hiện ban đầu cho thấy dấu hiệu ARP/IP scanning.",
                "New Detection Use Cases": [
                    "Phát hiện ARP scan tự động bằng machine learning",
                    "Giám sát hành vi bất thường kết hợp nhiều tầng mạng",
                    "Phân tích tương quan giữa ICMP Unreachable và port scan",
                    "Xây dựng baseline network behavior để phát hiện anomaly"
                ]
            }
            return default_result

    def _build_raw_packet_osi_prompt(self, packets: List, custom_prompt: str = None) -> str:
        """
        Xây dựng prompt để phân tích các gói tin thô theo mô hình OSI.
        
        Args:
            packets: Danh sách các gói tin thô
            custom_prompt: Prompt tùy chỉnh (nếu có)
            
        Returns:
            Prompt string
        """
        if custom_prompt:
            base_prompt = custom_prompt
        else:
            base_prompt = """
            Là một kỹ sư mạng (Network Engineer) chuyên nghiệp, hãy phân tích chi tiết các gói tin mạng dưới đây theo mô hình OSI để debug các vấn đề kết nối và phát hiện các cuộc tấn công tiềm tàng.

            ## Mục tiêu phân tích:
            1. Debug các vấn đề kết nối mạng - phân tích tại sao các thiết bị không ping được đến nhau
            2. Xác định chính xác thành phần mạng nào đang gặp trục trặc (Router, Switch, Firewall, DNS, v.v.)
            3. Phát hiện dấu hiệu của các cuộc tấn công mạng đang diễn ra
            4. Đề xuất các biện pháp khắc phục cụ thể cho từng loại vấn đề
            
            Dưới đây là dữ liệu gói tin cần phân tích:
            """

        prompt = base_prompt + "\n\n"

        # Thêm thông tin tổng quan
        prompt += f"## Tổng quan\n"
        prompt += f"- Tổng số gói tin: {len(packets)}\n"

        # Thống kê giao thức
        protocols = {}
        port_counter = {}
        source_ips = set()
        dest_ips = set()
        hosts_with_issues = {}

        # Thống kê chi tiết hơn
        for packet in packets:
            # Đếm giao thức
            proto = getattr(packet, 'protocol', 'Unknown')
            protocols[proto] = protocols.get(proto, 0) + 1

            # Thu thập thông tin IP
            if hasattr(packet, 'src_ip'):
                source_ips.add(packet.src_ip)
            if hasattr(packet, 'dst_ip'):
                dest_ips.add(packet.dst_ip)

            # Theo dõi cổng
            if hasattr(packet, 'src_port') and hasattr(packet, 'dst_port'):
                port_key = f"{packet.src_port}->{packet.dst_port}"
                port_counter[port_key] = port_counter.get(port_key, 0) + 1

            # Kiểm tra dấu hiệu của vấn đề kết nối
            if proto == 'TCP' and hasattr(packet, 'flags'):
                # Kiểm tra RST flag
                if 'RST' in packet.flags:
                    src_ip = getattr(packet, 'src_ip', 'unknown')
                    dst_ip = getattr(packet, 'dst_ip', 'unknown')
                    src_port = getattr(packet, 'src_port', 'unknown')
                    dst_port = getattr(packet, 'dst_port', 'unknown')
                    conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    if conn_key not in hosts_with_issues:
                        hosts_with_issues[conn_key] = {'type': 'TCP RST', 'count': 1}
                    else:
                        hosts_with_issues[conn_key]['count'] += 1

            # Kiểm tra ICMP unreachable
            elif proto == 'ICMP' and hasattr(packet, 'icmp_type'):
                if getattr(packet, 'icmp_type') == 3:  # Destination Unreachable
                    src_ip = getattr(packet, 'src_ip', 'unknown')
                    dst_ip = getattr(packet, 'dst_ip', 'unknown')
                    conn_key = f"{src_ip}-{dst_ip}"
                    code = getattr(packet, 'icmp_code', 'unknown')
                    if conn_key not in hosts_with_issues:
                        hosts_with_issues[conn_key] = {'type': f'ICMP Unreachable (code {code})', 'count': 1}
                    else:
                        hosts_with_issues[conn_key]['count'] += 1

        prompt += f"- Số lượng IP nguồn: {len(source_ips)}\n"
        prompt += f"- Số lượng IP đích: {len(dest_ips)}\n"

        # Thêm thống kê giao thức
        prompt += "\n## Thống kê giao thức\n"
        for proto, count in protocols.items():
            prompt += f"- {proto}: {count} gói tin\n"

        # Thêm thông tin về các vấn đề kết nối
        if hosts_with_issues:
            prompt += "\n## Dấu hiệu vấn đề kết nối\n"
            for conn, issue in hosts_with_issues.items():
                prompt += f"- {conn}: {issue['type']} (số lượng: {issue['count']})\n"

        # Thêm thông tin chi tiết về gói tin (tăng số lượng mẫu lên 15)
        prompt += "\n## Chi tiết gói tin (mẫu)\n"
        for i, packet in enumerate(packets[:15]):
            prompt += f"\n### Gói tin #{i + 1}\n"

            # Thông tin cơ bản
            for attr in ['protocol', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'timestamp', 'length']:
                if hasattr(packet, attr):
                    prompt += f"- {attr}: {getattr(packet, attr)}\n"

            # Thông tin chi tiết theo giao thức
            if hasattr(packet, 'protocol'):
                if packet.protocol == 'TCP':
                    # Thông tin TCP flags
                    if hasattr(packet, 'flags'):
                        prompt += f"- TCP flags: {packet.flags}\n"
                    # TCP sequence và ack number
                    for attr in ['seq_num', 'ack_num', 'window_size', 'data_offset', 'checksum']:
                        if hasattr(packet, attr):
                            prompt += f"- {attr}: {getattr(packet, attr)}\n"

                elif packet.protocol == 'ICMP':
                    # Thông tin ICMP
                    for attr in ['icmp_type', 'icmp_code', 'icmp_id', 'icmp_seq', 'checksum']:
                        if hasattr(packet, attr):
                            prompt += f"- {attr}: {getattr(packet, attr)}\n"

                elif packet.protocol == 'ARP':
                    # Thông tin ARP
                    for attr in ['src_mac', 'dst_mac', 'sender_ip', 'sender_mac', 'target_ip', 'target_mac',
                                 'operation']:
                        if hasattr(packet, attr):
                            prompt += f"- {attr}: {getattr(packet, attr)}\n"

                elif packet.protocol == 'DNS':
                    # Thông tin DNS
                    for attr in ['query_name', 'query_type', 'answer', 'response_code', 'id', 'flags']:
                        if hasattr(packet, attr):
                            prompt += f"- {attr}: {getattr(packet, attr)}\n"

                # Thông tin payload nếu có
                if hasattr(packet, 'payload') and getattr(packet, 'payload', None):
                    payload = getattr(packet, 'payload')
                    if isinstance(payload, str) and len(payload) > 100:
                        prompt += f"- payload: {payload[:100]}... (truncated)\n"
                    else:
                        prompt += f"- payload: {payload}\n"

        if len(packets) > 15:
            prompt += f"\n*... và {len(packets) - 15} gói tin khác ...*\n"

        # load prompt from file yaml
        # Khởi tạo PromptService
        prompt_dir: str = "src/infrastructure/prompts"
        prompt_repository = YamlPromptRepository(prompt_dir)
        self.prompt_service = PromptService(prompt_repository)
        prompt += self.prompt_service.get_formatted_prompt("raw_packet_analysis", {}, "osi_analysis")

        return prompt
