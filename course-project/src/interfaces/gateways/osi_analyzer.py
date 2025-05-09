"""
OSILayerAnalyzer - Specialized analyzer for OSI model layers in network traffic.
It children the base class Analyzer and implements the analyze method to provide
"""
from typing import Dict, Any, List
import json

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
        except (json.JSONDecodeError, TypeError):
            # Nếu không, sử dụng phản hồi gốc
            analyzed_results = {"analysis": response}
        
        return analyzed_results
    
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
            prompt += f"\n### Gói tin #{i+1}\n"
            
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
                    for attr in ['src_mac', 'dst_mac', 'sender_ip', 'sender_mac', 'target_ip', 'target_mac', 'operation']:
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
        
        # Thêm hướng dẫn phân tích theo mô hình OSI
        prompt += """
        \n## Phân tích theo mô hình OSI
        Hãy phân tích lưu lượng mạng theo 7 tầng của mô hình OSI, tập trung vào các vấn đề kết nối và dấu hiệu tấn công:
                
        ### 1. Tầng Vật lý (Physical Layer)
        - Xác định các dấu hiệu của vấn đề vật lý (nếu có thể suy luận từ dữ liệu gói tin)
        - Các vấn đề về độ trễ, mất gói tin, và truyền dẫn
                
        ### 2. Tầng Liên kết dữ liệu (Data Link Layer)
        - Phân tích các vấn đề liên quan đến MAC, ARP cache, và broadcast/multicast
        - Phát hiện các tấn công ARP poisoning, MAC flooding, MAC spoofing
        - Xác định các vấn đề VLAN
                
        ### 3. Tầng Mạng (Network Layer)
        - Phân tích định tuyến IP, fragment, TTL, và các vấn đề ICMP
        - Phát hiện lỗi định tuyến, vấn đề NAT, và cấu hình firewall
        - Phát hiện tấn công: IP spoofing, ICMP tunneling/flooding
                
        ### 4. Tầng Giao vận (Transport Layer)
        - Phân tích chi tiết về TCP handshake, cờ, cổng, và thứ tự gói tin
        - Phân tích các vấn đề kết nối: RST packets, retransmissions, window size
        - Phát hiện tấn công: SYN flood, RST attack, session hijacking, port scanning

        ### 5. Tầng Phiên và Trình diễn (Session & Presentation Layers)
        - Phân tích các vấn đề thiết lập và duy trì phiên
        - Phát hiện các vấn đề mã hóa, SSL/TLS, và chuyển đổi dữ liệu
                
        ### 6. Tầng Ứng dụng (Application Layer)
        - Phân tích các giao thức ứng dụng: HTTP, DNS, DHCP, FTP...
        - Xác định các vấn đề ứng dụng, timeout, và lỗi phản hồi
        - Phát hiện tấn công: DNS cache poisoning, HTTP flood, DHCP starvation
                
        ## Kết luận và Giải pháp
        1. Tóm tắt các vấn đề kết nối mạng chính đã phát hiện
        2. Xác định chính xác thành phần nào của mạng đang gặp trục trặc
        3. Các dấu hiệu tấn công mạng đã phát hiện và mức độ nghiêm trọng
        4. Đề xuất các lệnh và công cụ debug cụ thể để xác minh và khắc phục vấn đề
        5. Hướng dẫn chi tiết để khắc phục các vấn đề đã phát hiện
        """
        
        return prompt