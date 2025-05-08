"""
SummaryCreator - Tạo các tóm tắt phân tích từ dữ liệu PCAP.
"""
from typing import Dict, List

class SummaryCreator:
    """Tạo các tóm tắt phân tích từ dữ liệu PCAP."""
    
    def create_file_summary(self, results: Dict, file_name: str) -> str:
        """
        Tạo tóm tắt về nội dung của file PCAP.
        
        Args:
            results: Kết quả phân tích từ file PCAP
            file_name: Tên file PCAP
            
        Returns:
            Tóm tắt về nội dung file
        """
        summary = f"## Tóm tắt file PCAP: {file_name}\n\n"

        # Thống kê cơ bản
        if "packet_count" in results:
            summary += f"- Tổng số gói tin: {results['packet_count']}\n"

        # Thống kê giao thức
        if "protocol_statistics" in results:
            proto_stats = results["protocol_statistics"]
            top_protocols = sorted(proto_stats.items(), key=lambda x: x[1], reverse=True)[:3]
            proto_list = ", ".join([f"{proto} ({count} gói)" for proto, count in top_protocols])
            summary += f"- Giao thức chính: {proto_list}\n"

        # Thống kê cuộc tấn công
        attacks = results.get("attacks", [])
        if attacks:
            attack_types = set(a.get("attack_type", "Unknown") for a in attacks)
            summary += f"- ⚠️ Phát hiện {len(attacks)} cuộc tấn công thuộc {len(attack_types)} loại\n"

            # Liệt kê các loại tấn công
            attack_list = ", ".join(attack_types)
            summary += f"- Loại tấn công: {attack_list}\n"
        else:
            summary += "- ✅ Không phát hiện tấn công nào\n"

        # Thống kê luồng
        if "flow_statistics" in results:
            flow_stats = results["flow_statistics"]
            summary += f"- Tổng số luồng TCP: {flow_stats.get('total_flows', 0)}\n"
            summary += f"- Luồng đã thiết lập: {flow_stats.get('established_count', 0)}\n"

            # Phân tích tỷ lệ reset
            total_flows = flow_stats.get("total_flows", 0)
            reset_count = flow_stats.get("reset_count", 0)
            if total_flows > 0:
                reset_percent = (reset_count / total_flows) * 100
                if reset_percent > 20:
                    summary += f"- ⚠️ Tỷ lệ kết nối đặt lại cao: {reset_percent:.1f}%\n"
                else:
                    summary += f"- Tỷ lệ kết nối đặt lại: {reset_percent:.1f}%\n"

        # Kết luận và hướng dẫn
        summary += "\n### Hành động đề xuất:\n"

        if attacks:
            summary += "1. **Phân tích rủi ro mạng** - Hỏi tôi về 'phân tích rủi ro trong file này'\n"
            summary += "2. **Tìm hiểu biện pháp giảm thiểu** - Hỏi tôi về 'cách giảm thiểu các cuộc tấn công'\n"
        else:
            summary += "1. **Kiểm tra hiệu suất mạng** - Hỏi tôi về 'phân tích kết nối TCP'\n"
            summary += "2. **Xem xét phân bố giao thức** - Hỏi tôi về 'phân tích giao thức mạng'\n"

        summary += "3. **Phân tích theo mô hình OSI** - Hỏi tôi về 'phân tích theo mô hình OSI'\n"
        summary += "4. **Nên tiếp tục giám sát mạng** - Tải lên thêm file PCAP để phân tích dài hạn\n"

        return summary
        
    def create_risk_summary(self, results: Dict) -> List[Dict]:
        """
        Tạo tóm tắt về các rủi ro an ninh mạng từ kết quả phân tích.
        
        Args:
            results: Kết quả phân tích PCAP
            
        Returns:
            Danh sách các rủi ro được xác định
        """
        risks = []

        # Kiểm tra các cuộc tấn công
        attacks = results.get("attacks", [])
        if attacks:
            risks.append({
                "type": "Rủi ro bảo mật cao",
                "description": f"Đã phát hiện {len(attacks)} cuộc tấn công trong lưu lượng mạng",
                "impact": "Có thể dẫn đến mất dữ liệu, gián đoạn dịch vụ, hoặc xâm phạm hệ thống",
                "remediation": "Triển khai các biện pháp phòng thủ như firewall, IDS/IPS, và cập nhật bảo mật"
            })

            # Kiểm tra có tấn công ARP không
            arp_attacks = [a for a in attacks if "ARP" in a.get("attack_type", "")]
            if arp_attacks:
                risks.append({
                    "type": "Rủi ro giả mạo ARP (man-in-the-middle)",
                    "description": f"Phát hiện {len(arp_attacks)} cuộc tấn công ARP spoofing",
                    "impact": "Kẻ tấn công có thể chặn lưu lượng mạng, đánh cắp thông tin nhạy cảm, và thay đổi dữ liệu",
                    "remediation": "Sử dụng ARP tĩnh, Dynamic ARP Inspection, và mã hóa lưu lượng mạng"
                })

        # Kiểm tra tỉ lệ kết nối TCP đặt lại
        if "flow_statistics" in results:
            flow_stats = results["flow_statistics"]
            total_flows = flow_stats.get("total_flows", 0)
            reset_count = flow_stats.get("reset_count", 0)

            if total_flows > 0 and (reset_count / total_flows > 0.2):  # Nếu tỷ lệ RST > 20%
                risks.append({
                    "type": "Rủi ro về hiệu suất mạng",
                    "description": f"Tỷ lệ kết nối bị đặt lại cao ({(reset_count/total_flows*100):.1f}%)",
                    "impact": "Có thể dẫn đến giảm hiệu suất ứng dụng, timeout, và trải nghiệm người dùng kém",
                    "remediation": "Kiểm tra cấu hình mạng, giảm tắc nghẽn, và tối ưu hóa thông số TCP"
                })

        # Kiểm tra phân bố giao thức bất thường
        if "protocol_statistics" in results:
            proto_stats = results["protocol_statistics"]
            total_packets = sum(proto_stats.values())

            # Nếu có quá nhiều gói tin ICMP (>10%), có thể có vấn đề
            if "ICMP" in proto_stats and total_packets > 0:
                icmp_percent = proto_stats["ICMP"] / total_packets * 100
                if icmp_percent > 10:
                    risks.append({
                        "type": "Rủi ro về định tuyến/kết nối",
                        "description": f"Lượng gói tin ICMP cao bất thường ({icmp_percent:.1f}%)",
                        "impact": "Có thể chỉ ra vấn đề về cấu hình định tuyến hoặc tấn công ICMP flood",
                        "remediation": "Kiểm tra cấu hình định tuyến và chính sách bảo mật cho ICMP"
                    })

        # Nếu không tìm thấy rủi ro cụ thể, thêm một rủi ro chung
        if not risks:
            risks.append({
                "type": "Rủi ro mạng chung",
                "description": "Không phát hiện rủi ro nghiêm trọng nào trong lưu lượng mạng đã phân tích",
                "impact": "Rủi ro thấp với mạng và dịch vụ của bạn dựa trên dữ liệu hiện tại",
                "remediation": "Tiếp tục giám sát và duy trì các biện pháp bảo mật hiện tại"
            })

        return risks
    
    def format_risk_summary(self, risks: List[Dict], file_name: str) -> str:
        """
        Định dạng tóm tắt rủi ro thành chuỗi dễ đọc.
        
        Args:
            risks: Danh sách rủi ro
            file_name: Tên file PCAP
            
        Returns:
            Chuỗi định dạng tóm tắt rủi ro
        """
        response = f"Dựa trên phân tích file {file_name}, tôi đã xác định {len(risks)} rủi ro chính:\n\n"

        for i, risk in enumerate(risks, 1):
            response += f"**{i}. {risk['type']}**\n"
            response += f"- *Mô tả:* {risk['description']}\n"
            response += f"- *Tác động:* {risk['impact']}\n"
            response += f"- *Khuyến nghị:* {risk['remediation']}\n\n"

        response += "Bạn có muốn biết thêm chi tiết về bất kỳ rủi ro cụ thể nào không?"
        return response 