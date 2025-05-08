"""
Analyzer Component - Xử lý phân tích PCAP và tạo báo cáo
"""
from typing import Dict, Tuple, List
import os
from src.interfaces.presenters.base_presenter import BasePresenter
from src.interfaces.presenters.chart_creator import ChartCreator
from src.interfaces.gateways.smolagent_gateway import SmolagentGateway
import pandas as pd

class AnalyzerComponent:
    """Component xử lý phân tích PCAP và tạo báo cáo."""

    def __init__(self, base_presenter: BasePresenter):
        """
        Khởi tạo analyzer component.
        
        Args:
            base_presenter: Instance BasePresenter
        """
        self.base_presenter = base_presenter
        self.chart_creator = ChartCreator()
        self.chat_history = []
        self.smolagent_gateway = SmolagentGateway()

    def create_osi_analysis(self, results: Dict) -> str:
        """
        Tạo phân tích AI cho lưu lượng mạng theo mô hình OSI sử dụng SmolagentGateway.
        
        Args:
            results: Kết quả phân tích từ file PCAP
            
        Returns:
            Phân tích chi tiết theo mô hình OSI
        """
        if not results:
            return "Không có dữ liệu để phân tích. Vui lòng tải lên file PCAP trước."

        try:
            # Gọi smolagent_gateway để phân tích
            osi_analysis = self.smolagent_gateway.analyze_osi_layers(results)
            
            # Kiểm tra kết quả và trả về phân tích
            if isinstance(osi_analysis, dict) and "analysis" in osi_analysis:
                return osi_analysis["analysis"]
            elif isinstance(osi_analysis, str):
                return osi_analysis
            else:
                return "## Phân tích theo mô hình OSI\n\n" + str(osi_analysis)
        except Exception as e:
            return f"## Lỗi khi phân tích theo mô hình OSI\n\nĐã xảy ra lỗi khi phân tích: {str(e)}"

    def create_ai_chat_response(self, query: str, results: Dict) -> str:
        """
        Tạo phản hồi cho hội thoại chat dựa trên truy vấn của người dùng và kết quả phân tích từ file PCAP đã tải lên.
        
        Args:
            query: Truy vấn của người dùng
            results: Kết quả phân tích PCAP từ file đã tải lên
            
        Returns:
            Phản hồi được tạo bởi AI
        """
        if not results:
            return "Tôi không có dữ liệu nào để phân tích. Vui lòng tải lên file PCAP trước."

        query_lower = query.lower()

        # Xử lý truy vấn về file cụ thể
        if "file này" in query_lower or "dữ liệu này" in query_lower or "pcap này" in query_lower:
            # Thêm logic xử lý truy vấn về file hiện tại
            pcap_file = self.base_presenter.latest_pcap_file
            file_name = os.path.basename(pcap_file) if pcap_file else "không xác định"

            if "có gì" in query_lower or "chứa gì" in query_lower or "tóm tắt" in query_lower:
                return self._create_file_summary(results, file_name)

        # Xử lý truy vấn về tấn công ARP cụ thể
        if "arp" in query_lower or "spoofing" in query_lower or "giả mạo arp" in query_lower:
            attacks = results.get("attacks", [])
            arp_attacks = [a for a in attacks if "ARP" in a.get("attack_type", "")]

            if not arp_attacks:
                return "Không phát hiện tấn công ARP spoofing nào trong file PCAP đã phân tích. ARP spoofing là kỹ thuật tấn công mạn trong mạng, trong đó kẻ tấn công gửi các gói tin ARP giả mạo để liên kết địa chỉ MAC của họ với địa chỉ IP của máy chủ hợp pháp trong mạng."

            file_name = os.path.basename(self.base_presenter.latest_pcap_file) if self.base_presenter.latest_pcap_file else "đã tải lên"
            response = f"Trong file {file_name}, tôi đã phát hiện {len(arp_attacks)} cuộc tấn công ARP Spoofing:\n\n"

            for i, attack in enumerate(arp_attacks, 1):
                # Trích xuất thông tin chi tiết từ attack
                timestamp = attack.get("timestamp", "không xác định")
                severity = attack.get("severity", 0)
                spoofed_mac = attack.get("spoofed_mac", "không xác định")
                real_mac = attack.get("real_mac", "không xác định")
                target_ip = attack.get("target_ips", ["không xác định"])[0]

                response += f"**Tấn công {i}:**\n"
                response += f"- Thời gian: {timestamp}\n"
                response += f"- Mức độ nghiêm trọng: {severity}/10\n"
                response += f"- IP bị tấn công: {target_ip}\n"
                response += f"- MAC hợp pháp: {real_mac}\n"
                response += f"- MAC giả mạo: {spoofed_mac}\n"

                # Thêm cảnh báo đặc biệt nếu là gateway
                if target_ip.endswith(".1") or target_ip.endswith(".254"):
                    response += f"- ⚠️ **CẢNH BÁO ĐẶC BIỆT**: Đây có thể là tấn công vào gateway ({target_ip}), có thể dẫn đến tấn công Man-in-the-Middle đối với tất cả lưu lượng mạng!\n"

                response += "\n"

            # Thêm giải thích và các biện pháp khắc phục
            response += "**Giải thích về tấn công ARP Spoofing:**\n"
            response += "ARP Spoofing là kỹ thuật tấn công trong đó kẻ tấn công gửi các gói tin ARP giả mạo để liên kết địa chỉ MAC của họ với địa chỉ IP của một máy chủ hợp pháp. Điều này cho phép kẻ tấn công chặn, sửa đổi hoặc ngừng dữ liệu đang được truyền.\n\n"

            response += "**Các biện pháp phòng chống:**\n"
            response += "1. Sử dụng ARP tĩnh (static ARP) cho các máy chủ quan trọng\n"
            response += "2. Triển khai Dynamic ARP Inspection (DAI) trên switch\n"
            response += "3. Sử dụng các giải pháp như VPN hoặc IPsec để mã hóa lưu lượng mạng\n"
            response += "4. Triển khai các giải pháp phát hiện xâm nhập (IDS/IPS)\n"
            response += "5. Sử dụng các công cụ giám sát ARP như ArpWatch\n"

            return response

        # Phản hồi cho các truy vấn về rủi ro mạng
        if "rủi ro" in query_lower or "nguy cơ" in query_lower or "risk" in query_lower:
            # Phân tích rủi ro dựa trên dữ liệu
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

            # Tạo phản hồi chi tiết
            file_name = os.path.basename(self.base_presenter.latest_pcap_file) if self.base_presenter.latest_pcap_file else "đã tải lên"
            response = f"Dựa trên phân tích file {file_name}, tôi đã xác định {len(risks)} rủi ro chính:\n\n"

            for i, risk in enumerate(risks, 1):
                response += f"**{i}. {risk['type']}**\n"
                response += f"- *Mô tả:* {risk['description']}\n"
                response += f"- *Tác động:* {risk['impact']}\n"
                response += f"- *Khuyến nghị:* {risk['remediation']}\n\n"

            response += "Bạn có muốn biết thêm chi tiết về bất kỳ rủi ro cụ thể nào không?"
            return response

        # Phản hồi dựa trên các từ khóa trong truy vấn
        elif "tấn công" in query_lower or "attack" in query_lower:
            attacks = results.get("attacks", [])
            if not attacks:
                return f"Không phát hiện tấn công nào trong file PCAP đã phân tích."

            attack_types = set(a.get("attack_type", "Unknown") for a in attacks)
            file_name = os.path.basename(self.base_presenter.latest_pcap_file) if self.base_presenter.latest_pcap_file else "đã tải lên"
            response = f"Trong file {file_name}, tôi đã phát hiện {len(attacks)} cuộc tấn công thuộc {len(attack_types)} loại: {', '.join(attack_types)}. "

            # Phân tích chi tiết cuộc tấn công nghiêm trọng nhất
            most_severe = max(attacks, key=lambda a: a.get("severity", 0), default=None)
            if most_severe:
                response += f"\n\nCuộc tấn công nghiêm trọng nhất là {most_severe.get('attack_type')}, "
                response += f"xảy ra vào lúc {most_severe.get('timestamp')}. "
                response += f"Mức độ nghiêm trọng: {most_severe.get('severity')}/10. "

                if "src_ip" in most_severe and "dst_ip" in most_severe:
                    response += f"\nNguồn tấn công: {most_severe.get('src_ip')} → Đích: {most_severe.get('dst_ip')}"

                response += "\n\nHãy hỏi tôi nếu bạn muốn biết thêm về cách giảm thiểu tấn công này."

            return response

        elif "tcp" in query_lower or "kết nối" in query_lower:
            tcp_analysis = self.create_osi_analysis(results)
            # Thêm thông tin về file đang được phân tích
            file_name = os.path.basename(self.base_presenter.latest_pcap_file) if self.base_presenter.latest_pcap_file else "đã tải lên"
            return f"Phân tích lưu lượng mạng theo mô hình OSI từ file {file_name}:\n\n{tcp_analysis}"

        elif "giao thức" in query_lower or "protocol" in query_lower:
            if "protocol_statistics" in results:
                proto_stats = results["protocol_statistics"]
                top_protocols = sorted(proto_stats.items(), key=lambda x: x[1], reverse=True)[:5]

                file_name = os.path.basename(self.base_presenter.latest_pcap_file) if self.base_presenter.latest_pcap_file else "đã tải lên"
                response = f"Phân tích giao thức từ file {file_name}:\n\n"

                for proto, count in top_protocols:
                    response += f"- {proto}: {count} gói tin\n"

                response += "\nGiao thức chính được sử dụng là " + top_protocols[0][0]
                return response
            return "Không có thông tin về phân bố giao thức trong dữ liệu."

        elif "osi" in query_lower or "mô hình osi" in query_lower:
            # Trả về phân tích mô hình OSI khi được yêu cầu cụ thể
            osi_analysis = self.create_osi_analysis(results)
            file_name = os.path.basename(self.base_presenter.latest_pcap_file) if self.base_presenter.latest_pcap_file else "đã tải lên"
            return f"Phân tích lưu lượng mạng theo mô hình OSI từ file {file_name}:\n\n{osi_analysis}"

        elif "giảm thiểu" in query_lower or "mitigate" in query_lower or "phòng chống" in query_lower:
            attacks = results.get("attacks", [])
            if not attacks:
                return "Không phát hiện tấn công nào để đưa ra biện pháp giảm thiểu."

            file_name = os.path.basename(self.base_presenter.latest_pcap_file) if self.base_presenter.latest_pcap_file else "đã tải lên"
            response = f"Biện pháp giảm thiểu cho các cuộc tấn công trong file {file_name}:\n\n"

            attack_types = set(a.get("attack_type", "") for a in attacks)

            if any("SYN Flood" in at for at in attack_types):
                response += "**Cho tấn công SYN Flood:**\n"
                response += "- Áp dụng SYN cookies hoặc SYN cache\n"
                response += "- Tăng hàng đợi SYN backlog\n"
                response += "- Giảm thời gian chờ SYN-RECEIVED\n"
                response += "- Sử dụng tường lửa hoặc IPS để lọc lưu lượng đáng ngờ\n\n"

            if any("RST" in at for at in attack_types):
                response += "**Cho tấn công RST:**\n"
                response += "- Triển khai xác thực gói tin\n"
                response += "- Sử dụng VPN hoặc IPsec để bảo vệ kết nối\n"
                response += "- Cập nhật phần mềm và firmware cho router/firewall\n\n"

            if any("Scan" in at for at in attack_types or "Quét" in at for at in attack_types):
                response += "**Cho hoạt động quét cổng:**\n"
                response += "- Đóng các cổng không sử dụng\n"
                response += "- Triển khai tường lửa với cấu hình thích hợp\n"
                response += "- Sử dụng IDS/IPS để phát hiện hoạt động quét\n"
                response += "- Hạn chế phản hồi ICMP\n\n"

            response += "**Biện pháp chung:**\n"
            response += "- Giám sát mạng liên tục\n"
            response += "- Cập nhật tất cả phần mềm bảo mật\n"
            response += "- Triển khai giải pháp phát hiện xâm nhập\n"

            return response

        # Trường hợp mặc định nếu không có từ khóa phù hợp
        try:
            # Gọi trực tiếp đến deepseek model thông qua phương thức direct_query
            return self.smolagent_gateway.direct_query(query)
        except Exception as e:
            # Nếu có lỗi, sử dụng phản hồi mặc định
            file_name = os.path.basename(self.base_presenter.latest_pcap_file) if self.base_presenter.latest_pcap_file else "đã tải lên"
            return (
                f"Tôi có thể cung cấp phân tích chi tiết về file PCAP {file_name}. "
                "Hãy hỏi tôi về: tấn công phát hiện được, phân tích mạng theo mô hình OSI, phân bố giao thức, "
                "rủi ro mạng, hoặc biện pháp giảm thiểu tấn công."
            )

    def _create_file_summary(self, results: Dict, file_name: str) -> str:
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

        summary += "3. **Nên tiếp tục giám sát mạng** - Tải lên thêm file PCAP để phân tích dài hạn\n"

        return summary

    def update_chat_history(self, query: str, results: Dict) -> List[Dict[str, str]]:
        """
        Cập nhật lịch sử chat và trả về phản hồi mới.
        
        Args:
            query: Truy vấn của người dùng
            results: Kết quả phân tích PCAP
            
        Returns:
            Lịch sử chat đã cập nhật
        """
        # Nếu là truy vấn đầu tiên và chat_history trống, thêm tin nhắn chào mừng
        if not self.chat_history:
            welcome_message = self.get_initial_chat_message(results)
            self.chat_history.append({"role": "assistant", "content": welcome_message})

        # Thêm tin nhắn của người dùng vào lịch sử
        self.chat_history.append({"role": "user", "content": query})

        # Tạo phản hồi
        response = self.create_ai_chat_response(query, results)

        # Thêm phản hồi vào lịch sử
        self.chat_history.append({"role": "assistant", "content": response})

        # Trả về lịch sử chat đã cập nhật
        return self.chat_history

    def get_initial_chat_message(self, results: Dict) -> str:
        """
        Tạo tin nhắn ban đầu cho chat box dựa trên kết quả phân tích.
        
        Args:
            results: Kết quả phân tích PCAP
            
        Returns:
            Tin nhắn chào mừng ban đầu
        """
        if not results:
            return "Chào bạn! Tôi là trợ lý phân tích mạng. Vui lòng tải lên file PCAP để bắt đầu phân tích."

        # Tạo tin nhắn chào mừng với tổng quan
        message = "Chào bạn! Tôi đã phân tích xong file PCAP của bạn.\n\n"

        # Thêm thông tin tổng quan về rủi ro
        message += "**Tổng quan về an ninh mạng:**\n\n"

        # Phân tích các rủi ro cơ bản
        risks_found = False

        # Kiểm tra tấn công
        attacks = results.get("attacks", [])
        if attacks:
            message += f"⚠️ **Phát hiện {len(attacks)} cuộc tấn công!** Đây là rủi ro an ninh cao cần xử lý ngay.\n\n"
            risks_found = True

            # Kiểm tra tấn công ARP đặc biệt
            arp_attacks = [a for a in attacks if "ARP" in a.get("attack_type", "")]
            if arp_attacks:
                gateway_attacks = [a for a in arp_attacks if any(ip.endswith(".1") or ip.endswith(".254") for ip in a.get("target_ips", []))]

                if gateway_attacks:
                    message += f"🚨 **NGUY HIỂM: Phát hiện {len(gateway_attacks)} tấn công ARP nhắm vào gateway!**\n"
                    message += "Đây là dấu hiệu của tấn công Man-in-the-Middle có thể đánh cắp thông tin nhạy cảm.\n\n"
                else:
                    message += f"⚠️ **Phát hiện {len(arp_attacks)} tấn công ARP spoofing** có thể dẫn đến tấn công Man-in-the-Middle.\n\n"
        else:
            message += "✅ **Không phát hiện tấn công nào.** Điều này tốt cho an ninh mạng của bạn.\n\n"

        # Kiểm tra tỉ lệ kết nối TCP đặt lại
        if "flow_statistics" in results:
            flow_stats = results["flow_statistics"]
            total_flows = flow_stats.get("total_flows", 0)
            reset_count = flow_stats.get("reset_count", 0)

            if total_flows > 0:
                reset_percent = (reset_count / total_flows) * 100
                if reset_percent > 20:
                    message += f"⚠️ **Tỷ lệ kết nối đặt lại cao: {reset_percent:.1f}%** - Có thể có vấn đề về hiệu suất mạng.\n\n"
                    risks_found = True

        # Tóm tắt rủi ro
        if risks_found:
            message += "Có một số rủi ro mạng cần được xem xét. Hãy hỏi tôi về 'phân tích rủi ro mạng' để biết chi tiết.\n\n"
        else:
            message += "Mạng của bạn có vẻ an toàn dựa trên dữ liệu đã phân tích. Tuy nhiên, việc giám sát liên tục rất quan trọng.\n\n"

        # Thêm hướng dẫn tương tác
        message += "Bạn có thể hỏi tôi về:\n"
        message += "- Phân tích rủi ro mạng\n"
        message += "- Chi tiết về các cuộc tấn công\n"

        # Thêm gợi ý về ARP nếu có tấn công ARP
        if attacks and any("ARP" in a.get("attack_type", "") for a in attacks):
            message += "- Thông tin về tấn công ARP spoofing\n"

        message += "- Biện pháp giảm thiểu rủi ro\n"
        message += "- Phân tích kết nối TCP\n"

        # Khởi tạo lịch sử chat
        self.chat_history = [{"role": "assistant", "content": message}]

        return message

    def analyze_pcap(self, pcap_file) -> Tuple:
        """Phân tích file pcap và trả về kết quả đã định dạng cho UI."""
        if not pcap_file:
            return "Không tìm thấy file PCAP.", pd.DataFrame(), None, None, None, None, None

        # Lưu thông tin về file hiện tại
        file_path = pcap_file.name if hasattr(pcap_file, 'name') else pcap_file
        self.base_presenter.latest_pcap_file = file_path

        try:
            # Phân tích file pcap
            results = self.base_presenter.controller.analyze_pcap_file(file_path)
            self.base_presenter.latest_results = results

            # Định dạng kết quả để hiển thị
            summary = f"## Kết quả phân tích\n\n"
            summary += f"File: {os.path.basename(file_path)}\n\n"

            if "attack_count" in results:
                if results["attack_count"] > 0:
                    summary += f"⚠️ **Phát hiện {results['attack_count']} cuộc tấn công!**\n\n"
                else:
                    summary += "✅ **Không phát hiện tấn công nào.**\n\n"

            # Thêm thống kê luồng
            if "flow_statistics" in results:
                flow_stats = results["flow_statistics"]
                summary += f"- Tổng số luồng: {flow_stats.get('total_flows', 0)}\n"
                summary += f"- Luồng đã thiết lập: {flow_stats.get('established_count', 0)}\n"
                summary += f"- Luồng bị đặt lại: {flow_stats.get('reset_count', 0)}\n"

            # Tạo bảng tấn công
            attack_table = self.base_presenter.format_attack_table(results.get("attacks", []))

            # Tạo biểu đồ giao thức
            protocol_chart = self.chart_creator.create_protocol_chart(results)

            # Tạo biểu đồ mức độ nghiêm trọng của tấn công
            attack_chart = self.chart_creator.create_attack_severity_chart(results.get("attacks", []))

            # Tạo đồ thị luồng
            flow_graph = self.chart_creator.create_flow_graph(results)

            # Tạo AI analysis cho tab chi tiết
            tcp_analysis = self.create_osi_analysis(results)

            # Tạo trực quan hóa cụ thể cho TCP
            tcp_visualizations = self.chart_creator.create_tcp_visualizations(results)

            # Tạo tin nhắn chat ban đầu và cập nhật chat history
            initial_chat_message = self.get_initial_chat_message(results)

            return summary, attack_table, protocol_chart, attack_chart, flow_graph, tcp_visualizations, initial_chat_message

        except Exception as e:
            # Xử lý nếu có lỗi trong quá trình phân tích
            error_message = f"## Lỗi khi phân tích file\n\n"
            error_message += f"Không thể phân tích file: {str(e)}\n\n"
            error_message += "Vui lòng kiểm tra lại file PCAP và thử lại."

            empty_chart = self.chart_creator._create_empty_chart("Lỗi phân tích")

            # Tạo tin nhắn chat với thông báo lỗi
            error_chat = "Đã xảy ra lỗi khi phân tích file PCAP. Vui lòng kiểm tra lại file và thử lại."
            self.chat_history = [{"role": "assistant", "content": error_chat}]

            return (
                error_message,
                None,
                empty_chart,
                empty_chart,
                empty_chart,
                empty_chart,
                error_chat
            )