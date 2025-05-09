"""
PCAPAnalyzer - Phân tích file PCAP và định dạng kết quả cho UI.
"""
from typing import Dict, Tuple
import os
import pandas as pd
from src.interfaces.presenters.chart_creator import ChartCreator
# Tạo instance SmolagentGateway nếu chưa có
from src.interfaces.gateways.smolagent_gateway import SmolagentGateway

class PCAPAnalyzer:
    """Phân tích file PCAP và định dạng kết quả cho UI."""
    
    def __init__(self, controller, chart_creator: ChartCreator = None):
        """
        Khởi tạo PCAP analyzer.
        
        Args:
            controller: Controller để phân tích PCAP
            chart_creator: Đối tượng ChartCreator để tạo biểu đồ
        """
        self.controller = controller
        self.chart_creator = chart_creator or ChartCreator()
        self.latest_pcap_file = None
        self.latest_results = None
    
    def analyze_pcap(self, pcap_file) -> Tuple:
        """
        Phân tích file pcap và định dạng kết quả cho UI.
        
        Args:
            pcap_file: File PCAP để phân tích
            
        Returns:
            Tuple (summary, attack_table, protocol_chart, attack_chart, flow_graph, tcp_visualizations, initial_chat_message)
        """
        if not pcap_file:
            empty_chart = self.chart_creator._create_empty_chart("Không có dữ liệu")
            return "Không tìm thấy file PCAP.", pd.DataFrame(), empty_chart, empty_chart, empty_chart, empty_chart, None

        # Lưu thông tin về file hiện tại
        file_path = pcap_file.name if hasattr(pcap_file, 'name') else pcap_file
        self.latest_pcap_file = file_path

        try:
            # Phân tích file pcap
            results = self.controller.analyze_pcap_file(file_path)
            self.latest_results = results

            # Định dạng kết quả để hiển thị
            summary = self._create_summary(file_path, results)

            # Tạo bảng tấn công
            attack_table = self._format_attack_table(results.get("attacks", []))

            # Tạo các biểu đồ
            protocol_chart = self.chart_creator.create_protocol_chart(results)
            attack_chart = self.chart_creator.create_attack_severity_chart(results.get("attacks", []))
            flow_graph = self.chart_creator.create_flow_graph(results)
            tcp_visualizations = self.chart_creator.create_tcp_visualizations(results)

            # Tạo tin nhắn chat ban đầu
            initial_chat_message = self._create_initial_chat_message(results)

            return summary, attack_table, protocol_chart, attack_chart, flow_graph, tcp_visualizations, initial_chat_message

        except Exception as e:
            # Xử lý nếu có lỗi trong quá trình phân tích
            error_message = f"## Lỗi khi phân tích file\n\n"
            error_message += f"Không thể phân tích file: {str(e)}\n\n"
            error_message += "Vui lòng kiểm tra lại file PCAP và thử lại."

            empty_chart = self.chart_creator._create_empty_chart("Lỗi phân tích")

            # Tạo tin nhắn chat với thông báo lỗi
            error_chat = "Đã xảy ra lỗi khi phân tích file PCAP. Vui lòng kiểm tra lại file và thử lại."

            return (
                error_message,
                None,
                empty_chart,
                empty_chart,
                empty_chart,
                empty_chart,
                error_chat
            )
    
    def analyze_pcap_raw_packets(self, pcap_file, custom_prompt: str = None) -> str:
        """
        Phân tích file pcap sử dụng phương pháp phân tích gói tin thô.
        
        Args:
            pcap_file: File PCAP để phân tích
            custom_prompt: Prompt tùy chỉnh để hướng dẫn AI phân tích
            
        Returns:
            Kết quả phân tích dưới dạng chuỗi văn bản
        """
        if not pcap_file:
            return "Không tìm thấy file PCAP."

        # Lưu thông tin về file hiện tại
        file_path = pcap_file.name if hasattr(pcap_file, 'name') else pcap_file
        self.latest_pcap_file = file_path

        try:
            # Tải các gói tin thô trực tiếp mà không thực hiện phân tích
            packets = self.controller.analyze_packet_use_case.packet_repository.load_pcap_file(file_path)

            smolagent_gateway = getattr(self.controller, 'smolagent_gateway', None)

            if not smolagent_gateway:
                smolagent_gateway = SmolagentGateway()
            
            # Kiểm tra từ khóa trong prompt để quyết định loại phân tích
            if custom_prompt and ("osi" in custom_prompt.lower() or "mô hình osi" in custom_prompt.lower()):
                # Sử dụng phương thức phân tích theo mô hình OSI
                result = smolagent_gateway.analyze_osi_raw_packets(packets, custom_prompt)
            else:
                # Sử dụng phương thức phân tích thông thường
                result = smolagent_gateway.analyze_raw_packets(packets, custom_prompt)
            
            # Xử lý kết quả
            if isinstance(result, dict) and "analysis" in result:
                return result["analysis"]
            elif isinstance(result, str):
                return result
            else:
                return str(result)
        except Exception as e:
            # Xử lý lỗi
            error_message = f"## Lỗi khi phân tích file\n\n"
            error_message += f"Không thể phân tích file: {str(e)}\n\n"
            error_message += "Vui lòng kiểm tra lại file PCAP và thử lại."
            return error_message
    
    def _create_summary(self, file_path: str, results: Dict) -> str:
        """
        Tạo tóm tắt từ kết quả phân tích.
        
        Args:
            file_path: Đường dẫn đến file PCAP
            results: Kết quả phân tích
            
        Returns:
            Chuỗi tóm tắt kết quả phân tích
        """
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
            
        return summary
    
    def _format_attack_table(self, attacks: list) -> pd.DataFrame:
        """
        Định dạng danh sách tấn công thành DataFrame.
        
        Args:
            attacks: Danh sách các tấn công
            
        Returns:
            DataFrame chứa thông tin tấn công
        """
        if not attacks:
            return pd.DataFrame()
        
        # Tạo danh sách các mục
        formatted_attacks = []
        for attack in attacks:
            formatted_attack = {
                "Loại tấn công": attack.get("attack_type", "Unknown"),
                "Mức độ nghiêm trọng": attack.get("severity", 0),
                "Thời gian": attack.get("timestamp", "N/A"),
                "Nguồn": attack.get("src_ip", "unknown"),
                "Đích": attack.get("dst_ip", "unknown"),
                "Chi tiết": attack.get("description", "Không có mô tả chi tiết")
            }
            formatted_attacks.append(formatted_attack)
            
        # Tạo DataFrame từ danh sách
        df = pd.DataFrame(formatted_attacks)
        
        # Sắp xếp theo mức độ nghiêm trọng
        if not df.empty and "Mức độ nghiêm trọng" in df.columns:
            df = df.sort_values(by="Mức độ nghiêm trọng", ascending=False)
            
        return df
    
    def _create_initial_chat_message(self, results: Dict) -> str:
        """
        Tạo tin nhắn chat ban đầu.
        
        Args:
            results: Kết quả phân tích PCAP
            
        Returns:
            Tin nhắn chat ban đầu
        """
        message = "Chào bạn! Tôi đã phân tích xong file PCAP của bạn.\n\n"
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
        message += "- Phân tích lưu lượng mạng theo mô hình OSI\n"

        # Thêm gợi ý về ARP nếu có tấn công ARP
        if attacks and any("ARP" in a.get("attack_type", "") for a in attacks):
            message += "- Thông tin về tấn công ARP spoofing\n"

        message += "- Biện pháp giảm thiểu rủi ro\n"

        return message 