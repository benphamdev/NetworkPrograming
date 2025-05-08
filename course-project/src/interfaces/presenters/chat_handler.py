"""
ChatHandler - Quản lý hội thoại chat với người dùng về phân tích mạng.
"""
from typing import Dict, List
import os
from src.interfaces.gateways.smolagent_gateway import SmolagentGateway
from src.interfaces.presenters.summary_creator import SummaryCreator

class ChatHandler:
    """Quản lý hội thoại chat với người dùng về phân tích mạng."""
    
    def __init__(self, latest_pcap_file=None):
        """
        Khởi tạo chat handler.
        
        Args:
            latest_pcap_file: Đường dẫn đến file PCAP hiện tại (nếu có)
        """
        self.chat_history = []
        self.latest_pcap_file = latest_pcap_file
        self.smolagent_gateway = SmolagentGateway()
        self.summary_creator = SummaryCreator()
    
    def create_ai_chat_response(self, query: str, results: Dict) -> str:
        """
        Tạo phản hồi cho hội thoại chat dựa trên truy vấn của người dùng và kết quả phân tích từ file PCAP.
        
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
            # Logic xử lý truy vấn về file hiện tại
            file_name = os.path.basename(self.latest_pcap_file) if self.latest_pcap_file else "không xác định"

            if "có gì" in query_lower or "chứa gì" in query_lower or "tóm tắt" in query_lower:
                return self.summary_creator.create_file_summary(results, file_name)

        # Xử lý truy vấn về mô hình OSI
        if "osi" in query_lower or "mô hình osi" in query_lower:
            # Gọi phân tích OSI từ SmolagentGateway
            osi_analysis = self._get_osi_analysis(results)
            file_name = os.path.basename(self.latest_pcap_file) if self.latest_pcap_file else "đã tải lên"
            return f"Phân tích lưu lượng mạng theo mô hình OSI từ file {file_name}:\n\n{osi_analysis}"
            
        # Gọi trực tiếp đến deepseek model (trường hợp mặc định)
        try:
            # Gọi trực tiếp đến deepseek model thông qua phương thức direct_query
            return self.smolagent_gateway.direct_query(query)
        except Exception as e:
            # Nếu có lỗi, sử dụng phản hồi mặc định
            file_name = os.path.basename(self.latest_pcap_file) if self.latest_pcap_file else "đã tải lên"
            return (
                f"Tôi có thể cung cấp phân tích chi tiết về file PCAP {file_name}. "
                "Hãy hỏi tôi về: tấn công phát hiện được, phân tích mạng theo mô hình OSI, phân bố giao thức, "
                "rủi ro mạng, hoặc biện pháp giảm thiểu tấn công."
            )
    
    def _get_osi_analysis(self, results: Dict) -> str:
        """
        Lấy phân tích theo mô hình OSI từ SmolagentGateway.
        
        Args:
            results: Kết quả phân tích PCAP
            
        Returns:
            Phân tích theo mô hình OSI
        """
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
        message += "- Phân tích lưu lượng mạng theo mô hình OSI\n"

        # Thêm gợi ý về ARP nếu có tấn công ARP
        if attacks and any("ARP" in a.get("attack_type", "") for a in attacks):
            message += "- Thông tin về tấn công ARP spoofing\n"

        message += "- Biện pháp giảm thiểu rủi ro\n"

        # Khởi tạo lịch sử chat
        self.chat_history = [{"role": "assistant", "content": message}]

        return message
    
    def clear_chat_history(self):
        """Xóa lịch sử chat."""
        self.chat_history = [] 