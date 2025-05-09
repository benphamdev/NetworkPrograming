"""
ChatHandler - Quản lý hội thoại chat với người dùng về phân tích mạng.
Lớp này xử lý các truy vấn từ người dùng và tạo phản hồi dựa trên kết quả phân tích từ file PCAP.
Nó là con của Gradio gateway
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
            
        # Xử lý truy vấn về cờ TCP
        if "cờ tcp" in query_lower or "tcp flag" in query_lower or "phân tích cờ" in query_lower:
            return self._analyze_tcp_flags(results)
        
        # Xử lý truy vấn về dự đoán các vấn đề
        if "dự đoán" in query_lower or "có thể xảy ra" in query_lower or "khả năng" in query_lower:
            return self._predict_network_issues(results)
        
        # Xử lý truy vấn về thông số nguy hiểm
        if "thông số nguy hiểm" in query_lower or "gói tin nguy hiểm" in query_lower or "thông số bất thường" in query_lower or "payload độc hại" in query_lower:
            return self._analyze_dangerous_parameters(results)
        
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
                # Đảm bảo luôn trả về chuỗi, không phải dictionary
                return "## Phân tích theo mô hình OSI\n\n" + str(osi_analysis)
        except Exception as e:
            return f"## Lỗi khi phân tích theo mô hình OSI\n\nĐã xảy ra lỗi khi phân tích: {str(e)}"
    
    def analyze_tcp_flags_raw(self, packets: List) -> str:
        """
        Phân tích cờ TCP từ danh sách gói tin thô.
        
        Args:
            packets: Danh sách các gói tin cần phân tích
            
        Returns:
            Phân tích về cờ TCP
        """
        if not packets:
            return "Không có dữ liệu để phân tích. Vui lòng tải lên file PCAP."
        
        # Lọc gói tin TCP
        tcp_packets = [p for p in packets if hasattr(p, 'protocol') and p.protocol == 'TCP']
        
        if not tcp_packets:
            return "Không tìm thấy gói tin TCP nào trong dữ liệu."
        
        # Tạo phân tích về cờ TCP
        file_name = os.path.basename(self.latest_pcap_file) if self.latest_pcap_file else "đã tải lên"
        
        # Xây dựng prompt tùy chỉnh
        custom_prompt = """
        Là một chuyên gia phân tích mạng, hãy tập trung phân tích chi tiết các cờ TCP trong lưu lượng mạng sau.
        
        Phân tích cụ thể:
        1. Phân bố của các cờ TCP (SYN, ACK, FIN, RST, PSH, URG)
        2. Tỷ lệ SYN/ACK và ý nghĩa của nó
        3. Mức độ bất thường của cờ RST nếu có
        4. Dấu hiệu của các cuộc tấn công liên quan đến TCP như SYN flood, RST attack, port scan
        5. Đề xuất các use case mới để phát hiện tấn công dựa trên phân tích cờ TCP
        
        Hãy đưa ra kết luận và khuyến nghị bảo mật cụ thể dựa trên phân tích.
        """
        
        # Sử dụng phương thức analyze_raw_packets từ SmolagentGateway thay vì của lớp này
        try:
            result = self.smolagent_gateway.analyze_raw_packets(tcp_packets, custom_prompt)
            
            # Kiểm tra và trả về kết quả phân tích
            if isinstance(result, dict) and "analysis" in result:
                return result["analysis"]
            return str(result)
        except Exception as e:
            return f"Lỗi khi phân tích cờ TCP: {str(e)}"
    
    def analyze_raw_packets(self, packets: List, custom_prompt: str = None) -> str:
        """
        Phân tích trực tiếp danh sách gói tin thô thay vì sử dụng kết quả đã được xử lý.
        
        Args:
            packets: Danh sách các gói tin cần phân tích
            custom_prompt: Prompt tùy chỉnh để hướng dẫn AI phân tích
            
        Returns:
            Phân tích từ AI dưới dạng chuỗi văn bản
        """
        try:
            # Sử dụng phương thức analyze_raw_packets mới từ smolagent_gateway
            analysis_result = self.smolagent_gateway.analyze_raw_packets(packets, custom_prompt)
            
            # Kiểm tra kết quả và trả về phân tích
            if isinstance(analysis_result, dict) and "analysis" in analysis_result:
                return analysis_result["analysis"]
            elif isinstance(analysis_result, str):
                return analysis_result
            else:
                # Đảm bảo luôn trả về chuỗi, không phải dictionary
                return "## Phân tích gói tin\n\n" + str(analysis_result)
        except Exception as e:
            return f"## Lỗi khi phân tích gói tin\n\nĐã xảy ra lỗi khi phân tích: {str(e)}"
    
    def analyze_raw_packets_with_osi(self, packets: List, custom_prompt: str = None) -> str:
        """
        Phân tích danh sách gói tin thô theo mô hình OSI.
        
        Args:
            packets: Danh sách các gói tin cần phân tích
            custom_prompt: Prompt tùy chỉnh để hướng dẫn AI phân tích
            
        Returns:
            Phân tích theo mô hình OSI dưới dạng chuỗi văn bản
        """
        try:
            # Nếu không có prompt tùy chỉnh, tạo prompt tập trung vào phân tích OSI
            if not custom_prompt:
                custom_prompt = """
                Là một chuyên gia phân tích mạng, hãy phân tích chi tiết các gói tin dưới đây theo mô hình OSI (7 tầng).
                
                Phân tích từng tầng:
                1. Tầng vật lý (Physical Layer)
                2. Tầng liên kết dữ liệu (Data Link Layer) - MAC, ARP, v.v.
                3. Tầng mạng (Network Layer) - IP, ICMP, định tuyến, v.v.
                4. Tầng giao vận (Transport Layer) - TCP, UDP, cờ TCP, port, v.v.
                5. Tầng phiên (Session Layer)
                6. Tầng trình diễn (Presentation Layer)
                7. Tầng ứng dụng (Application Layer) - HTTP, DNS, v.v.
                
                Tập trung vào:
                - Dấu hiệu tấn công hoặc bất thường ở mỗi tầng
                - Vấn đề hiệu suất hoặc kết nối
                - Các use case phân tích mới có thể thêm vào hệ thống
                - Các biện pháp bảo mật và giảm thiểu rủi ro
                """
            
            # Sử dụng phương thức analyze_raw_packets với prompt tùy chỉnh cho OSI
            osi_analysis = self.smolagent_gateway.analyze_raw_packets(packets, custom_prompt)
            
            # Xử lý kết quả từ SmolagentGateway
            if isinstance(osi_analysis, dict) and "analysis" in osi_analysis:
                return osi_analysis["analysis"]
            elif isinstance(osi_analysis, str):
                return osi_analysis
            else:
                # Đảm bảo luôn trả về chuỗi, không phải dictionary
                return "## Phân tích gói tin theo mô hình OSI\n\n" + str(osi_analysis)
        except Exception as e:
            return f"## Lỗi khi phân tích gói tin theo mô hình OSI\n\nĐã xảy ra lỗi khi phân tích: {str(e)}"
    
    def _analyze_tcp_flags(self, results: Dict) -> str:
        """
        Phân tích chi tiết về các cờ TCP từ kết quả phân tích PCAP.
        
        Args:
            results: Kết quả phân tích PCAP
            
        Returns:
            Phân tích về các cờ TCP
        """
        if not results:
            return "Không có dữ liệu để phân tích. Vui lòng tải lên file PCAP."
            
        # Kiểm tra xem có dữ liệu cờ TCP không
        if "tcp_flags" not in results:
            return "Không tìm thấy thông tin về cờ TCP trong dữ liệu phân tích."
            
        tcp_flags = results["tcp_flags"]
        if not tcp_flags:
            return "Không có thông tin về cờ TCP trong dữ liệu phân tích."
            
        # Tạo phân tích về cờ TCP
        file_name = os.path.basename(self.latest_pcap_file) if self.latest_pcap_file else "đã tải lên"
        analysis = f"# Phân tích cờ TCP\n\n"
        analysis += f"*File: {file_name}*\n\n"
        
        # Tính tổng số cờ TCP
        total_flags = sum(tcp_flags.values())
        if total_flags == 0:
            return analysis + "Không có gói tin TCP nào được tìm thấy."
            
        # Phân tích tỉ lệ các cờ
        analysis += "## Phân bố cờ TCP\n\n"
        analysis += "| Cờ | Số lượng gói tin | Tỉ lệ |\n"
        analysis += "|-----|-----------------|------|\n"
        
        # Sắp xếp cờ theo thứ tự phổ biến: SYN, ACK, FIN, RST, PSH, URG
        flag_order = {"SYN": 1, "ACK": 2, "FIN": 3, "RST": 4, "PSH": 5, "URG": 6}
        sorted_flags = sorted(tcp_flags.items(), key=lambda x: flag_order.get(x[0], 99))
        
        for flag, count in sorted_flags:
            percentage = (count / total_flags) * 100
            analysis += f"| **{flag}** | {count} | {percentage:.2f}% |\n"
        
        # Phân tích ý nghĩa của các cờ và dự đoán vấn đề
        analysis += "\n## Phân tích cờ TCP\n\n"
        
        # Thêm giải thích về vai trò của từng cờ
        analysis += "### Ý nghĩa của các cờ TCP\n\n"
        analysis += "| Cờ | Ý nghĩa | Vai trò thông thường |\n"
        analysis += "|-----|---------|----------------------|\n"
        analysis += "| **SYN** | Synchronize | Khởi tạo kết nối TCP |\n"
        analysis += "| **ACK** | Acknowledgment | Xác nhận dữ liệu đã nhận |\n"
        analysis += "| **FIN** | Finish | Kết thúc kết nối TCP |\n"
        analysis += "| **RST** | Reset | Đặt lại/từ chối kết nối |\n"
        analysis += "| **PSH** | Push | Yêu cầu đẩy dữ liệu ngay lập tức |\n"
        analysis += "| **URG** | Urgent | Chỉ định dữ liệu khẩn cấp |\n\n"
        
        # Phân tích chi tiết các cờ đáng chú ý
        analysis += "### Phân tích chi tiết\n\n"
        
        # Phân tích SYN
        if "SYN" in tcp_flags:
            syn_count = tcp_flags.get("SYN", 0)
            syn_percentage = (syn_count / total_flags) * 100
            
            analysis += "#### Cờ SYN\n\n"
            if syn_percentage > 40:
                analysis += f"**Cảnh báo: Tỉ lệ SYN cao ({syn_percentage:.2f}%)**\n\n"
                analysis += "Số lượng lớn gói SYN có thể chỉ ra:\n"
                analysis += "- Tấn công SYN flood (DoS/DDoS)\n"
                analysis += "- Quét cổng (port scanning)\n"
                analysis += "- Thiết lập nhiều kết nối mới một cách bất thường\n\n"
                analysis += "Khi tỉ lệ gói SYN cao mà không có ACK tương ứng, đây thường là dấu hiệu của hoạt động không bình thường trên mạng.\n\n"
            else:
                analysis += f"**Tỉ lệ SYN bình thường ({syn_percentage:.2f}%)**\n\n"
                analysis += "Tỉ lệ gói SYN nằm trong ngưỡng bình thường, phản ánh các yêu cầu kết nối mới thông thường trong mạng.\n\n"
        
        # Phân tích RST
        if "RST" in tcp_flags:
            rst_count = tcp_flags.get("RST", 0)
            rst_percentage = (rst_count / total_flags) * 100
            
            analysis += "#### Cờ RST\n\n"
            if rst_percentage > 10:
                analysis += f"**Cảnh báo: Tỉ lệ RST cao ({rst_percentage:.2f}%)**\n\n"
                analysis += "Số lượng lớn gói RST có thể chỉ ra:\n"
                analysis += "- Kết nối bị từ chối bởi firewall\n"
                analysis += "- Cổng đích đóng hoặc dịch vụ không hoạt động\n"
                analysis += "- Tấn công quét cổng đang diễn ra\n"
                analysis += "- Vấn đề với cấu hình mạng\n"
                analysis += "- Kết nối TCP không hợp lệ hoặc bị hỏng\n\n"
                
                if rst_percentage > 25:
                    analysis += "**Phân tích sâu hơn:** Tỉ lệ RST rất cao (trên 25%) thường là dấu hiệu của vấn đề nghiêm trọng, có thể là tấn công hoặc cấu hình mạng sai. Cần kiểm tra ngay các firewall và các kết nối bị reset.\n\n"
            else:
                analysis += f"**Tỉ lệ RST bình thường ({rst_percentage:.2f}%)**\n\n"
                analysis += "Tỉ lệ gói RST nằm trong ngưỡng bình thường, thường xuất hiện khi kết thúc kết nối bất thường hoặc từ chối kết nối không mong muốn.\n\n"
        
        # Phân tích FIN
        if "FIN" in tcp_flags:
            fin_count = tcp_flags.get("FIN", 0)
            fin_percentage = (fin_count / total_flags) * 100
            
            analysis += "#### Cờ FIN\n\n"
            if fin_percentage > 25:
                analysis += f"**Cảnh báo: Tỉ lệ FIN cao ({fin_percentage:.2f}%)**\n\n"
                analysis += "Số lượng lớn gói FIN có thể chỉ ra:\n"
                analysis += "- Kết thúc đồng loạt nhiều kết nối\n"
                analysis += "- Kỹ thuật quét FIN stealth\n"
                analysis += "- Đóng nhiều kết nối một cách bất thường\n\n"
            else:
                analysis += f"**Tỉ lệ FIN bình thường ({fin_percentage:.2f}%)**\n\n"
                analysis += "Tỉ lệ gói FIN nằm trong ngưỡng bình thường, đại diện cho việc đóng kết nối TCP bình thường.\n\n"
        
        # Phân tích tỉ lệ SYN/ACK
        syn_count = tcp_flags.get("SYN", 0)
        ack_count = tcp_flags.get("ACK", 0)
        
        if syn_count > 0 and ack_count > 0:
            syn_ack_ratio = syn_count / ack_count
            
            analysis += "#### Tỉ lệ SYN/ACK\n\n"
            if syn_ack_ratio > 1.5:
                analysis += f"**Cảnh báo: Tỉ lệ SYN/ACK cao ({syn_ack_ratio:.2f}:1)**\n\n"
                analysis += "Nhiều yêu cầu kết nối không được phản hồi, có thể do:\n"
                analysis += "- Tấn công SYN flood\n"
                analysis += "- Máy chủ đích quá tải\n"
                analysis += "- Firewall chặn kết nối\n"
                analysis += "- Quét cổng đang diễn ra\n\n"
                
                if syn_ack_ratio > 3:
                    analysis += "**Phân tích sâu hơn:** Tỉ lệ SYN/ACK rất cao (trên 3:1) là dấu hiệu mạnh của cuộc tấn công hoặc vấn đề nghiêm trọng với máy chủ đích. Cần có biện pháp khẩn cấp để bảo vệ tài nguyên mạng.\n\n"
            elif syn_ack_ratio < 0.5:
                analysis += f"**Tỉ lệ ACK/SYN cao ({1/syn_ack_ratio:.2f}:1)**\n\n"
                analysis += "Nhiều gói ACK so với SYN có thể chỉ ra:\n"
                analysis += "- Lưu lượng kết nối đã thiết lập chiếm phần lớn\n"
                analysis += "- Phiên làm việc kéo dài với nhiều gói dữ liệu được xác nhận\n"
                analysis += "- Hoạt động mạng bình thường với các kết nối ổn định\n\n"
            else:
                analysis += f"**Tỉ lệ SYN/ACK bình thường ({syn_ack_ratio:.2f}:1)**\n\n"
                analysis += "Tỉ lệ kết nối được thiết lập và hoàn thành là bình thường, cho thấy mạng đang hoạt động ổn định.\n\n"
        
        # Phân tích các tổ hợp cờ bất thường
        if "PSH+ACK" in tcp_flags and "ACK" in tcp_flags:
            psh_ack = tcp_flags.get("PSH+ACK", 0)
            ack = tcp_flags.get("ACK", 0)
            psh_ack_ratio = psh_ack / (psh_ack + ack) * 100 if (psh_ack + ack) > 0 else 0
            
            analysis += "#### Tổ hợp cờ PSH+ACK\n\n"
            if psh_ack_ratio > 70:
                analysis += f"**Cảnh báo: Tỉ lệ PSH+ACK cao ({psh_ack_ratio:.2f}%)**\n\n"
                analysis += "Số lượng lớn gói PSH+ACK có thể chỉ ra:\n"
                analysis += "- Truyền dữ liệu tương tác với yêu cầu phản hồi nhanh\n"
                analysis += "- Có thể là dấu hiệu của Shell tương tác từ xa\n"
                analysis += "- Truyền tải dữ liệu nhỏ và thường xuyên\n\n"
            else:
                analysis += f"**Tỉ lệ PSH+ACK ({psh_ack_ratio:.2f}%)**\n\n"
                analysis += "Tỉ lệ PSH+ACK nằm trong ngưỡng bình thường, thường thấy trong truyền tải dữ liệu thông thường.\n\n"
        
        # Phát hiện quét cổng ẩn
        if any(flag in tcp_flags for flag in ["FIN", "NULL", "XMAS"]):
            stealth_scans = sum(tcp_flags.get(flag, 0) for flag in ["FIN", "NULL", "XMAS"])
            stealth_percentage = (stealth_scans / total_flags) * 100 if total_flags > 0 else 0
            
            if stealth_percentage > 5:
                analysis += "#### Dấu hiệu quét cổng ẩn\n\n"
                analysis += f"**Cảnh báo: Phát hiện {stealth_scans} gói tin có thể là quét cổng ẩn ({stealth_percentage:.2f}%)**\n\n"
                analysis += "Bao gồm các cờ bất thường như FIN, NULL, XMAS thường được sử dụng trong:\n"
                analysis += "- Kỹ thuật quét cổng ẩn\n"
                analysis += "- Nỗ lực vượt qua tường lửa\n"
                analysis += "- Né tránh phát hiện của các hệ thống IDS/IPS\n\n"
                analysis += "Đây là kỹ thuật nâng cao thường được sử dụng bởi các công cụ như Nmap với các chế độ quét ẩn.\n\n"
        
        # Tổng kết và đề xuất
        analysis += "## Tổng kết và khuyến nghị\n\n"
        
        # Xác định các vấn đề có thể
        issues = []
        issue_severities = {}
        
        # Kiểm tra dấu hiệu SYN flood
        if "SYN" in tcp_flags and "ACK" in tcp_flags:
            syn_count = tcp_flags.get("SYN", 0)
            ack_count = tcp_flags.get("ACK", 0)
            
            if syn_count > ack_count * 2 and syn_count > 100:
                issues.append("Có dấu hiệu của tấn công SYN flood hoặc quét cổng")
                issue_severities["Có dấu hiệu của tấn công SYN flood hoặc quét cổng"] = "Cao"
        
        # Kiểm tra dấu hiệu bị firewall chặn
        if "RST" in tcp_flags:
            rst_count = tcp_flags.get("RST", 0)
            rst_percentage = (rst_count / total_flags) * 100
            
            if rst_percentage > 20:
                issues.append("Có dấu hiệu kết nối bị firewall chặn hoặc dịch vụ không hoạt động")
                issue_severities["Có dấu hiệu kết nối bị firewall chặn hoặc dịch vụ không hoạt động"] = "Trung bình" if rst_percentage < 40 else "Cao"
        
        # Kiểm tra dấu hiệu quét cổng FIN/NULL/XMAS
        stealth_scans = 0
        for flag in ["FIN", "NULL", "XMAS"]:
            if flag in tcp_flags:
                stealth_scans += tcp_flags.get(flag, 0)
        
        if stealth_scans > 50:
            issues.append("Có dấu hiệu của kỹ thuật quét cổng ẩn (stealth scanning)")
            issue_severities["Có dấu hiệu của kỹ thuật quét cổng ẩn (stealth scanning)"] = "Cao"
        
        # Thêm các vấn đề vào phân tích
        if issues:
            analysis += "### Vấn đề tiềm ẩn\n\n"
            analysis += "| Vấn đề | Mức độ nghiêm trọng |\n"
            analysis += "|--------|---------------------|\n"
            for issue in issues:
                severity = issue_severities.get(issue, "Trung bình")
                analysis += f"| {issue} | **{severity}** |\n"
            
            analysis += "\n### Khuyến nghị bảo mật\n\n"
            
            if "Có dấu hiệu của tấn công SYN flood hoặc quét cổng" in issues:
                analysis += "#### Đối với SYN Flood/Quét cổng\n\n"
                analysis += "- Triển khai SYN cookies để bảo vệ chống lại các cuộc tấn công SYN flood\n"
                analysis += "- Cấu hình rate limiting để hạn chế số lượng kết nối TCP mới từ một nguồn\n"
                analysis += "- Sử dụng IDS/IPS để phát hiện và chặn các hoạt động quét cổng\n"
                analysis += "- Xem xét sử dụng dịch vụ anti-DDoS nếu đây là vấn đề thường xuyên\n\n"
            
            if "Có dấu hiệu kết nối bị firewall chặn hoặc dịch vụ không hoạt động" in issues:
                analysis += "#### Đối với kết nối bị chặn/dịch vụ không phản hồi\n\n"
                analysis += "- Kiểm tra logs của firewall để xác định các kết nối bị chặn\n"
                analysis += "- Xem xét lại quy tắc firewall để đảm bảo chúng không quá hạn chế\n"
                analysis += "- Kiểm tra trạng thái của các dịch vụ để đảm bảo chúng đang hoạt động\n"
                analysis += "- Xác minh rằng các cổng dịch vụ được mở và lắng nghe đúng cách\n\n"
            
            if "Có dấu hiệu của kỹ thuật quét cổng ẩn (stealth scanning)" in issues:
                analysis += "#### Đối với quét cổng ẩn\n\n"
                analysis += "- Triển khai tường lửa có khả năng phát hiện quét cổng ẩn\n"
                analysis += "- Cấu hình các quy tắc IDS cụ thể cho việc phát hiện quét NULL, FIN và XMAS\n"
                analysis += "- Giám sát và ghi lại thông tin nguồn của các kết nối quét\n"
                analysis += "- Xem xét chặn tạm thời địa chỉ IP thực hiện các hoạt động quét cổng ẩn\n\n"
        else:
            analysis += "### Đánh giá tổng thể\n\n"
            analysis += "Không phát hiện vấn đề nghiêm trọng từ phân tích cờ TCP. Các cờ TCP có phân bố bình thường, phản ánh hoạt động mạng thông thường.\n\n"
            analysis += "### Khuyến nghị bảo mật\n\n"
            analysis += "Mặc dù không phát hiện vấn đề, vẫn nên duy trì các biện pháp bảo mật cơ bản:\n\n"
            analysis += "- Giám sát liên tục luồng TCP để phát hiện sớm các dấu hiệu bất thường\n"
            analysis += "- Cập nhật thường xuyên các thiết bị bảo mật mạng\n"
            analysis += "- Duy trì cấu hình firewall tối ưu\n"
            analysis += "- Thực hiện phân tích lưu lượng mạng định kỳ\n"
        
        try:
            # Xử lý sâu hơn bằng cách gọi SmolagentGateway
            deep_analysis = self.smolagent_gateway.analyze_traffic_pattern({"tcp_flags": tcp_flags})
            
            # Thêm phân tích sâu nếu có
            if deep_analysis and "analysis" in deep_analysis:
                analysis += "## Phân tích chuyên sâu từ AI\n\n"
                analysis += deep_analysis["analysis"]
        except Exception as e:
            # Bỏ qua lỗi nếu không gọi được SmolagentGateway
            pass
        
        return analysis
    
    def _predict_network_issues(self, results: Dict) -> str:
        """
        Dự đoán và phân tích các vấn đề mạng có thể xảy ra dựa trên kết quả phân tích PCAP.
        
        Args:
            results: Kết quả phân tích PCAP
            
        Returns:
            Phân tích dự đoán về các vấn đề mạng
        """
        if not results:
            return "Không có dữ liệu để phân tích. Vui lòng tải lên file PCAP."
            
        file_name = os.path.basename(self.latest_pcap_file) if self.latest_pcap_file else "đã tải lên"
        analysis = f"## Dự đoán các vấn đề mạng từ file {file_name}\n\n"
        
        # Các vấn đề tiềm ẩn sẽ được thêm vào đây
        potential_issues = []
        
        # 1. Kiểm tra các vấn đề về TCP
        if "tcp_flags" in results:
            tcp_flags = results["tcp_flags"]
            total_flags = sum(tcp_flags.values())
            
            if total_flags > 0:
                # Kiểm tra RST cao
                rst_count = tcp_flags.get("RST", 0)
                rst_percentage = (rst_count / total_flags) * 100
                
                if rst_percentage > 15:
                    potential_issues.append({
                        "type": "Firewall/Router Block",
                        "evidence": f"Tỉ lệ cờ RST cao ({rst_percentage:.2f}%)",
                        "description": "Các gói tin RST cao chỉ ra rằng nhiều kết nối đang bị chặn, có thể bởi firewall hoặc router. Các thiết bị bảo mật thường gửi gói RST để đóng các kết nối không mong muốn.",
                        "severity": "Trung bình" if rst_percentage < 30 else "Cao"
                    })
                
                # Kiểm tra SYN/ACK mất cân đối
                syn_count = tcp_flags.get("SYN", 0)
                ack_count = tcp_flags.get("ACK", 0)
                
                if syn_count > 0 and ack_count > 0:
                    syn_ack_ratio = syn_count / ack_count
                    
                    if syn_ack_ratio > 1.5:
                        potential_issues.append({
                            "type": "SYN Flood/Scan",
                            "evidence": f"Tỉ lệ SYN/ACK cao ({syn_ack_ratio:.2f}:1)",
                            "description": "Số lượng gói SYN cao hơn nhiều so với ACK chỉ ra rằng nhiều kết nối đang được khởi tạo nhưng không hoàn tất. Đây có thể là dấu hiệu của tấn công SYN flood, quét cổng, hoặc dịch vụ đích không phản hồi.",
                            "severity": "Cao" if syn_count > 100 and syn_ack_ratio > 2 else "Trung bình"
                        })
                
                # Kiểm tra FIN cao bất thường
                fin_count = tcp_flags.get("FIN", 0)
                fin_percentage = (fin_count / total_flags) * 100
                
                if fin_percentage > 25:
                    potential_issues.append({
                            "type": "FIN Scan/Unusual Termination",
                            "evidence": f"Tỉ lệ cờ FIN cao ({fin_percentage:.2f}%)",
                            "description": "Số lượng gói FIN cao bất thường chỉ ra việc kết thúc đồng loạt các kết nối hoặc kỹ thuật quét FIN stealth.",
                            "severity": "Thấp" if fin_percentage < 35 else "Trung bình"
                        })
        
        # 2. Kiểm tra các vấn đề về ARP
        if "arp_mapping" in results:
            arp_mapping = results["arp_mapping"]
            
            # Tìm IP có nhiều MAC (dấu hiệu ARP spoofing)
            suspicious_ips = [ip for ip, mac_list in arp_mapping.items() if len(mac_list) > 1]
            
            if suspicious_ips:
                potential_issues.append({
                    "type": "ARP Spoofing",
                    "evidence": f"Phát hiện {len(suspicious_ips)} địa chỉ IP có nhiều MAC",
                    "description": "Nhiều địa chỉ MAC cho cùng một IP là dấu hiệu của tấn công ARP spoofing, có thể dẫn đến tấn công Man-in-the-Middle.",
                    "severity": "Cao"
                })
        
        # 3. Kiểm tra các vấn đề về ICMP
        if "icmp_stats" in results:
            icmp_stats = results["icmp_stats"]
            
            # Kiểm tra ICMP Echo Request cao
            echo_requests = icmp_stats.get("echo_request", 0)
            
            if echo_requests > 100:
                potential_issues.append({
                    "type": "ICMP Flood/Ping Scan",
                    "evidence": f"Số lượng lớn ICMP Echo Request ({echo_requests})",
                    "description": "Số lượng lớn gói ICMP Echo Request (ping) có thể chỉ ra việc quét mạng hoặc tấn công ICMP flood.",
                    "severity": "Thấp" if echo_requests < 300 else "Trung bình"
                })
        
        # 4. Kiểm tra thống kê luồng
        if "flow_statistics" in results:
            flow_stats = results["flow_statistics"]
            
            # Kiểm tra luồng bị reset
            reset_count = flow_stats.get("reset_count", 0)
            total_flows = flow_stats.get("total_flows", 0)
            
            if total_flows > 0:
                reset_percentage = (reset_count / total_flows) * 100
                
                if reset_percentage > 15:
                    potential_issues.append({
                        "type": "Connection Blocking",
                        "evidence": f"Tỉ lệ kết nối bị reset cao ({reset_percentage:.2f}%)",
                        "description": "Tỉ lệ cao các luồng bị reset có thể chỉ ra việc chặn kết nối bởi firewall, IDS, hoặc các thiết bị bảo mật khác.",
                        "severity": "Trung bình" if reset_percentage < 30 else "Cao"
                    })
        
        # 5. Kiểm tra phân mảnh IP
        if "ip_fragmentation" in results:
            ip_frag = results["ip_fragmentation"]
            
            frag_count = ip_frag.get("fragmented_packets", 0)
            total_packets = ip_frag.get("total_packets", 0)
            
            if total_packets > 0 and frag_count > 0:
                frag_percentage = (frag_count / total_packets) * 100
                
                if frag_percentage > 10:
                    potential_issues.append({
                        "type": "IP Fragmentation Attack",
                        "evidence": f"Tỉ lệ gói tin phân mảnh cao ({frag_percentage:.2f}%)",
                        "description": "Số lượng lớn gói IP bị phân mảnh có thể chỉ ra tấn công phân mảnh IP hoặc nỗ lực vượt qua firewall.",
                        "severity": "Trung bình" if frag_percentage < 20 else "Cao"
                    })
        
        # Thêm các vấn đề vào phân tích
        if potential_issues:
            analysis += "### Các vấn đề tiềm ẩn\n\n"
            
            for issue in potential_issues:
                analysis += f"#### {issue['type']} (Mức độ: {issue['severity']})\n\n"
                analysis += f"**Bằng chứng:** {issue['evidence']}\n\n"
                analysis += f"**Mô tả:** {issue['description']}\n\n"
            
            # Thêm phần khuyến nghị
            analysis += "### Khuyến nghị\n\n"
            
            # Khuyến nghị dựa trên loại vấn đề
            issue_types = [issue["type"] for issue in potential_issues]
            
            if "Firewall/Router Block" in issue_types:
                analysis += "- **Firewall/Router Block:** Kiểm tra cấu hình firewall, router và các thiết bị bảo mật. Xem xét logs để xác định các quy tắc chặn đang được kích hoạt.\n\n"
            
            if "SYN Flood/Scan" in issue_types:
                analysis += "- **SYN Flood/Scan:** Triển khai SYN cookies, rate limiting, và các biện pháp bảo vệ DDoS. Tăng cường giám sát các nỗ lực quét cổng.\n\n"
            
            if "ARP Spoofing" in issue_types:
                analysis += "- **ARP Spoofing:** Triển khai ARP cố định (static ARP), sử dụng công cụ phát hiện ARP spoofing, và xem xét triển khai 802.1X hoặc các giải pháp chứng thực mạng khác.\n\n"
            
            if "ICMP Flood/Ping Scan" in issue_types:
                analysis += "- **ICMP Flood/Ping Scan:** Xem xét giới hạn lưu lượng ICMP hoặc chặn ping từ các mạng không đáng tin cậy.\n\n"
        else:
            analysis += "Không phát hiện vấn đề tiềm ẩn đáng kể từ dữ liệu mạng đã phân tích. Các thông số mạng hiện nằm trong ngưỡng bình thường.\n\n"
            analysis += "Tuy nhiên, vẫn nên duy trì việc giám sát mạng liên tục và cập nhật các biện pháp bảo mật để đảm bảo an toàn mạng.\n"
        
        try:
            # Xử lý sâu hơn bằng cách gọi SmolagentGateway
            deep_analysis = self.smolagent_gateway.analyze_traffic_pattern(results)
            
            # Thêm phân tích sâu nếu có
            if deep_analysis and "analysis" in deep_analysis:
                analysis += "\n### Phân tích chuyên sâu từ AI\n\n"
                analysis += deep_analysis["analysis"]
        except Exception as e:
            # Bỏ qua lỗi nếu không gọi được SmolagentGateway
            pass
        
        return analysis
    
    def _analyze_dangerous_parameters(self, results: Dict) -> str:
        """
        Phân tích các thông số nguy hiểm và bất thường trong gói tin.
        
        Args:
            results: Kết quả phân tích PCAP
            
        Returns:
            Phân tích về các thông số nguy hiểm
        """
        if not results:
            return "Không có dữ liệu để phân tích. Vui lòng tải lên file PCAP."
            
        file_name = os.path.basename(self.latest_pcap_file) if self.latest_pcap_file else "đã tải lên"
        analysis = f"# Phân tích thông số nguy hiểm trong lưu lượng mạng\n\n"
        analysis += f"*File: {file_name}*\n\n"
        
        # Danh sách các thông số nguy hiểm phát hiện được
        dangerous_params = []
        
        # 1. Kiểm tra payload độc hại
        if "malicious_payloads" in results:
            mal_payloads = results["malicious_payloads"]
            if mal_payloads:
                dangerous_params.append({
                    "type": "Payload độc hại",
                    "details": f"Phát hiện {len(mal_payloads)} payload đáng ngờ",
                    "severity": "Cao",
                    "examples": [
                        f"{p.get('signature', 'Unknown')} - {p.get('src_ip', 'unknown')} → {p.get('dst_ip', 'unknown')}"
                        for p in mal_payloads[:3]
                    ]
                })
                
                # Phân tích chi tiết
                analysis += "## Payload độc hại\n\n"
                analysis += f"Đã phát hiện {len(mal_payloads)} payload có dấu hiệu độc hại:\n\n"
                
                for i, payload in enumerate(mal_payloads[:5]):
                    src = payload.get("src_ip", "unknown")
                    dst = payload.get("dst_ip", "unknown")
                    signature = payload.get("signature", "Unknown signature")
                    severity = payload.get("severity", "unknown")
                    protocol = payload.get("protocol", "unknown")
                    
                    analysis += f"### Payload #{i+1}: {signature}\n"
                    analysis += f"- **Nguồn:** {src} → **Đích:** {dst}\n"
                    analysis += f"- **Giao thức:** {protocol}\n"
                    analysis += f"- **Mức độ nguy hiểm:** {severity}\n"
                    
                    # Thêm mẫu hex nếu có
                    if "hex_sample" in payload:
                        hex_sample = payload["hex_sample"]
                        analysis += f"- **Mẫu Hex:** `{hex_sample[:50]}...`\n"
                    
                    # Thêm thông tin bổ sung
                    if "additional_info" in payload:
                        analysis += f"- **Thông tin bổ sung:** {payload['additional_info']}\n"
                    
                    analysis += "\n"
                
                if len(mal_payloads) > 5:
                    analysis += f"*...và {len(mal_payloads) - 5} payload độc hại khác...*\n\n"
        
        # 2. Kiểm tra header bất thường
        if "abnormal_headers" in results:
            abnormal_headers = results["abnormal_headers"]
            
            if abnormal_headers:
                total_abnormal = sum(len(instances) for instances in abnormal_headers.values())
                dangerous_params.append({
                    "type": "Header bất thường",
                    "details": f"Phát hiện {total_abnormal} gói tin có header bất thường",
                    "severity": "Trung bình đến Cao",
                    "examples": [
                        f"{header_type}: {len(instances)} gói tin"
                        for header_type, instances in list(abnormal_headers.items())[:3]
                    ]
                })
                
                # Phân tích chi tiết
                analysis += "## Header bất thường\n\n"
                
                for header_type, instances in abnormal_headers.items():
                    analysis += f"### {header_type} ({len(instances)} gói tin)\n\n"
                    
                    for i, instance in enumerate(instances[:3]):
                        src = instance.get("src", "unknown")
                        dst = instance.get("dst", "unknown")
                        details = instance.get("details", "không có chi tiết")
                        
                        analysis += f"**Trường hợp {i+1}:** {src} → {dst}\n"
                        analysis += f"- **Chi tiết:** {details}\n"
                        
                        # Thêm các trường header cụ thể nếu có
                        if "header_fields" in instance:
                            analysis += "- **Header fields:**\n"
                            for field, value in instance["header_fields"].items():
                                analysis += f"  * {field}: `{value}`\n"
                    
                    if len(instances) > 3:
                        analysis += f"*...và {len(instances) - 3} trường hợp khác...*\n\n"
        
        # 3. Kiểm tra TTL bất thường
        if "abnormal_ttl" in results:
            abnormal_ttl = results["abnormal_ttl"]
            
            if abnormal_ttl:
                dangerous_params.append({
                    "type": "TTL bất thường",
                    "details": f"Phát hiện {len(abnormal_ttl)} giá trị TTL bất thường",
                    "severity": "Thấp đến Trung bình",
                    "examples": [
                        f"TTL={ttl_info['ttl']}: {ttl_info['count']} gói tin"
                        for ttl_info in abnormal_ttl[:3]
                    ]
                })
                
                # Phân tích chi tiết
                analysis += "## TTL (Time-to-Live) bất thường\n\n"
                analysis += "Các giá trị TTL bất thường có thể chỉ ra các kỹ thuật né tránh, scan từ xa, hoặc các nỗ lực spoofing:\n\n"
                
                for ttl_info in abnormal_ttl:
                    ttl = ttl_info["ttl"]
                    count = ttl_info["count"]
                    source_ips = ttl_info.get("source_ips", [])
                    
                    analysis += f"### TTL={ttl} ({count} gói tin)\n"
                    
                    # Phân loại vấn đề dựa trên giá trị TTL
                    if ttl < 5:
                        analysis += "- **Cảnh báo:** TTL cực thấp có thể là dấu hiệu của traceroute, tấn công giả mạo hoặc gói tin bị tiêu thụ trong mạng cục bộ\n"
                    elif ttl > 200:
                        analysis += "- **Cảnh báo:** TTL cực cao có thể là dấu hiệu của OS fingerprinting hoặc kỹ thuật né tránh IDS\n"
                    
                    # Hiển thị các IP nguồn
                    if source_ips:
                        if len(source_ips) <= 3:
                            analysis += f"- **IP nguồn:** {', '.join(source_ips)}\n"
                        else:
                            analysis += f"- **IP nguồn:** {', '.join(source_ips[:3])} và {len(source_ips) - 3} IP khác\n"
                    
                    analysis += "\n"
        
        # 4. Kiểm tra kích thước gói tin bất thường
        if "abnormal_sizes" in results:
            abnormal_sizes = results["abnormal_sizes"]
            
            if abnormal_sizes:
                oversized = abnormal_sizes.get("oversized", 0)
                undersized = abnormal_sizes.get("undersized", 0)
                
                if oversized > 0 or undersized > 0:
                    details = []
                    if oversized > 0:
                        details.append(f"{oversized} gói tin quá lớn")
                    if undersized > 0:
                        details.append(f"{undersized} gói tin quá nhỏ")
                    
                    dangerous_params.append({
                        "type": "Kích thước gói tin bất thường",
                        "details": ", ".join(details),
                        "severity": "Trung bình",
                        "examples": []
                    })
                    
                    # Phân tích chi tiết
                    analysis += "## Kích thước gói tin bất thường\n\n"
                    
                    if oversized > 0:
                        analysis += f"### Gói tin quá lớn ({oversized} gói tin)\n\n"
                        analysis += "Gói tin có kích thước lớn bất thường có thể là dấu hiệu của:\n"
                        analysis += "- Tấn công Ping of Death hoặc tấn công Buffer Overflow\n"
                        analysis += "- Nỗ lực phá vỡ các thiết bị mạng hoặc firewall\n"
                        analysis += "- Nỗ lực gửi lượng lớn dữ liệu độc hại qua mạng\n\n"
                    
                    if undersized > 0:
                        analysis += f"### Gói tin quá nhỏ ({undersized} gói tin)\n\n"
                        analysis += "Gói tin có kích thước nhỏ bất thường có thể là dấu hiệu của:\n"
                        analysis += "- Kỹ thuật quét cổng ẩn (stealth scanning)\n"
                        analysis += "- Các gói tin đã bị phân mảnh\n"
                        analysis += "- Nỗ lực né tránh phát hiện\n\n"
        
        # 5. Kiểm tra cổng bất thường
        if "unusual_ports" in results:
            unusual_ports = results["unusual_ports"]
            
            if unusual_ports:
                total_unusual = sum(len(port_info) for port_info in unusual_ports.values())
                
                dangerous_params.append({
                    "type": "Cổng bất thường",
                    "details": f"Phát hiện {total_unusual} cổng bất thường đang được sử dụng",
                    "severity": "Trung bình đến Cao",
                    "examples": []
                })
                
                # Phân tích chi tiết
                analysis += "## Cổng bất thường\n\n"
                
                for port_type, port_info in unusual_ports.items():
                    analysis += f"### {port_type}\n\n"
                    
                    for port, details in sorted(port_info.items(), key=lambda x: x[1]['count'], reverse=True)[:5]:
                        count = details['count']
                        source_ips = details.get('source_ips', [])
                        
                        analysis += f"**Cổng {port}:** {count} kết nối từ {len(source_ips)} IP nguồn\n"
                        
                        # Phân loại mức độ nguy hiểm dựa trên cổng
                        if port in [22, 23, 3389]:
                            analysis += "- **Cảnh báo cao:** Cổng remote access (SSH/Telnet/RDP) - Có thể là nỗ lực truy cập trái phép\n"
                        elif port == 445:
                            analysis += "- **Cảnh báo cao:** Cổng SMB - Thường bị nhắm mục tiêu bởi ransomware và worm\n"
                        elif port in [1433, 3306, 5432]:
                            analysis += "- **Cảnh báo cao:** Cổng database - Có thể là nỗ lực tấn công SQL injection\n"
                        elif port >= 6000 and port <= 7000:
                            analysis += "- **Cảnh báo:** Có thể là dấu hiệu của backdoor hoặc trojan\n"
                        
                        analysis += "\n"
                    
                    if len(port_info) > 5:
                        analysis += f"*...và {len(port_info) - 5} cổng bất thường khác...*\n\n"
        
        # Tổng hợp các thông số nguy hiểm
        if dangerous_params:
            # Sắp xếp theo mức độ nghiêm trọng
            severity_order = {"Cao": 3, "Trung bình đến Cao": 2, "Trung bình": 1, "Thấp đến Trung bình": 0, "Thấp": -1}
            dangerous_params.sort(key=lambda x: severity_order.get(x["severity"], 0), reverse=True)
            
            # Thêm tổng quan vào đầu phân tích
            overview = "## Tóm tắt các thông số nguy hiểm\n\n"
            overview += "| Loại thông số | Mức độ | Chi tiết |\n"
            overview += "|--------------|--------|----------|\n"
            for param in dangerous_params:
                overview += f"| **{param['type']}** | {param['severity']} | {param['details']} |\n"
            
            if any(param["examples"] for param in dangerous_params):
                overview += "\n### Một số ví dụ đáng chú ý:\n\n"
                for param in dangerous_params:
                    if param["examples"]:
                        overview += f"- **{param['type']}:** " + " | ".join(param["examples"][:2]) + "\n"
            
            # Chèn tổng quan vào sau tiêu đề chính
            first_section_pos = analysis.find("\n## ")
            if first_section_pos > 0:
                analysis = analysis[:first_section_pos] + "\n" + overview + analysis[first_section_pos:]
            else:
                analysis += overview
            
            # Thêm phần khuyến nghị
            analysis += "## Khuyến nghị bảo mật\n\n"
            
            # Khuyến nghị dựa trên loại thông số nguy hiểm
            param_types = [param["type"] for param in dangerous_params]
            
            if "Payload độc hại" in param_types:
                analysis += "### Đối với Payload độc hại\n\n"
                analysis += "- Cập nhật IDS/IPS để phát hiện và chặn các payload độc hại\n"
                analysis += "- Kiểm tra các máy có liên quan tới payload độc hại để tìm dấu hiệu nhiễm mã độc\n"
                analysis += "- Cân nhắc triển khai giải pháp Deep Packet Inspection (DPI) để phân tích sâu hơn nội dung gói tin\n\n"
            
            if "Header bất thường" in param_types:
                analysis += "### Đối với Header bất thường\n\n"
                analysis += "- Cấu hình firewall để kiểm tra và lọc gói tin có header bất thường\n"
                analysis += "- Triển khai quy tắc IDS/IPS để phát hiện các header không tuân thủ tiêu chuẩn\n"
                analysis += "- Giám sát các gói tin có header bất thường để xác định nguồn gốc và mục đích\n\n"
            
            if "TTL bất thường" in param_types:
                analysis += "### Đối với TTL bất thường\n\n"
                analysis += "- Giám sát các gói tin có TTL bất thường, đặc biệt là TTL quá thấp hoặc quá cao\n"
                analysis += "- Cấu hình IDS để cảnh báo khi phát hiện TTL bất thường từ các nguồn cụ thể\n"
                analysis += "- Cân nhắc triển khai tường lửa kiểm tra TTL để ngăn chặn các kỹ thuật né tránh\n\n"
            
            if "Kích thước gói tin bất thường" in param_types:
                analysis += "### Đối với Kích thước gói tin bất thường\n\n"
                analysis += "- Cấu hình giới hạn kích thước gói tin tại các thiết bị biên\n"
                analysis += "- Triển khai các biện pháp chống tấn công Buffer Overflow và DoS dựa trên kích thước\n"
                analysis += "- Giám sát đặc biệt các gói tin có kích thước quá lớn hoặc quá nhỏ\n\n"
            
            if "Cổng bất thường" in param_types:
                analysis += "### Đối với Cổng bất thường\n\n"
                analysis += "- Đóng tất cả các cổng không sử dụng trên các thiết bị mạng và máy chủ\n"
                analysis += "- Giám sát chặt chẽ các cổng nhạy cảm (22, 23, 3389, 445, các cổng database...)\n"
                analysis += "- Kiểm tra các kết nối đến các cổng bất thường để xác định xem có phải là backdoor hay trojan\n"
                analysis += "- Triển khai chính sách kiểm soát truy cập mạng (NAC) và phân đoạn mạng để hạn chế tác động\n\n"
        else:
            analysis += "## Kết quả phân tích\n\n"
            analysis += "Không phát hiện thông số nguy hiểm đáng kể trong các gói tin. Các thông số mạng hiện nằm trong ngưỡng bình thường.\n\n"
            analysis += "## Khuyến nghị bảo mật\n\n"
            analysis += "Mặc dù không phát hiện thông số nguy hiểm, vẫn nên:\n\n"
            analysis += "- Duy trì việc giám sát mạng liên tục\n"
            analysis += "- Cập nhật các biện pháp bảo mật thường xuyên\n"
            analysis += "- Thực hiện quét và phân tích lưu lượng mạng định kỳ\n"
            analysis += "- Theo dõi các cảnh báo bảo mật từ các nhà cung cấp và cộng đồng\n"
        
        try:
            # Xử lý sâu hơn bằng cách gọi SmolagentGateway
            deep_analysis = self.smolagent_gateway.analyze_attack_indicators(results)
            
            # Thêm phân tích sâu nếu có
            if deep_analysis and "analysis" in deep_analysis:
                analysis += "## Phân tích chuyên sâu từ AI\n\n"
                analysis += deep_analysis["analysis"]
        except Exception as e:
            # Bỏ qua lỗi nếu không gọi được SmolagentGateway
            pass
        
        return analysis
    
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

        # Kiểm tra cờ TCP bất thường
        if "tcp_flags" in results:
            tcp_flags = results["tcp_flags"]
            total_flags = sum(tcp_flags.values())
            
            if total_flags > 0:
                # Kiểm tra RST cao
                rst_count = tcp_flags.get("RST", 0)
                if rst_count > 0:
                    rst_percentage = (rst_count / total_flags) * 100
                    if rst_percentage > 15:
                        message += f"⚠️ **Tỷ lệ cờ TCP RST cao: {rst_percentage:.1f}%** - Có thể có firewall đang chặn kết nối hoặc dịch vụ không phản hồi.\n\n"
                        risks_found = True
                
                # Kiểm tra SYN/ACK mất cân đối
                syn_count = tcp_flags.get("SYN", 0)
                ack_count = tcp_flags.get("ACK", 0)
                
                if syn_count > 0 and ack_count > 0:
                    syn_ack_ratio = syn_count / ack_count
                    if syn_ack_ratio > 1.5:
                        message += f"⚠️ **Tỷ lệ SYN/ACK bất thường: {syn_ack_ratio:.1f}:1** - Có thể có quét cổng hoặc tấn công SYN flood.\n\n"
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
        message += "- Phân tích chi tiết các cờ TCP và ý nghĩa của chúng\n"
        message += "- Dự đoán các vấn đề có thể xảy ra (như bị firewall chặn, tấn công...)\n"
        message += "- Phân tích thông số nguy hiểm trong gói tin (payload độc hại, header bất thường, TTL...)\n"

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