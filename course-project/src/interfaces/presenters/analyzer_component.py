"""
Analyzer Component - Xử lý phân tích PCAP và tạo báo cáo
"""
from typing import Dict, Tuple, List

from src.interfaces.presenters.base_presenter import BasePresenter
from src.interfaces.presenters.chat_handler import ChatHandler
from src.interfaces.presenters.summary_creator import SummaryCreator
from src.interfaces.presenters.pcap_analyzer import PCAPAnalyzer
from src.interfaces.presenters.chart_creator import ChartCreator
from src.interfaces.gateways.smolagent_gateway import SmolagentGateway

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
        self.smolagent_gateway = SmolagentGateway()
        self.summary_creator = SummaryCreator()
        self.pcap_analyzer = PCAPAnalyzer(self.base_presenter.controller, self.chart_creator)
        self.chat_handler = ChatHandler()
        self.chat_history = []
    
    def create_osi_analysis(self, results: Dict) -> str:
        """
        Tạo phân tích AI cho lưu lượng mạng theo mô hình OSI sử dụng SmolagentGateway.
        
        Args:
            results: Kết quả phân tích từ file PCAP
            
        Returns:
            Phân tích chi tiết theo mô hình OSI
        """
        # Cập nhật thông tin file hiện tại cho chat handler
        self.chat_handler.latest_pcap_file = self.base_presenter.latest_pcap_file
        
        # Gọi _get_osi_analysis từ chat_handler và đảm bảo trả về chuỗi
        response = self.chat_handler._get_osi_analysis(results)
        
        # Kiểm tra và đảm bảo phản hồi là chuỗi
        if not isinstance(response, str):
            try:
                if isinstance(response, dict) and "analysis" in response:
                    return response["analysis"]
                else:
                    return str(response)
            except Exception:
                return "Không thể hiển thị kết quả phân tích OSI."
        
        return response
    
    def create_ai_chat_response(self, query: str, results: Dict) -> str:
        """
        Tạo phản hồi cho hội thoại chat dựa trên truy vấn của người dùng và kết quả phân tích.
        
        Args:
            query: Truy vấn của người dùng
            results: Kết quả phân tích PCAP từ file đã tải lên
            
        Returns:
            Phản hồi được tạo bởi AI
        """
        # Cập nhật thông tin file hiện tại cho chat handler
        self.chat_handler.latest_pcap_file = self.base_presenter.latest_pcap_file
        
        # Chuẩn bị truy vấn cho phân tích cờ TCP hoặc dự đoán vấn đề
        query_lower = query.lower()
        
        # Kiểm tra nếu truy vấn về phân tích cờ TCP
        if "cờ tcp" in query_lower or "tcp flag" in query_lower or "phân tích cờ" in query_lower:
            return self.chat_handler._analyze_tcp_flags(results)
            
        # Kiểm tra nếu truy vấn về dự đoán vấn đề
        if "dự đoán" in query_lower or "có thể xảy ra" in query_lower or "khả năng" in query_lower:
            return self.chat_handler._predict_network_issues(results)
            
        # Kiểm tra nếu truy vấn về thông số nguy hiểm
        if "thông số nguy hiểm" in query_lower or "gói tin nguy hiểm" in query_lower or "thông số bất thường" in query_lower or "payload độc hại" in query_lower:
            return self.chat_handler._analyze_dangerous_parameters(results)
        
        # Gọi create_ai_chat_response từ chat_handler
        return self.chat_handler.create_ai_chat_response(query, results)
    
    def update_chat_history(self, query: str, results: Dict) -> List[Dict[str, str]]:
        """
        Cập nhật lịch sử chat và trả về phản hồi mới.
        
        Args:
            query: Truy vấn của người dùng
            results: Kết quả phân tích PCAP
            
        Returns:
            Lịch sử chat đã cập nhật
        """
        # Cập nhật thông tin file hiện tại cho chat handler
        self.chat_handler.latest_pcap_file = self.base_presenter.latest_pcap_file
        
        # Gọi update_chat_history từ chat_handler
        self.chat_history = self.chat_handler.update_chat_history(query, results)
        return self.chat_history
    
    def analyze_raw_packets(self, packets: List, custom_prompt: str = None) -> str:
        """
        Phân tích trực tiếp danh sách gói tin thô sử dụng SmolagentGateway.
        
        Args:
            packets: Danh sách các gói tin cần phân tích
            custom_prompt: Prompt tùy chỉnh để hướng dẫn AI phân tích (nếu không cung cấp sẽ dùng prompt mặc định)
            
        Returns:
            Phân tích chi tiết dưới dạng chuỗi văn bản
        """
        return self.chat_handler.analyze_raw_packets(packets, custom_prompt)
    
    def analyze_raw_packets_with_osi(self, packets: List, custom_prompt: str = None) -> str:
        """
        Phân tích danh sách gói tin thô theo mô hình OSI sử dụng SmolagentGateway.
        
        Args:
            packets: Danh sách các gói tin cần phân tích
            custom_prompt: Prompt tùy chỉnh để hướng dẫn AI phân tích (nếu không cung cấp sẽ dùng prompt mặc định)
            
        Returns:
            Phân tích theo mô hình OSI dưới dạng chuỗi văn bản
        """
        return self.chat_handler.analyze_raw_packets_with_osi(packets, custom_prompt)
    
    def analyze_tcp_flags_from_raw_packets(self, packets: List) -> str:
        """
        Phân tích chi tiết về các cờ TCP từ danh sách gói tin thô.
        
        Args:
            packets: Danh sách các gói tin cần phân tích
            
        Returns:
            Phân tích về các cờ TCP dưới dạng chuỗi văn bản
        """
        return self.chat_handler.analyze_tcp_flags_raw(packets)
    
    def get_initial_chat_message(self, results: Dict) -> str:
        """
        Lấy tin nhắn chat ban đầu từ ChatHandler.
        
        Args:
            results: Kết quả phân tích PCAP
            
        Returns:
            Tin nhắn chat ban đầu
        """
        # Cập nhật thông tin file hiện tại cho chat handler
        self.chat_handler.latest_pcap_file = self.base_presenter.latest_pcap_file
        
        # Gọi get_initial_chat_message từ chat_handler
        return self.chat_handler.get_initial_chat_message(results)
    
    def analyze_pcap(self, pcap_file) -> Tuple:
        """
        Phân tích file pcap và trả về kết quả đã định dạng cho UI.
        
        Args:
            pcap_file: File PCAP để phân tích
            
        Returns:
            Tuple (summary, attack_table, protocol_chart, attack_chart, flow_graph, tcp_visualizations, initial_chat_message)
        """
        # Sử dụng pcap_analyzer để phân tích file
        result = self.pcap_analyzer.analyze_pcap(pcap_file)
        
        # Cập nhật thông tin trong base_presenter
        self.base_presenter.latest_pcap_file = self.pcap_analyzer.latest_pcap_file
        self.base_presenter.latest_results = self.pcap_analyzer.latest_results
        
        # Cập nhật thông tin file hiện tại cho chat handler
        self.chat_handler.latest_pcap_file = self.pcap_analyzer.latest_pcap_file
        
        # Trả về kết quả phân tích
        return result