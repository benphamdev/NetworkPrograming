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
        
        # Gọi _get_osi_analysis từ chat_handler
        return self.chat_handler._get_osi_analysis(results)
    
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