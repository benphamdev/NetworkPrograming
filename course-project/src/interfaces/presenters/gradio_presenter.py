# filepath: d:\03_WorkSpace\01_SourceCode\04_NetworkJava\course-project\src\interfaces\presenters\gradio_presenter.py
"""
Gradio Presenter - Web-based interface for packet analysis using Gradio.
It includes components for analyzing PCAP files, visualizing results, and providing real-time monitoring.
"""
from typing import Tuple

from src.interfaces.presenters.analyzer_component import AnalyzerComponent
from src.interfaces.presenters.base_presenter import BasePresenter
from src.interfaces.presenters.chart_creator import ChartCreator
from src.interfaces.presenters.chat_interface import ChatInterface
from src.interfaces.presenters.dashboard_presenter import DashboardPresenter
from src.interfaces.presenters.report_manager import ReportManager
from src.interfaces.presenters.ui.ui_event_handlers import UIEventHandlers
from src.interfaces.presenters.ui.ui_layout_creator import UILayoutCreator


class GradioPresenter:
    """Web-based presenter for packet analysis results using Gradio."""

    def __init__(self, controller):
        """
        Initialize the Gradio presenter.
        
        Args:
            controller: PacketAnalyzerController instance
        """
        # Khởi tạo các components cốt lõi
        self.base_presenter = BasePresenter(controller)
        self.chart_creator = ChartCreator()
        self.analyzer = AnalyzerComponent(self.base_presenter)

        # Khởi tạo các module mới
        self.chat_interface = ChatInterface(self.base_presenter, self.analyzer)
        self.dashboard = DashboardPresenter(self.base_presenter, self.chart_creator)
        self.report_manager = ReportManager(self.base_presenter)
        self.ui_creator = UILayoutCreator(self)

    def analyze_pcap(self, pcap_file) -> Tuple:
        """Phân tích file pcap và trả về kết quả cho UI."""
        # Lưu thông tin về file hiện tại
        if pcap_file:
            self.base_presenter.latest_pcap_file = pcap_file.name if hasattr(pcap_file, 'name') else pcap_file

        # Gọi hàm phân tích từ analyzer_component và bỏ qua giá trị cuối cùng (initial_chat_message)
        results = self.analyzer.analyze_pcap(pcap_file)
        if results and len(results) == 7:
            # Chỉ trả về 6 giá trị đầu tiên
            return results[0], results[1], results[2], results[3], results[4], results[5]
        return results

    def get_analysis_results(self) -> Tuple:
        """Lấy kết quả phân tích hiện tại mà không thực hiện phân tích lại."""
        if not self.base_presenter.latest_results:
            # Nếu chưa có kết quả, trả về giá trị mặc định
            empty_msg = "Chưa có dữ liệu phân tích. Vui lòng tải lên và phân tích file PCAP."
            empty_chart = self.chart_creator._create_empty_chart("Không có dữ liệu")
            return empty_msg, None, empty_chart, empty_chart, empty_chart, empty_chart

        # Cập nhật thông tin trong analyzer.pcap_analyzer
        self.analyzer.pcap_analyzer.latest_pcap_file = self.base_presenter.latest_pcap_file
        self.analyzer.pcap_analyzer.latest_results = self.base_presenter.latest_results

        # Tạo tóm tắt
        summary = self.analyzer.pcap_analyzer._create_summary(
            self.base_presenter.latest_pcap_file,
            self.base_presenter.latest_results
        )

        # Tạo bảng tấn công
        attack_table = self.analyzer.pcap_analyzer._format_attack_table(
            self.base_presenter.latest_results.get("attacks", [])
        )

        # Tạo biểu đồ giao thức
        protocol_chart = self.chart_creator.create_protocol_chart(self.base_presenter.latest_results)

        # Tạo biểu đồ mức độ nghiêm trọng của tấn công
        attack_chart = self.chart_creator.create_attack_severity_chart(
            self.base_presenter.latest_results.get("attacks", [])
        )

        # Tạo đồ thị luồng
        flow_graph = self.chart_creator.create_flow_graph(self.base_presenter.latest_results)

        # Tạo trực quan hóa cụ thể cho TCP
        tcp_visualizations = self.chart_creator.create_tcp_visualizations(self.base_presenter.latest_results)

        return summary, attack_table, protocol_chart, attack_chart, flow_graph, tcp_visualizations

    def get_detailed_tcp_analysis(self) -> str:
        """Lấy phân tích chi tiết theo mô hình OSI cho tab chi tiết AI."""
        if not self.base_presenter.latest_pcap_file:
            return "Chưa có dữ liệu phân tích. Vui lòng tải lên file PCAP trước."

        try:
            pcap_file = self.base_presenter.latest_pcap_file

            # Tạo prompt tùy chỉnh cho phân tích OSI
            custom_prompt = """
            Là một chuyên gia điều tra số trong lĩnh vực mạng (Network Forensics Expert), hãy phân tích chi tiết lưu lượng mạng dưới đây theo mô hình OSI (7 tầng).
            Tập trung phân tích sâu về các dấu hiệu bất thường và các vấn đề bảo mật tiềm ẩn ở mỗi tầng.
            Đề xuất các use case phân tích mới để phát hiện tấn công hoặc vấn đề mạng ngoài những gì hệ thống hiện tại đã phát hiện.
            """

            # Sử dụng pcap_analyzer.analyze_pcap_raw_packets trực tiếp với file và prompt tùy chỉnh
            return self.analyzer.pcap_analyzer.analyze_pcap_raw_packets(pcap_file, custom_prompt)
        except Exception as e:
            return f"Lỗi khi phân tích gói tin: {str(e)}\n\nVui lòng tải lại file PCAP và thử lại."

    def analyze_raw_packets(self, pcap_file, prompt: str = None) -> str:
        """
        Phân tích các gói tin thô từ file PCAP với prompt tùy chỉnh.
        
        Args:
            pcap_file: File PCAP để phân tích
            prompt: Prompt tùy chỉnh để hướng dẫn AI phân tích
            
        Returns:
            Phân tích chi tiết dưới dạng chuỗi văn bản markdown
        """
        if not pcap_file:
            return "Vui lòng tải lên file PCAP trước khi phân tích."  # Cập nhật thông tin file hiện tại
        file_path = pcap_file.name if hasattr(pcap_file, 'name') else pcap_file
        self.base_presenter.latest_pcap_file = file_path

        # Phân tích với prompt tùy chỉnh
        return self.analyzer.pcap_analyzer.analyze_pcap_raw_packets(pcap_file, prompt)

    def launch_interface(self):
        """Launch the Gradio interface."""
        # Tạo giao diện UI
        interface, components = self.ui_creator.create_interface()

        # Kết nối các sự kiện
        event_handler = UIEventHandlers(self, components)
        event_handler.connect_events(interface)

        # Khởi chạy giao diện
        interface.launch(share=False)
