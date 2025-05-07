"""
Gradio Presenter - Web-based interface for packet analysis using Gradio.
"""
import gradio as gr
from typing import Tuple

from src.interfaces.presenters.base_presenter import BasePresenter
from src.interfaces.presenters.chart_creator import ChartCreator
from src.interfaces.presenters.analyzer_component import AnalyzerComponent
from src.interfaces.presenters.monitoring_component import MonitoringComponent

class GradioPresenter:
    """Web-based presenter for packet analysis results using Gradio."""
    
    def __init__(self, controller):
        """
        Initialize the Gradio presenter.
        
        Args:
            controller: PacketAnalyzerController instance
        """
        # Khởi tạo các components
        self.base_presenter = BasePresenter(controller)
        self.chart_creator = ChartCreator()
        self.analyzer = AnalyzerComponent(self.base_presenter)
        self.monitoring = MonitoringComponent(self.base_presenter)
        
    def analyze_pcap(self, pcap_file) -> Tuple:
        """Phân tích file pcap và trả về kết quả cho UI."""
        return self.analyzer.analyze_pcap(pcap_file)
    
    def start_monitoring(self, duration_minutes: int) -> str:
        """Bắt đầu giám sát thời gian thực."""
        return self.monitoring.start_monitoring(duration_minutes)
    
    def display_attack_details(self, hours: int) -> Tuple:
        """Hiển thị chi tiết tấn công."""
        return self.monitoring.display_attack_details(hours)
    
    def display_flow_stats(self, hours: int) -> Tuple:
        """Hiển thị thống kê luồng."""
        return self.monitoring.display_flow_stats(hours)
        
    def launch_interface(self):
        """Launch the Gradio interface."""
        with gr.Blocks(title="Network Packet Analyzer", theme=gr.themes.Soft()) as interface:
            gr.Markdown("# Network Packet Analyzer")
            gr.Markdown("Công cụ phân tích gói tin mạng để phát hiện các cuộc tấn công như ARP spoofing, SYN flood và ICMP flood")
            
            # Tab phân tích PCAP
            with gr.Tab("Phân tích PCAP"):
                with gr.Row():
                    with gr.Column(scale=1):
                        pcap_file = gr.File(label="Tải lên file PCAP")
                        analyze_btn = gr.Button("Phân tích", variant="primary")
                    
                    with gr.Column(scale=2):
                        analysis_summary = gr.Markdown("Tải lên file PCAP để bắt đầu phân tích...")
                
                with gr.Row():
                    attack_table = gr.DataFrame(label="Các cuộc tấn công đã phát hiện")
                
                with gr.Row():
                    with gr.Column():
                        protocol_chart = gr.Plot(label="Phân bố giao thức")
                    with gr.Column():
                        attack_chart = gr.Plot(label="Phân bố tấn công")
                
                with gr.Row():
                    with gr.Column():
                        flow_graph = gr.Plot(label="Biểu đồ luồng mạng")
                    with gr.Column():
                        ai_analysis = gr.Markdown(label="Phân tích AI")
                
                with gr.Row():
                    tcp_viz = gr.Plot(label="Phân tích TCP")
            
            # Tab phân tích AI chi tiết
            with gr.Tab("Phân tích AI chi tiết"):
                with gr.Row():
                    with gr.Column():
                        gr.Markdown("### Phân tích AI chi tiết về luồng TCP và các tấn công")
                        ai_analysis_detail = gr.Markdown("Tải lên file PCAP trong tab 'Phân tích PCAP' để xem phân tích chi tiết...")
                    
                with gr.Row():
                    with gr.Column():
                        tcp_flags_chart = gr.Plot(label="Phân bố cờ TCP")
                    with gr.Column():
                        tcp_attack_chart = gr.Plot(label="Phân tích các cuộc tấn công TCP")
            
            # Tab giám sát thời gian thực
            with gr.Tab("Giám sát thời gian thực"):
                with gr.Row():
                    with gr.Column(scale=1):
                        duration_slider = gr.Slider(
                            minimum=1, maximum=30, step=1, value=5,
                            label="Thời gian giám sát (phút)"
                        )
                        monitor_btn = gr.Button("Bắt đầu giám sát", variant="primary")
                    
                    with gr.Column(scale=2):
                        monitoring_results = gr.Markdown("Thiết lập thời gian và nhấn 'Bắt đầu giám sát'...")
            
            # Tab chi tiết tấn công
            with gr.Tab("Chi tiết tấn công"):
                with gr.Row():
                    with gr.Column(scale=1):
                        attack_hours = gr.Number(value=24, label="Số giờ cần xem")
                        attack_btn = gr.Button("Xem chi tiết tấn công", variant="primary")
                    
                    with gr.Column(scale=2):
                        attack_summary = gr.Markdown("Nhấn 'Xem chi tiết tấn công' để hiển thị...")
                
                with gr.Row():
                    attacks_detail_table = gr.DataFrame(label="Chi tiết các cuộc tấn công")
                
                with gr.Row():
                    attacks_detail_chart = gr.Plot(label="Phân tích tấn công")
            
            # Tab thống kê luồng
            with gr.Tab("Thống kê luồng"):
                with gr.Row():
                    with gr.Column(scale=1):
                        stats_hours = gr.Number(value=1, label="Số giờ cần xem")
                        stats_btn = gr.Button("Xem thống kê luồng", variant="primary")
                    
                    with gr.Column(scale=2):
                        stats_summary = gr.Markdown("Nhấn 'Xem thống kê luồng' để hiển thị...")
                
                with gr.Row():
                    stats_chart = gr.Plot(label="Phân bố giao thức")
            
            # Kết nối các xử lý sự kiện
            analyze_btn.click(
                fn=self.analyze_pcap,
                inputs=[pcap_file],
                outputs=[analysis_summary, attack_table, protocol_chart, attack_chart, flow_graph, ai_analysis, tcp_viz]
            )
            
            analyze_btn.click(
                fn=lambda pcap_file: (
                    self.analyzer.create_tcp_analysis(self.base_presenter.latest_results) 
                        if self.base_presenter.latest_results else "Chưa có dữ liệu phân tích",
                    self.chart_creator.create_tcp_visualizations(self.base_presenter.latest_results),
                    self.chart_creator.create_attack_severity_chart(
                        self.base_presenter.latest_results.get("attacks", []) 
                        if self.base_presenter.latest_results else []
                    )
                ),
                inputs=[pcap_file],
                outputs=[ai_analysis_detail, tcp_flags_chart, tcp_attack_chart]
            )
            
            monitor_btn.click(
                fn=self.start_monitoring,
                inputs=[duration_slider],
                outputs=[monitoring_results]
            )
            
            attack_btn.click(
                fn=self.display_attack_details,
                inputs=[attack_hours],
                outputs=[attack_summary, attacks_detail_table, attacks_detail_chart]
            )
            
            stats_btn.click(
                fn=self.display_flow_stats,
                inputs=[stats_hours],
                outputs=[stats_summary, stats_chart]
            )
        
        # Khởi chạy giao diện
        interface.launch(share=False)