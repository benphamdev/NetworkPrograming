"""
Gradio Presenter - Web-based interface for packet analysis using Gradio.
"""
import gradio as gr
from typing import Tuple
import os

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
        
        # Lấy thông tin từ kết quả phân tích đã được lưu
        results = self.base_presenter.latest_results
        
        # Tạo tóm tắt
        summary = f"## Kết quả phân tích\n\n"
        if self.base_presenter.latest_pcap_file:
            summary += f"File: {os.path.basename(self.base_presenter.latest_pcap_file)}\n\n"
        
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
        
        # Tạo trực quan hóa cụ thể cho TCP
        tcp_visualizations = self.chart_creator.create_tcp_visualizations(results)
        
        return summary, attack_table, protocol_chart, attack_chart, flow_graph, tcp_visualizations
    
    def get_detailed_tcp_analysis(self) -> str:
        """Lấy phân tích chi tiết TCP cho tab chi tiết AI."""
        if not self.base_presenter.latest_results:
            return "Chưa có dữ liệu phân tích. Vui lòng tải lên file PCAP trước."
        
        return self.analyzer.create_tcp_analysis(self.base_presenter.latest_results)
    
    def start_monitoring(self, duration_minutes: int) -> str:
        """Bắt đầu giám sát thời gian thực."""
        return self.monitoring.start_monitoring(duration_minutes)
    
    def display_attack_details(self, hours: int) -> Tuple:
        """Hiển thị chi tiết tấn công."""
        return self.monitoring.display_attack_details(hours)
    
    def display_flow_stats(self, hours: int) -> Tuple:
        """Hiển thị thống kê luồng."""
        return self.monitoring.display_flow_stats(hours)
        
    def process_chat_query(self, query: str) -> str:
        """
        Xử lý truy vấn chat và trả về phản hồi dựa trên file PCAP đã tải lên.
        
        Args:
            query: Truy vấn người dùng
            
        Returns:
            Phản hồi từ AI dựa trên phân tích file PCAP
        """
        # Kiểm tra có file và kết quả chưa
        has_file = self.base_presenter.latest_pcap_file is not None
        has_results = self.base_presenter.latest_results is not None
        
        if not has_file:
            return "Vui lòng tải lên file PCAP trước khi chat. Tôi cần dữ liệu từ file để phân tích và tư vấn."
        
        if not has_results:
            file_name = os.path.basename(self.base_presenter.latest_pcap_file)
            return f"Tôi đã nhận file {file_name} nhưng chưa được phân tích. Vui lòng nhấn nút 'Phân tích' trong tab 'Phân tích PCAP' và quay lại đây để tư vấn."
            
        # Log thông tin để debug
        pcap_file = self.base_presenter.latest_pcap_file
        pcap_info = f"(File đang phân tích: {pcap_file})" if pcap_file else "(Không có file)"
        
        # Sử dụng phương thức create_ai_chat_response từ AnalyzerComponent với context từ file
        response = self.analyzer.create_ai_chat_response(query, self.base_presenter.latest_results)
        
        # Thêm metadata về file đang được sử dụng nếu cần
        # response += f"\n\n_Phân tích dựa trên file: {os.path.basename(pcap_file)}_" if pcap_file else ""
        
        return response
        
    def update_chat(self, user_message, chat_history):
        """
        Cập nhật lịch sử chat với truy vấn mới của người dùng, sử dụng context từ file PCAP.
        
        Args:
            user_message: Truy vấn của người dùng
            chat_history: Lịch sử chat hiện tại trong định dạng Gradio
            
        Returns:
            Cặp (truy vấn đã xóa, lịch sử chat đã cập nhật)
        """
        if not user_message:
            return "", chat_history
            
        # Kiểm tra có file và kết quả chưa
        has_file = self.base_presenter.latest_pcap_file is not None
        has_results = self.base_presenter.latest_results is not None
        
        if not has_file:
            bot_response = "Vui lòng tải lên file PCAP trước khi chat. Tôi cần phân tích file để cung cấp tư vấn chính xác về rủi ro mạng."
            chat_history.append([user_message, bot_response])
            return "", chat_history
        
        if not has_results:
            file_name = os.path.basename(self.base_presenter.latest_pcap_file)
            bot_response = f"Tôi đã nhận file {file_name} nhưng chưa được phân tích. Vui lòng nhấn nút 'Phân tích' trong tab 'Phân tích PCAP' và quay lại đây để tư vấn."
            chat_history.append([user_message, bot_response])
            return "", chat_history
        
        # Tạo phản hồi từ AI dựa trên context từ file PCAP
        bot_response = self.process_chat_query(user_message)
        
        # Thêm vào lịch sử chat ở định dạng Gradio [user_msg, bot_msg]
        chat_history.append([user_message, bot_response])
        
        # Đồng thời cập nhật lịch sử chat trong analyzer để lưu trữ toàn bộ cuộc hội thoại
        self.analyzer.update_chat_history(user_message, self.base_presenter.latest_results)
        
        # Xóa truy vấn và trả về lịch sử đã cập nhật
        return "", chat_history
    
    def clear_chat(self):
        """
        Xóa lịch sử chat.
        
        Returns:
            Tuple (lịch sử chat trống, truy vấn trống)
        """
        # Đặt lại lịch sử chat trong analyzer
        self.analyzer.chat_history = []
        
        # Nếu có kết quả phân tích, thêm tin nhắn chào mừng mới
        if self.base_presenter.latest_results:
            initial_message = self.analyzer.get_initial_chat_message(self.base_presenter.latest_results)
            self.analyzer.chat_history = [{"role": "assistant", "content": initial_message}]
            # Trả về phiên bản định dạng gradio của tin nhắn chào mừng
            return [[None, initial_message]], ""
        
        # Nếu không có kết quả phân tích, trả về lịch sử trống
        return [], ""

    def launch_interface(self):
        """Launch the Gradio interface."""
        with gr.Blocks(title="Network Packet Analyzer", theme=gr.themes.Soft()) as interface:
            gr.Markdown("# Network Packet Analyzer")
            gr.Markdown("Công cụ phân tích gói tin mạng để phát hiện các cuộc tấn công như ARP spoofing, SYN flood và ICMP flood")
            
            # Biến state để lưu thông tin file hiện tại
            current_file_info = gr.State("")
            
            # Tab phân tích PCAP
            with gr.Tab("Phân tích PCAP"):
                with gr.Row():
                    with gr.Column(scale=1):
                        pcap_file = gr.File(label="Tải lên file PCAP")
                        analyze_btn = gr.Button("Phân tích", variant="primary")
                    
                    with gr.Column(scale=2):
                        analysis_summary = gr.Markdown("Tải lên file PCAP để bắt đầu phân tích...")
                        current_file_display = gr.Markdown("Chưa có file nào được tải lên")
                
                with gr.Row():
                    attack_table = gr.DataFrame(label="Các cuộc tấn công đã phát hiện")
                
                with gr.Row():
                    with gr.Column():
                        protocol_chart = gr.Plot(label="Phân bố giao thức")
                    with gr.Column():
                        attack_chart = gr.Plot(label="Phân bố tấn công")
                
                with gr.Row():
                    flow_graph = gr.Plot(label="Biểu đồ luồng mạng")
                
                with gr.Row():
                    tcp_viz = gr.Plot(label="Phân tích TCP")
            
            # Tab ChatBox Tư vấn rủi ro mạng
            with gr.Tab("ChatBox Tư Vấn"):
                with gr.Row():
                    with gr.Column(scale=3):
                        chat_history = gr.Chatbot(
                            label="Tư vấn rủi ro mạng",
                            height=500,
                            render=True,
                            elem_id="chatbox"
                        )
                    
                    with gr.Column(scale=1):
                        gr.Markdown("### Tư vấn rủi ro mạng")
                        current_chat_file = gr.Markdown("File đang phân tích: *Chưa có file*")
                        gr.Markdown("""
                        Hỏi các câu hỏi về:
                        - Rủi ro mạng phát hiện được
                        - Tấn công và giảm thiểu
                        - Kết nối TCP
                        - Phân tích giao thức
                        """)
                        
                        gr.Markdown("---")
                        gr.Markdown("#### Các câu hỏi gợi ý:")
                        gr.Markdown("""
                        - Phân tích rủi ro mạng trong dữ liệu
                        - Cách giảm thiểu các cuộc tấn công đã phát hiện
                        - File này có phát hiện tấn công nào không?
                        - Phân tích các kết nối TCP bất thường
                        """)
                        
                        clear_chat_btn = gr.Button("Xóa lịch sử chat", variant="secondary")
                
                with gr.Row():
                    user_question = gr.Textbox(
                        label="Nhập câu hỏi về rủi ro mạng",
                        placeholder="Ví dụ: Phân tích rủi ro mạng trong file PCAP tôi vừa tải lên...",
                        max_lines=3
                    )
                    submit_btn = gr.Button("Gửi", variant="primary")
            
            # Tab phân tích AI chi tiết
            with gr.Tab("Phân tích AI chi tiết"):
                with gr.Row():
                    with gr.Column():
                        gr.Markdown("### Phân tích AI chi tiết về luồng TCP và các tấn công")
                        ai_analysis_detail = gr.Markdown("Tải lên file PCAP trong tab 'Phân tích PCAP' để xem phân tích chi tiết...")
                        refresh_detail_btn = gr.Button("Làm mới phân tích", variant="secondary")
                    
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
            
            # Hàm cập nhật thông tin file
            def update_file_info(file):
                if file and isinstance(file, str):
                    file_info = f"File đang phân tích: **{os.path.basename(file)}**"
                    return file_info, file_info
                elif file and hasattr(file, 'name'):
                    file_info = f"File đang phân tích: **{os.path.basename(file.name)}**"
                    return file_info, file_info
                return "Chưa có file nào được tải lên", "File đang phân tích: *Chưa có file*"
            
            # Kết nối các xử lý sự kiện - cập nhật tất cả các tab khi nhấn phân tích
            def analyze_and_update_all_tabs(pcap_file):
                """Phân tích file PCAP và cập nhật tất cả các tab cùng một lúc."""
                # Phân tích PCAP chính
                main_results = self.analyze_pcap(pcap_file)
                
                # Tạo dữ liệu cho tab Phân tích AI chi tiết
                tcp_analysis = self.get_detailed_tcp_analysis()
                tcp_flags = self.chart_creator.create_tcp_flags_chart(self.base_presenter.latest_results) if self.base_presenter.latest_results else self.chart_creator._create_empty_chart("Không có dữ liệu")
                tcp_attack = self.chart_creator.create_tcp_attack_chart(self.base_presenter.latest_results) if self.base_presenter.latest_results else self.chart_creator._create_empty_chart("Không có dữ liệu")
                
                # Tạo tin nhắn chat ban đầu
                chat_msg = [[None, self.analyzer.get_initial_chat_message(self.base_presenter.latest_results)]]
                
                # Cập nhật thông tin file
                file_info = ""
                chat_file_info = ""
                if pcap_file:
                    filename = os.path.basename(pcap_file.name if hasattr(pcap_file, 'name') else pcap_file)
                    file_info = f"File đang phân tích: **{filename}**"
                    chat_file_info = file_info
                else:
                    file_info = "Chưa có file nào được tải lên"
                    chat_file_info = "File đang phân tích: *Chưa có file*"
                
                # Trả về kết quả cho tất cả các tab
                return (*main_results, file_info, chat_file_info, chat_msg, tcp_analysis, tcp_flags, tcp_attack)
            
            # Kết nối sự kiện nhấn phân tích với tất cả các đầu ra cần cập nhật
            analyze_btn.click(
                fn=analyze_and_update_all_tabs,
                inputs=[pcap_file],
                outputs=[
                    # Tab Phân tích PCAP
                    analysis_summary, attack_table, protocol_chart, attack_chart, flow_graph, tcp_viz,
                    # Thông tin file
                    current_file_display, current_chat_file,
                    # Tab ChatBox Tư Vấn
                    chat_history,
                    # Tab Phân tích AI chi tiết
                    ai_analysis_detail, tcp_flags_chart, tcp_attack_chart
                ]
            )
            
            # Cập nhật thông tin file ngay khi tải lên
            pcap_file.change(
                fn=update_file_info,
                inputs=[pcap_file],
                outputs=[current_file_display, current_chat_file]
            )
            
            # Cập nhật chatbox khi tải file lên
            def init_chat_on_upload(file):
                if file:
                    # Phân tích sơ qua file để cập nhật self.base_presenter.latest_pcap_file
                    file_path = file.name if hasattr(file, 'name') else file
                    self.base_presenter.latest_pcap_file = file_path
                    # Trả về placeholder message trước khi phân tích
                    return [[None, f"Đã nhận file {os.path.basename(file_path)}. Nhấn nút 'Phân tích' để tiến hành phân tích file."]]
                return [[None, "Chào bạn! Tôi là trợ lý phân tích mạng. Vui lòng tải lên file PCAP để bắt đầu phân tích."]]
            
            pcap_file.change(
                fn=init_chat_on_upload,
                inputs=[pcap_file],
                outputs=[chat_history]
            )
            
            # Kết nối sự kiện chat
            submit_btn.click(
                fn=self.update_chat,
                inputs=[user_question, chat_history],
                outputs=[user_question, chat_history]
            )
            
            # Cũng cho phép người dùng nhấn Enter để gửi
            user_question.submit(
                fn=self.update_chat,
                inputs=[user_question, chat_history], 
                outputs=[user_question, chat_history]
            )
            
            # Kết nối nút xóa chat
            clear_chat_btn.click(
                fn=self.clear_chat,
                inputs=[], 
                outputs=[chat_history, user_question]
            )
            
            # Thêm chức năng làm mới cho tab chi tiết
            refresh_detail_btn.click(
                fn=lambda: (
                    self.get_detailed_tcp_analysis(),
                    self.chart_creator.create_tcp_flags_chart(self.base_presenter.latest_results) if self.base_presenter.latest_results else self.chart_creator._create_empty_chart("Không có dữ liệu"),
                    self.chart_creator.create_tcp_attack_chart(self.base_presenter.latest_results) if self.base_presenter.latest_results else self.chart_creator._create_empty_chart("Không có dữ liệu")
                ),
                inputs=[],
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