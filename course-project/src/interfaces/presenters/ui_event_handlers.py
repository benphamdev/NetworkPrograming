# filepath: src/interfaces/presenters/ui_event_handlers.py
"""
UI Event Handlers - Xử lý các sự kiện UI trong Gradio.
"""
import os

class UIEventHandlers:
    """Xử lý các sự kiện UI trong Gradio interface."""

    def __init__(self, gradio_presenter, ui_components):
        """
        Khởi tạo UI Event Handlers.
        
        Args:
            gradio_presenter: GradioPresenter instance
            ui_components: Dictionary chứa các component UI
        """
        self.gradio_presenter = gradio_presenter
        self.ui_components = ui_components

    def analyze_and_update_all_tabs(self, pcap_file):
        """
        Phân tích file PCAP và cập nhật tất cả các tab cùng một lúc.
        
        Args:
            pcap_file: File PCAP để phân tích
            
        Returns:
            Nhiều đầu ra cho UI
        """
        # Phân tích PCAP chính
        main_results = self.gradio_presenter.analyze_pcap(pcap_file)

        # Tạo dữ liệu cho tab Phân tích AI chi tiết
        # Sử dụng phương thức phân tích trực tiếp từ gói tin thay vì kết quả đã phân tích
        tcp_analysis = self.gradio_presenter.get_detailed_tcp_analysis()

        # Tiếp tục sử dụng các biểu đồ từ kết quả đã được phân tích
        if self.gradio_presenter.base_presenter.latest_results:
            tcp_flags = self.gradio_presenter.chart_creator.create_tcp_flags_chart(
                self.gradio_presenter.base_presenter.latest_results)
            tcp_attack = self.gradio_presenter.chart_creator.create_tcp_attack_chart(
                self.gradio_presenter.base_presenter.latest_results)
        else:
            tcp_flags = self.gradio_presenter.chart_creator._create_empty_chart("Không có dữ liệu")
            tcp_attack = self.gradio_presenter.chart_creator._create_empty_chart("Không có dữ liệu")

        # Tạo tin nhắn chat ban đầu
        chat_msg = [{"role": "assistant",
                     "content": self.gradio_presenter.analyzer.get_initial_chat_message(
                         self.gradio_presenter.base_presenter.latest_results)}]

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

        # Lưu kết quả phân tích vào state
        analysis_data = self.gradio_presenter.base_presenter.latest_results if self.gradio_presenter.base_presenter.latest_results else {}

        # Tạo dữ liệu cho Dashboard
        dashboard_results = self.gradio_presenter.dashboard.update_dashboard(
            pcap_file, 10, ["Hiển thị nguồn", "Hiển thị đích"])

        # Trả về kết quả cho tất cả các tab
        return (*main_results, file_info, chat_file_info, chat_msg,
                tcp_analysis, tcp_flags, tcp_attack,
                *dashboard_results, analysis_data)

    def connect_events(self, interface=None):
        """
        Kết nối các sự kiện với các component UI.
        
        Args:
            interface: Gradio Blocks interface (optional)
            
        Returns:
            Interface với các sự kiện đã được kết nối
        """
        # Bọc tất cả event connections trong một with interface context
        if interface is None:
            # Nếu không cung cấp interface, in cảnh báo và trả về sớm
            print("Warning: Cannot connect events without a valid Gradio Blocks context")
            return
            
        with interface:
            # Trích xuất các components
            pcap_file, analyze_btn, analysis_summary, current_file_display, attack_table, protocol_chart, attack_chart, flow_graph, tcp_viz = self.ui_components['pcap']
            device_status_chart, link_quality_chart, arp_attack_chart, icmp_anomaly_chart, dhcp_attack_chart, dns_attack_chart, top_n_slider, update_top_n_btn, display_options, top_talkers_chart, refresh_dashboard_btn = self.ui_components['dashboard']
            chat_history, current_chat_file, clear_chat_btn, user_question, submit_btn = self.ui_components['chat']
            ai_analysis_detail, refresh_detail_btn, export_report_btn, report_status, file_download, reports_df, refresh_reports_btn, tcp_flags_chart, tcp_attack_chart = self.ui_components['osi']
            current_file_info, analysis_state = self.ui_components['state']

            # Kết nối sự kiện nhấn phân tích với tất cả các đầu ra cần cập nhật
            analyze_btn.click(
                fn=self.analyze_and_update_all_tabs,
                inputs=[pcap_file],
                outputs=[
                    # Tab Phân tích PCAP
                    analysis_summary, attack_table, protocol_chart, attack_chart, flow_graph, tcp_viz,
                    # Thông tin file
                    current_file_display, current_chat_file,
                    # Tab ChatBox Tư Vấn
                    chat_history,
                    # Tab Phân tích AI chi tiết
                    ai_analysis_detail, tcp_flags_chart, tcp_attack_chart,
                    # Tab Dashboard Network Engineer
                    device_status_chart, link_quality_chart, arp_attack_chart,
                    icmp_anomaly_chart, dhcp_attack_chart, dns_attack_chart, top_talkers_chart,
                    # State lưu kết quả phân tích
                    analysis_state
                ]
            )

            # Cập nhật chatbox khi tải file lên
            pcap_file.change(
                fn=self.gradio_presenter.chat_interface.init_chat_on_upload,
                inputs=[pcap_file],
                outputs=[chat_history]
            )

            # Kết nối sự kiện chat
            submit_btn.click(
                fn=self.gradio_presenter.chat_interface.update_chat,
                inputs=[user_question, chat_history],
                outputs=[user_question, chat_history]
            )

            # Cũng cho phép người dùng nhấn Enter để gửi
            user_question.submit(
                fn=self.gradio_presenter.chat_interface.update_chat,
                inputs=[user_question, chat_history],
                outputs=[user_question, chat_history]
            )

            # Kết nối nút xóa chat
            clear_chat_btn.click(
                fn=self.gradio_presenter.chat_interface.clear_chat,
                inputs=[],
                outputs=[chat_history, user_question]
            )

            # Thêm chức năng làm mới cho tab chi tiết
            refresh_detail_btn.click(
                fn=lambda: (
                    self.gradio_presenter.get_detailed_tcp_analysis(),
                    self.gradio_presenter.chart_creator.create_tcp_flags_chart(
                        self.gradio_presenter.base_presenter.latest_results) if self.gradio_presenter.base_presenter.latest_results else self.gradio_presenter.chart_creator._create_empty_chart(
                        "Không có dữ liệu"),
                    self.gradio_presenter.chart_creator.create_tcp_attack_chart(
                        self.gradio_presenter.base_presenter.latest_results) if self.gradio_presenter.base_presenter.latest_results else self.gradio_presenter.chart_creator._create_empty_chart(
                        "Không có dữ liệu")
                ),
                inputs=[],
                outputs=[ai_analysis_detail, tcp_flags_chart, tcp_attack_chart]
            )

            # Kết nối sự kiện làm mới dashboard
            refresh_dashboard_btn.click(
                fn=self.gradio_presenter.dashboard.update_dashboard,
                inputs=[pcap_file, top_n_slider, display_options],
                outputs=[
                    device_status_chart, link_quality_chart, arp_attack_chart,
                    icmp_anomaly_chart, dhcp_attack_chart, dns_attack_chart, top_talkers_chart
                ]
            )

            # Kết nối sự kiện cập nhật Top N
            update_top_n_btn.click(
                fn=self.gradio_presenter.dashboard.update_top_n,
                inputs=[pcap_file, top_n_slider],
                outputs=[top_talkers_chart]
            )

            # Thêm các event handlers cho báo cáo
            export_report_btn.click(
                fn=self.gradio_presenter.report_manager.export_osi_report,
                inputs=[analysis_state],
                outputs=[report_status, reports_df]
            )

            refresh_reports_btn.click(
                fn=self.gradio_presenter.report_manager.get_reports_dataframe,
                inputs=[],
                outputs=[reports_df]
            )

            reports_df.select(
                fn=self.gradio_presenter.report_manager.reports_select_handler,
                inputs=[],
                outputs=[report_status, reports_df, file_download]
            )

        return self.ui_components