"""
Gradio Presenter - Web-based interface for packet analysis using Gradio.
It includes components for analyzing PCAP files, visualizing results, and providing real-time monitoring.
"""
import os
from typing import Tuple

import gradio as gr

from src.interfaces.presenters.analyzer_component import AnalyzerComponent
from src.interfaces.presenters.base_presenter import BasePresenter
from src.interfaces.presenters.chart_creator import ChartCreator
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

    def start_monitoring(self, duration_minutes: int) -> str:
        """Bắt đầu giám sát thời gian thực."""
        return self.monitoring.start_monitoring(duration_minutes)

    def display_attack_details(self, hours: int) -> Tuple:
        """Hiển thị chi tiết tấn công."""
        return self.monitoring.display_attack_details(hours)

    def display_flow_stats(self, hours: int) -> Tuple:
        """Hiển thị thống kê luồng."""
        return self.monitoring.display_flow_stats(hours)

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
            return "Vui lòng tải lên file PCAP trước khi phân tích."

        # Cập nhật thông tin file hiện tại
        file_path = pcap_file.name if hasattr(pcap_file, 'name') else pcap_file
        self.base_presenter.latest_pcap_file = file_path

        # Phân tích với prompt tùy chỉnh
        return self.analyzer.pcap_analyzer.analyze_pcap_raw_packets(pcap_file, prompt)

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
            chat_history.append({"role": "user", "content": user_message})
            chat_history.append({"role": "assistant", "content": bot_response})
            return "", chat_history

        if not has_results:
            file_name = os.path.basename(self.base_presenter.latest_pcap_file)
            bot_response = f"Tôi đã nhận file {file_name} nhưng chưa được phân tích. Vui lòng nhấn nút 'Phân tích' trong tab 'Phân tích PCAP' và quay lại đây để tư vấn."
            chat_history.append({"role": "user", "content": user_message})
            chat_history.append({"role": "assistant", "content": bot_response})
            return "", chat_history

        # Tạo phản hồi từ AI dựa trên context từ file PCAP
        bot_response = self.process_chat_query(user_message)

        # Thêm vào lịch sử chat ở định dạng Gradio messages
        chat_history.append({"role": "user", "content": user_message})
        chat_history.append({"role": "assistant", "content": bot_response})

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
            return [{"role": "assistant", "content": initial_message}], ""

        # Nếu không có kết quả phân tích, trả về lịch sử trống
        return [], ""

    def launch_interface(self):
        """Launch the Gradio interface."""
        with gr.Blocks(title="Network Packet Analyzer cho Network Engineer", theme=gr.themes.Soft(), css="""
        #export_report_btn {
            background-color: #4CAF50 !important;
            border-color: #4CAF50 !important;
            color: white !important;
            font-weight: bold !important;
            transition: all 0.3s !important;
            padding: 10px 20px !important;
            border-radius: 8px !important;
        }

        #export_report_btn:hover {
            background-color: #45a049 !important;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2) !important;
            transform: translateY(-2px) !important;
        }

        #reports_accordion {
            margin-top: 20px !important;
            border: 1px solid #ddd !important;
            border-radius: 8px !important;
            overflow: hidden !important;
        }

        #reports_list {
            width: 100% !important; 
            margin-top: 10px !important;
        }

        #export_report_guide {
            background-color: #f8f9fa !important;
            padding: 10px !important;
            border-left: 4px solid #4CAF50 !important;
            margin: 15px 0 !important;
            border-radius: 4px !important;
        }
        
        #report_download {
            margin-top: 15px !important;
            margin-bottom: 15px !important;
            padding: 10px !important;
            border-radius: 8px !important;
            background-color: #f0f8ff !important;
            border: 1px dashed #2196F3 !important;
        }
        
        button {
            transition: all 0.3s !important;
        }
        
        button:hover {
            opacity: 0.9 !important;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2) !important;
        }
        """) as interface:
            gr.Markdown("# Network Packet Analyzer cho Network Engineer")

            # Biến state để lưu thông tin file hiện tại
            current_file_info = gr.State("")

            # Biến state để lưu kết quả phân tích
            analysis_state = gr.State({})

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

            # Tab Dashboard cho Network Engineer
            with gr.Tab("Dashboard Network Engineer"):
                gr.Markdown("## Dashboard giám sát mạng và phân tích bảo mật")

                # Phần I: Giám sát Trạng thái và Kết nối Mạng
                gr.Markdown("### I. Giám sát Trạng thái và Kết nối Mạng")

                with gr.Row():
                    with gr.Column():
                        device_status_chart = gr.Plot(label="Trạng thái Thiết bị")
                    with gr.Column():
                        link_quality_chart = gr.Plot(label="Chất lượng Đường truyền")

                # Phần II: Phân tích Lưu lượng và Phát hiện Bất thường
                gr.Markdown("### II. Phân tích Lưu lượng và Phát hiện Bất thường")

                with gr.Accordion("Phát hiện tấn công ARP", open=False):
                    arp_attack_chart = gr.Plot(label="Dấu hiệu tấn công ARP")

                with gr.Accordion("Phát hiện bất thường ICMP", open=False):
                    icmp_anomaly_chart = gr.Plot(label="Dấu hiệu bất thường ICMP")

                with gr.Accordion("Phát hiện tấn công DHCP", open=False):
                    dhcp_attack_chart = gr.Plot(label="Dấu hiệu tấn công DHCP")

                with gr.Accordion("Phát hiện tấn công DNS", open=False):
                    dns_attack_chart = gr.Plot(label="Dấu hiệu tấn công DNS")

                with gr.Row():
                    with gr.Column():
                        with gr.Row():
                            top_n_slider = gr.Slider(minimum=5, maximum=20, step=1, value=10, label="Số lượng Top N")
                            update_top_n_btn = gr.Button("Cập nhật Top N")
                    with gr.Column():
                        display_options = gr.CheckboxGroup(
                            ["Hiển thị nguồn", "Hiển thị đích", "Hiển thị cặp nguồn-đích", "Hiển thị giao thức"],
                            value=["Hiển thị nguồn", "Hiển thị đích"],
                            label="Tùy chọn hiển thị"
                        )

                with gr.Row():
                    top_talkers_chart = gr.Plot(label="Top N Talkers/Chatters")

                with gr.Row():
                    refresh_dashboard_btn = gr.Button("Làm mới Dashboard", variant="primary")

            # Tab ChatBox Tư vấn rủi ro mạng
            with gr.Tab("ChatBox Tư Vấn"):
                with gr.Row():
                    with gr.Column(scale=3):
                        chat_history = gr.Chatbot(
                            label="Tư vấn debug mạng và rủi ro bảo mật",
                            height=500,
                            render=True,
                            elem_id="chatbox",
                            type="messages"
                        )

                    with gr.Column(scale=1):
                        gr.Markdown("### Tư vấn kỹ sư mạng")
                        current_chat_file = gr.Markdown("File đang phân tích: *Chưa có file*")
                        gr.Markdown("""
                        Hỏi các câu hỏi về:
                        - Debug vấn đề kết nối mạng
                        - Phát hiện và khắc phục tấn công
                        - Phân tích TCP/IP và các giao thức
                        - Đề xuất công cụ và lệnh debug
                        """)

                        gr.Markdown("---")
                        gr.Markdown("#### Các câu hỏi gợi ý:")
                        gr.Markdown("""
                        - Tại sao các thiết bị này không ping được nhau?
                        - Phân tích các vấn đề kết nối trong mạng này
                        - Có dấu hiệu tấn công ARP spoofing không?
                        - Phân tích các gói tin ICMP unreachable
                        - Phân tích lưu lượng mạng theo mô hình OSI
                        - Đề xuất các lệnh để debug vấn đề routing
                        """)

                        clear_chat_btn = gr.Button("Xóa lịch sử chat", variant="secondary")

                with gr.Row():
                    user_question = gr.Textbox(
                        label="Nhập câu hỏi về vấn đề mạng",
                        placeholder="Ví dụ: Phân tích tại sao các thiết bị không ping được đến nhau trong file PCAP...",
                        max_lines=3
                    )
                    submit_btn = gr.Button("Gửi", variant="primary")

            # Tab phân tích AI chi tiết
            with gr.Tab("Phân tích theo mô hình OSI"):
                with gr.Row():
                    with gr.Column():
                        gr.Markdown("### Phân tích chi tiết theo mô hình OSI")
                        gr.Markdown("""
                        Phân tích các vấn đề ở từng tầng của mô hình OSI:
                        - Tầng vật lý (Physical): Vấn đề tín hiệu, mất gói tin
                        - Tầng liên kết dữ liệu (Data Link): ARP, MAC, VLAN
                        - Tầng mạng (Network): Định tuyến IP, ICMP, fragmentation
                        - Tầng giao vận (Transport): TCP/UDP, cổng, cờ TCP
                        - Tầng phiên & trình diễn (Session & Presentation): Thiết lập phiên, mã hóa
                        - Tầng ứng dụng (Application): HTTP, DNS, DHCP, FTP
                        """)
                        ai_analysis_detail = gr.Markdown(
                            "Tải lên file PCAP trong tab 'Phân tích PCAP' để xem phân tích chi tiết theo mô hình OSI...")

                        gr.Markdown("""
                        ### Xuất báo cáo phân tích
                        Sau khi phân tích gói tin, bạn có thể tạo báo cáo phân tích chi tiết theo định dạng Markdown và PDF bằng cách nhấn vào nút "Xuất báo cáo" bên dưới.
                        Báo cáo sẽ bao gồm:
                        - Tóm tắt phân tích
                        - Phân tích chi tiết theo mô hình OSI
                        - Các vấn đề phát hiện ở mỗi tầng
                        - Khuyến nghị giải quyết vấn đề
                        """, elem_id="export_report_guide")

                        with gr.Row():
                            refresh_detail_btn = gr.Button("Làm mới phân tích", variant="secondary")
                            export_report_btn = gr.Button("📊 Xuất báo cáo", variant="primary",
                                                          elem_id="export_report_btn")

                        # Cập nhật giao diện quản lý báo cáo
                        with gr.Accordion("Báo cáo đã tạo", open=True, elem_id="reports_accordion"):
                            report_status = gr.Markdown("Chưa có báo cáo nào", elem_id="report_status")
                            
                            # Thêm file download component để hỗ trợ tải xuống file
                            file_download = gr.File(
                                label="Tải xuống báo cáo", 
                                interactive=False, 
                                visible=True,
                                elem_id="report_download"
                            )

                            # Sử dụng DataFrame với cờ HTML để hiển thị các nút thao tác
                            reports_df = gr.DataFrame(
                                headers=["Thời gian", "Tên báo cáo", "Tải Markdown", "Tải PDF/HTML", "Hành động"],
                                datatype=["str", "str", "html", "html", "str"],
                                col_count=(5, "fixed"),
                                value=[],
                                interactive=False,
                                visible=True,
                                elem_id="reports_list",
                                wrap=True
                            )

                            refresh_reports_btn = gr.Button("🔄 Làm mới danh sách báo cáo", variant="secondary")

                with gr.Row():
                    with gr.Column():
                        tcp_flags_chart = gr.Plot(label="Phân tích tầng Giao vận (Transport)")
                    with gr.Column():
                        tcp_attack_chart = gr.Plot(label="Phân tích tầng Mạng (Network)")

            # Định nghĩa hàm cập nhật dashboard
            def update_dashboard(pcap_file, top_n, display_options):
                """Cập nhật tất cả các biểu đồ trong dashboard."""
                # Nếu không có file PCAP, trả về biểu đồ mẫu
                if not pcap_file:
                    empty_chart = self.chart_creator._create_empty_chart("Chưa có dữ liệu. Vui lòng tải lên file PCAP.")
                    return empty_chart, empty_chart, empty_chart, empty_chart, empty_chart, empty_chart, empty_chart

                # Tạo các biểu đồ từ dữ liệu phân tích
                device_status = self.chart_creator.create_device_status_chart(self.base_presenter.latest_results)
                link_quality = self.chart_creator.create_link_quality_chart(self.base_presenter.latest_results)
                arp_attack = self.chart_creator.create_arp_attack_chart(self.base_presenter.latest_results)
                icmp_anomaly = self.chart_creator.create_icmp_anomaly_chart(self.base_presenter.latest_results)
                dhcp_attack = self.chart_creator.create_dhcp_attack_chart(self.base_presenter.latest_results)
                dns_attack = self.chart_creator.create_dns_attack_chart(self.base_presenter.latest_results)
                top_talkers = self.chart_creator.create_top_talkers_chart(self.base_presenter.latest_results, top_n)

                return device_status, link_quality, arp_attack, icmp_anomaly, dhcp_attack, dns_attack, top_talkers

            # Sửa hàm analyze_and_update_all_tabs để cập nhật cả dashboard
            def analyze_and_update_all_tabs(pcap_file):
                """Phân tích file PCAP và cập nhật tất cả các tab cùng một lúc."""
                # Phân tích PCAP chính
                main_results = self.analyze_pcap(pcap_file)

                # Tạo dữ liệu cho tab Phân tích AI chi tiết
                # Sử dụng phương thức phân tích trực tiếp từ gói tin thay vì kết quả đã phân tích
                tcp_analysis = self.get_detailed_tcp_analysis()

                # Tiếp tục sử dụng các biểu đồ từ kết quả đã được phân tích
                tcp_flags = self.chart_creator.create_tcp_flags_chart(
                    self.base_presenter.latest_results) if self.base_presenter.latest_results else self.chart_creator._create_empty_chart(
                    "Không có dữ liệu")
                tcp_attack = self.chart_creator.create_tcp_attack_chart(
                    self.base_presenter.latest_results) if self.base_presenter.latest_results else self.chart_creator._create_empty_chart(
                    "Không có dữ liệu")

                # Tạo tin nhắn chat ban đầu
                chat_msg = [{"role": "assistant",
                             "content": self.analyzer.get_initial_chat_message(self.base_presenter.latest_results)}]

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
                analysis_data = self.base_presenter.latest_results if self.base_presenter.latest_results else {}

                # Tạo dữ liệu cho Dashboard
                dashboard_results = update_dashboard(pcap_file, 10, ["Hiển thị nguồn", "Hiển thị đích"])

                # Trả về kết quả cho tất cả các tab
                return (*main_results, file_info, chat_file_info, chat_msg,
                        tcp_analysis, tcp_flags, tcp_attack,
                        *dashboard_results, analysis_data)

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
                    ai_analysis_detail, tcp_flags_chart, tcp_attack_chart,
                    # Tab Dashboard Network Engineer
                    device_status_chart, link_quality_chart, arp_attack_chart,
                    icmp_anomaly_chart, dhcp_attack_chart, dns_attack_chart, top_talkers_chart,
                    # State lưu kết quả phân tích
                    analysis_state
                ]
            )

            # Cập nhật chatbox khi tải file lên
            def init_chat_on_upload(file):
                if file:
                    # Phân tích sơ qua file để cập nhật self.base_presenter.latest_pcap_file
                    file_path = file.name if hasattr(file, 'name') else file
                    self.base_presenter.latest_pcap_file = file_path
                    # Trả về placeholder message trước khi phân tích
                    return [{"role": "assistant",
                             "content": f"Đã nhận file {os.path.basename(file_path)}. Nhấn nút 'Phân tích' để tiến hành phân tích file."}]
                return [{"role": "assistant",
                         "content": "Chào bạn! Tôi là trợ lý phân tích mạng. Vui lòng tải lên file PCAP để bắt đầu phân tích."}]

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
                    self.chart_creator.create_tcp_flags_chart(
                        self.base_presenter.latest_results) if self.base_presenter.latest_results else self.chart_creator._create_empty_chart(
                        "Không có dữ liệu"),
                    self.chart_creator.create_tcp_attack_chart(
                        self.base_presenter.latest_results) if self.base_presenter.latest_results else self.chart_creator._create_empty_chart(
                        "Không có dữ liệu")
                ),
                inputs=[],
                outputs=[ai_analysis_detail, tcp_flags_chart, tcp_attack_chart]
            )

            # Kết nối sự kiện làm mới dashboard
            refresh_dashboard_btn.click(
                fn=update_dashboard,
                inputs=[pcap_file, top_n_slider, display_options],
                outputs=[
                    device_status_chart, link_quality_chart, arp_attack_chart,
                    icmp_anomaly_chart, dhcp_attack_chart, dns_attack_chart, top_talkers_chart
                ]
            )

            # Kết nối sự kiện cập nhật Top N
            update_top_n_btn.click(
                fn=lambda pcap_file, top_n: self.chart_creator.create_top_talkers_chart(
                    self.base_presenter.latest_results,
                    top_n) if self.base_presenter.latest_results else self.chart_creator._create_empty_chart(
                    "Không có dữ liệu"),
                inputs=[pcap_file, top_n_slider],
                outputs=[top_talkers_chart]
            )

            # Thêm hàm xử lý xuất báo cáo và hiển thị danh sách báo cáo để:
            # 1. Sửa lỗi 'SelectData' object has no attribute 'column'
            # 2. Tạo UI tùy chỉnh đẹp hơn với nút tải xuống thay vì hiện đường dẫn trực tiếp
            # 3. Sử dụng tách file báo cáo thành file riêng để tải xuống
            def export_osi_report(analysis_results):
                """Xuất báo cáo phân tích OSI"""
                try:
                    # Khởi tạo ReportWriterAgent
                    from src.interfaces.gateways.report_writer_agent import ReportWriterAgent
                    report_writer = ReportWriterAgent(output_dir="reports")

                    # Nếu không có kết quả phân tích từ state, thử lấy từ base_presenter
                    if not analysis_results or (isinstance(analysis_results, dict) and len(analysis_results) == 0):
                        if self.base_presenter.latest_results:
                            analysis_results = self.base_presenter.latest_results
                        else:
                            # Nếu không có kết quả nào, tạo báo cáo mẫu
                            report_info = report_writer.generate_sample_report()
                            return "Đã tạo báo cáo mẫu do không có dữ liệu phân tích cụ thể", get_reports_dataframe()

                    # Tạo báo cáo từ kết quả phân tích
                    report_info = report_writer.generate_report(
                        analysis_results,
                        report_title="Báo Cáo Phân Tích OSI",
                        include_recommendations=True
                    )

                    return f"✅ Đã tạo báo cáo thành công: {report_info['readable_time']}", get_reports_dataframe()
                except Exception as e:
                    return f"❌ Lỗi khi tạo báo cáo: {str(e)}", []

            def get_reports_dataframe():
                """Lấy danh sách báo cáo dưới dạng dataframe với nút tải xuống và xóa"""
                try:
                    from src.interfaces.gateways.report_writer_agent import ReportWriterAgent
                    import os

                    report_writer = ReportWriterAgent(output_dir="reports")
                    reports = report_writer.get_report_list()

                    if not reports:
                        return []  # Trả về list rỗng nếu không có báo cáo

                    # Tạo dataframe chứa thông tin báo cáo và nút thao tác
                    data = []
                    for report in reports:
                        report_id = report['timestamp']
                        md_filename = report['filename']
                        report_title = report.get('report_title', "Báo cáo phân tích mạng")

                        # Tạo nút tải xuống Markdown
                        if os.path.exists(os.path.join("reports", md_filename)):
                            md_link = f"<button style='background-color:#4CAF50; color:white; border:none; padding:5px 10px; border-radius:4px; cursor:pointer;'>📋 Tải Markdown</button>"
                        else:
                            md_link = "Không có file"

                        # Tạo nút tải xuống PDF/HTML
                        download_type = report.get('download_type', 'html').upper()
                        download_path = report.get('download_path', '')

                        if download_path and os.path.exists(os.path.join("reports", download_path)):
                            icon = "📊" if download_type.lower() == "pdf" else "📄"
                            download_link = f"<button style='background-color:#2196F3; color:white; border:none; padding:5px 10px; border-radius:4px; cursor:pointer;'>{icon} Tải {download_type}</button>"
                        else:
                            download_link = "Không có file"

                        # Tạo nút xóa
                        delete_btn = f"🗑️ Xóa_{report_id}"

                        # Thêm vào danh sách
                        data.append([
                            report['readable_time'],
                            report_title,
                            md_link,
                            download_link,
                            delete_btn
                        ])

                    return data
                except Exception as e:
                    print(f"Lỗi khi lấy danh sách báo cáo: {str(e)}")
                    return []

            def download_report(report_id, file_type="markdown"):
                """Tải xuống báo cáo theo ID"""
                try:
                    from src.interfaces.gateways.report_writer_agent import ReportWriterAgent
                    import os

                    report_writer = ReportWriterAgent(output_dir="reports")
                    reports = report_writer.get_report_list()

                    # Tìm báo cáo theo ID
                    target_report = None
                    for report in reports:
                        if report['timestamp'] == report_id:
                            target_report = report
                            break

                    if not target_report:
                        print(f"Báo cáo không tìm thấy với ID: {report_id}")
                        return f"Không tìm thấy báo cáo ID {report_id}"

                    # Xác định file cần tải xuống
                    if file_type.lower() == "markdown":
                        file_path = os.path.join("reports", target_report['filename'])
                        file_name = target_report['filename']
                    else:
                        # Sử dụng PDF hoặc HTML tùy vào cái nào có sẵn
                        download_path = target_report.get('download_path', '')
                        if not download_path:
                            print(f"Không có file để tải xuống cho báo cáo ID: {report_id}")
                            return "Không có file để tải xuống"
                        file_path = os.path.join("reports", download_path)
                        file_name = download_path

                    # Kiểm tra xem file có tồn tại không
                    if not os.path.exists(file_path):
                        print(f"File không tồn tại: {file_path}")
                        return f"File {file_name} không tồn tại"

                    # Đảm bảo trả về đường dẫn tuyệt đối để gradio có thể tìm thấy file
                    absolute_path = os.path.abspath(file_path)
                    print(f"Đường dẫn tải xuống: {absolute_path}")
                    
                    # Trả về đường dẫn để Gradio tạo liên kết tải xuống
                    return absolute_path
                except Exception as e:
                    print(f"Lỗi khi tải xuống báo cáo: {str(e)}")
                    return f"Lỗi khi tải xuống báo cáo: {str(e)}"

            def handle_reports_click(evt: gr.SelectData, reports_data):
                """Xử lý khi người dùng click vào danh sách báo cáo"""
                try:
                    from src.interfaces.gateways.report_writer_agent import ReportWriterAgent
                    import pandas as pd

                    # Kiểm tra nếu reports_data là DataFrame hoặc None
                    if reports_data is None:
                        return "Không có báo cáo nào", []

                    # Nếu là DataFrame, chuyển đổi thành danh sách
                    if isinstance(reports_data, pd.DataFrame):
                        reports_data = reports_data.values.tolist()
                    elif not isinstance(reports_data, list):
                        # Nếu không phải DataFrame hoặc list, trả về lỗi
                        return f"Loại dữ liệu không hỗ trợ: {type(reports_data)}", []

                    # Kiểm tra nếu danh sách trống
                    if len(reports_data) == 0:
                        return "Không có báo cáo nào", []

                    # Lấy dòng và cột được chọn
                    row_index = evt.index[0] if hasattr(evt, 'index') else 0
                    col_index = evt.index[1] if hasattr(evt, 'index') and len(evt.index) > 1 else 0

                    if row_index >= len(reports_data):
                        return "Chỉ số dòng không hợp lệ", reports_data

                    # Lấy thông tin báo cáo được chọn
                    selected_row = reports_data[row_index]
                    if len(selected_row) < 5:
                        return "Dữ liệu báo cáo không hợp lệ", reports_data

                    # Tách ID báo cáo từ cột cuối (nút Xóa)
                    delete_btn_text = selected_row[4]
                    if not isinstance(delete_btn_text, str) or not delete_btn_text.startswith("🗑️ Xóa_"):
                        return "Không thể xác định ID báo cáo", reports_data

                    report_id = delete_btn_text.replace("🗑️ Xóa_", "")

                    # Xử lý theo cột được chọn
                    if col_index == 2:  # Cột "Tải Markdown"
                        md_link_text = selected_row[2]
                        if md_link_text == "Không có file":
                            return "Markdown không khả dụng cho báo cáo này", reports_data
                        # Trả về đường dẫn file để Gradio tạo liên kết tải xuống
                        file_path = download_report(report_id, "markdown")
                        # Kiểm tra xem đường dẫn có hợp lệ không
                        if isinstance(file_path, str) and os.path.exists(file_path):
                            gr.Info(f"Đang tải xuống tệp Markdown cho báo cáo {selected_row[1]}")
                            # Trả về đường dẫn file để Gradio tạo nút tải xuống
                            return f"File Markdown sẵn sàng tải xuống: {file_path}", reports_data
                        else:
                            return f"Lỗi khi tải file: {file_path}", reports_data

                    elif col_index == 3:  # Cột "Tải PDF/HTML"
                        pdf_link_text = selected_row[3]
                        if pdf_link_text == "Không có file":
                            return "PDF/HTML không khả dụng cho báo cáo này", reports_data
                        # Trả về đường dẫn file để Gradio tạo liên kết tải xuống
                        file_path = download_report(report_id, "pdf")
                        # Kiểm tra xem đường dẫn có hợp lệ không
                        if isinstance(file_path, str) and os.path.exists(file_path):
                            download_type = "PDF" if file_path.endswith(".pdf") else "HTML"
                            gr.Info(f"Đang tải xuống tệp {download_type} cho báo cáo {selected_row[1]}")
                            # Trả về đường dẫn file để Gradio tạo nút tải xuống
                            return f"File {download_type} sẵn sàng tải xuống: {file_path}", reports_data
                        else:
                            return f"Lỗi khi tải file: {file_path}", reports_data

                    elif col_index == 4:  # Cột "Hành động" (Xóa)
                        # Xóa báo cáo
                        report_writer = ReportWriterAgent(output_dir="reports")
                        report_writer.delete_report(report_id)
                        # Cập nhật lại danh sách báo cáo
                        return f"Đã xóa báo cáo {selected_row[1]}", get_reports_dataframe()

                    return "Nhấp vào nút 'Tải Markdown', 'Tải PDF/HTML' hoặc 'Xóa' để tương tác với báo cáo", reports_data

                except Exception as e:
                    print(f"Lỗi khi xử lý click báo cáo: {str(e)}")
                    return f"Lỗi khi xử lý: {str(e)}", reports_data

            # Thêm các event handlers
            export_report_btn.click(
                fn=export_osi_report,
                inputs=[analysis_state],
                outputs=[report_status, reports_df]
            )

            refresh_reports_btn.click(
                fn=get_reports_dataframe,
                inputs=[],
                outputs=[reports_df]
            )

            # Thay đổi cách gọi sự kiện select để truyền dữ liệu đúng cách
            def reports_select_handler(evt: gr.SelectData):
                try:
                    import os
                    reports_data = get_reports_dataframe()
                    result, updated_df = handle_reports_click(evt, reports_data)
                    
                    # Kiểm tra xem kết quả có phải đường dẫn tải xuống không
                    if isinstance(result, str) and result.startswith("File ") and "sẵn sàng tải xuống:" in result:
                        # Trích xuất đường dẫn file
                        file_path = result.split("sẵn sàng tải xuống:")[1].strip()
                        if os.path.exists(file_path):
                            # Tạo một đường dẫn tạm thời cho Gradio để tạo liên kết tải xuống
                            return f"Tải xuống báo cáo: {os.path.basename(file_path)}", updated_df, file_path
                    
                    return result, updated_df, None
                except Exception as e:
                    print(f"Lỗi xử lý sự kiện select: {e}")
                    return f"Lỗi: {str(e)}", get_reports_dataframe(), None

            reports_df.select(
                fn=reports_select_handler,
                inputs=[],  # Không cần truyền reports_df làm đầu vào
                outputs=[report_status, reports_df, file_download]
            )

            refresh_detail_btn.click(
                fn=lambda: (
                    self.get_detailed_tcp_analysis(),
                    self.chart_creator.create_tcp_flags_chart(
                        self.base_presenter.latest_results) if self.base_presenter.latest_results else self.chart_creator._create_empty_chart(
                        "Không có dữ liệu"),
                    self.chart_creator.create_tcp_attack_chart(
                        self.base_presenter.latest_results) if self.base_presenter.latest_results else self.chart_creator._create_empty_chart(
                        "Không có dữ liệu")
                ),
                inputs=[],
                outputs=[ai_analysis_detail, tcp_flags_chart, tcp_attack_chart]
            )

        # Khởi chạy giao diện
        interface.launch(share=False)
