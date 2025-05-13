"""
UI Layout Creator - Tạo giao diện người dùng với Gradio.
"""
import gradio as gr
import os

class UILayoutCreator:
    """Tạo giao diện người dùng với Gradio."""

    def __init__(self, gradio_presenter):
        """
        Khởi tạo UI Layout Creator.
        
        Args:
            gradio_presenter: GradioPresenter instance
        """
        self.gradio_presenter = gradio_presenter
        self.css = self._get_css()

    def _get_css(self):
        """
        Lấy CSS cho giao diện
        
        Returns:
            CSS string cho giao diện
        """
        return """
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
        """

    def create_pcap_analysis_tab(self, interface):
        """
        Tạo tab phân tích PCAP
        
        Args:
            interface: Gradio Blocks interface
            
        Returns:
            Tuple chứa các thành phần giao diện
        """
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

        return pcap_file, analyze_btn, analysis_summary, current_file_display, attack_table, protocol_chart, attack_chart, flow_graph, tcp_viz

    def create_dashboard_tab(self, interface):
        """
        Tạo tab Dashboard cho Network Engineer
        
        Args:
            interface: Gradio Blocks interface
            
        Returns:
            Tuple chứa các thành phần giao diện
        """
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

        return (device_status_chart, link_quality_chart, arp_attack_chart, icmp_anomaly_chart, 
                dhcp_attack_chart, dns_attack_chart, top_n_slider, update_top_n_btn, 
                display_options, top_talkers_chart, refresh_dashboard_btn)

    def create_chat_tab(self, interface):
        """
        Tạo tab ChatBox Tư vấn rủi ro mạng
        
        Args:
            interface: Gradio Blocks interface
            
        Returns:
            Tuple chứa các thành phần giao diện
        """
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

        return chat_history, current_chat_file, clear_chat_btn, user_question, submit_btn

    def create_osi_analysis_tab(self, interface):
        """
        Tạo tab phân tích theo mô hình OSI
        
        Args:
            interface: Gradio Blocks interface
            
        Returns:
            Tuple chứa các thành phần giao diện
        """
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

        return (ai_analysis_detail, refresh_detail_btn, export_report_btn, report_status, 
                file_download, reports_df, refresh_reports_btn, tcp_flags_chart, tcp_attack_chart)

    def create_interface(self):
        """
        Tạo giao diện hoàn chỉnh
        
        Returns:
            Tuple (interface, components)
        """
        interface = gr.Blocks(title="Network Packet Analyzer cho Network Engineer", 
                             theme=gr.themes.Soft(), 
                             css=self.css)
        
        with interface:
            gr.Markdown("# Network Packet Analyzer cho Network Engineer")

            # Biến state để lưu thông tin file hiện tại
            current_file_info = gr.State("")

            # Biến state để lưu kết quả phân tích
            analysis_state = gr.State({})

            # Tạo các tab
            pcap_components = self.create_pcap_analysis_tab(interface)
            dashboard_components = self.create_dashboard_tab(interface)
            chat_components = self.create_chat_tab(interface)
            osi_components = self.create_osi_analysis_tab(interface)

            # Kết hợp tất cả các thành phần
            components = {
                'pcap': pcap_components,
                'dashboard': dashboard_components,
                'chat': chat_components,
                'osi': osi_components,
                'state': (current_file_info, analysis_state)
            }
            
        return interface, components
