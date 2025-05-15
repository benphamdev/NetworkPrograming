"""
Report Manager - Xử lý tạo và tải xuống báo cáo.
"""
import os

import gradio as gr
import pandas as pd


class ReportManager:
    """Quản lý tạo, hiển thị và tải xuống báo cáo phân tích."""

    def __init__(self, base_presenter):
        """
        Khởi tạo Report Manager.
        
        Args:
            base_presenter: BasePresenter instance
        """
        self.base_presenter = base_presenter
        self.output_dir = "reports"

    def export_osi_report(self, analysis_results):
        """
        Xuất báo cáo phân tích OSI
        
        Args:
            analysis_results: Dictionary chứa kết quả phân tích
            
        Returns:
            Tuple (message, reports_dataframe)
        """
        try:
            # Khởi tạo ReportWriterAgent
            from src.interfaces.gateways.report_writer_agent import ReportWriterAgent
            # Import biến toàn cục
            from src.interfaces.gateways.smolagent_gateway import LATEST_ANALYSIS_MARKDOWN
            report_writer = ReportWriterAgent(output_dir=self.output_dir)
            
            # Sử dụng template cho báo cáo
            from datetime import datetime
            import re
            
            if LATEST_ANALYSIS_MARKDOWN:
                # Đọc template
                template_path = "templates/network_analysis_template.md"
                try:
                    with open(template_path, 'r', encoding='utf-8') as f:
                        template = f.read()
                except Exception as e:
                    print(f"Không thể đọc template: {str(e)}")
                    template = "# {title}\n\n{osi_analysis}"
                
                # Chuẩn bị dữ liệu để điền vào template
                now = datetime.now()
                date_str = now.strftime("%d/%m/%Y")
                time_str = now.strftime("%H:%M:%S")
                
                # Trích xuất phần tóm tắt và các phần khác từ markdown phân tích
                summary = "Phân tích lưu lượng mạng và xác định các vấn đề tiềm ẩn"
                conclusion = "Xem chi tiết trong phân tích đầy đủ"
                
                # Cố gắng trích xuất các phần từ LATEST_ANALYSIS_MARKDOWN
                summary_match = re.search(r'## Tóm tắt\s*\n\n(.*?)(?=\n\n##|\Z)', LATEST_ANALYSIS_MARKDOWN, re.DOTALL)
                if summary_match:
                    summary = summary_match.group(1).strip()
                    
                conclusion_match = re.search(r'## Kết luận\s*\n\n(.*?)(?=\n\n##|\Z)', LATEST_ANALYSIS_MARKDOWN, re.DOTALL)
                if conclusion_match:
                    conclusion = conclusion_match.group(1).strip()
                    
                # Tìm tất cả các vấn đề bảo mật
                security_issues_rows = ""
                security_issues_pattern = r'\*\*Vấn đề bảo mật:\*\*\s*\n\n(.*?)(?=\n\n\*\*|\n\n##|\Z)'
                security_matches = re.finditer(security_issues_pattern, LATEST_ANALYSIS_MARKDOWN, re.DOTALL)
                for match in security_matches:
                    issues = match.group(1).strip().split('\n')
                    for issue in issues:
                        if issue.startswith('- '):
                            issue = issue[2:]  # Bỏ dấu gạch đầu dòng
                            security_issues_rows += f"| {issue} | Cao | Tiềm ẩn rủi ro bảo mật |\n"
                
                # Tìm tất cả khuyến nghị
                recommendations = ""
                recommendations_pattern = r'\*\*Khuyến nghị:\*\*\s*\n\n(.*?)(?=\n\n\*\*|\n\n##|\Z)'
                recommendations_matches = re.finditer(recommendations_pattern, LATEST_ANALYSIS_MARKDOWN, re.DOTALL)
                for match in recommendations_matches:
                    recs = match.group(1).strip()
                    recommendations += recs + "\n\n"
                
                # Điền template
                filled_template = template.format(
                    title="Báo Cáo Phân Tích OSI",
                    date=date_str,
                    time=time_str,
                    summary=summary,
                    osi_analysis=LATEST_ANALYSIS_MARKDOWN,
                    security_issues=security_issues_rows if security_issues_rows else "| Không phát hiện | - | - |",
                    recommendations=recommendations if recommendations else "Không có khuyến nghị cụ thể.",
                    conclusion=conclusion
                )
                
                # Tạo báo cáo với phân tích đơn giản
                report_info = report_writer.generate_report(
                    {"analysis": "Phân tích chi tiết lưu lượng mạng theo mô hình OSI"},
                    report_title="Báo Cáo Phân Tích OSI",
                    include_recommendations=True
                )
                
                # Ghi đè file markdown bằng template đã điền
                if 'filename' in report_info:
                    md_path = os.path.join(self.output_dir, report_info['filename'])
                    try:
                        with open(md_path, 'w', encoding='utf-8') as f:
                            f.write(filled_template)
                        print(f"Đã ghi nội dung template đầy đủ vào file {md_path}")
                        return f"✅ Đã tạo báo cáo thành công với nội dung đầy đủ: {report_info['readable_time']}", self.get_reports_dataframe()
                    except Exception as write_error:
                        print(f"Lỗi khi ghi file: {str(write_error)}")
                
                return f"✅ Đã tạo báo cáo: {report_info['readable_time']}", self.get_reports_dataframe()
                
            # Phần còn lại giữ nguyên
            if not analysis_results or (isinstance(analysis_results, dict) and len(analysis_results) == 0):
                if self.base_presenter.latest_results:
                    analysis_results = self.base_presenter.latest_results
                else:
                    # Nếu không có kết quả nào, tạo báo cáo mẫu
                    report_info = report_writer.generate_sample_report()
                    return "Đã tạo báo cáo mẫu do không có dữ liệu phân tích cụ thể", self.get_reports_dataframe()

            # Tạo báo cáo từ kết quả phân tích
            report_info = report_writer.generate_report(
                analysis_results,
                report_title="Báo Cáo Phân Tích OSI",
                include_recommendations=True
            )

            return f"✅ Đã tạo báo cáo thành công: {report_info['readable_time']}", self.get_reports_dataframe()
        except Exception as e:
            return f"❌ Lỗi khi tạo báo cáo: {str(e)}", []

    def get_reports_dataframe(self):
        """
        Lấy danh sách báo cáo dưới dạng dataframe với nút tải xuống và xóa
        
        Returns:
            List các báo cáo với thông tin định dạng
        """
        try:
            from src.interfaces.gateways.report_writer_agent import ReportWriterAgent

            report_writer = ReportWriterAgent(output_dir=self.output_dir)
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
                if os.path.exists(os.path.join(self.output_dir, md_filename)):
                    md_link = f"<button style='background-color:#4CAF50; color:white; border:none; padding:5px 10px; border-radius:4px; cursor:pointer;'>📋 Tải Markdown</button>"
                else:
                    md_link = "Không có file"

                # Tạo nút tải xuống PDF/HTML
                download_type = report.get('download_type', 'html').upper()
                download_path = report.get('download_path', '')

                if download_path and os.path.exists(os.path.join(self.output_dir, download_path)):
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

    def download_report(self, report_id, file_type="markdown"):
        """
        Tải xuống báo cáo theo ID
        
        Args:
            report_id: ID của báo cáo cần tải xuống
            file_type: Loại file cần tải xuống (markdown/pdf/html)
            
        Returns:
            Đường dẫn tuyệt đối đến file báo cáo
        """
        try:
            from src.interfaces.gateways.report_writer_agent import ReportWriterAgent

            report_writer = ReportWriterAgent(output_dir=self.output_dir)
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
                file_path = os.path.join(self.output_dir, target_report['filename'])
                file_name = target_report['filename']
            else:
                # Sử dụng PDF hoặc HTML tùy vào cái nào có sẵn
                download_path = target_report.get('download_path', '')
                if not download_path:
                    print(f"Không có file để tải xuống cho báo cáo ID: {report_id}")
                    return "Không có file để tải xuống"
                file_path = os.path.join(self.output_dir, download_path)
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

    def handle_reports_click(self, evt: gr.SelectData, reports_data):
        """
        Xử lý khi người dùng click vào danh sách báo cáo
        
        Args:
            evt: Sự kiện SelectData từ Gradio
            reports_data: Dữ liệu danh sách báo cáo
            
        Returns:
            Tuple (message, updated_reports_dataframe)
        """
        try:
            from src.interfaces.gateways.report_writer_agent import ReportWriterAgent

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
                file_path = self.download_report(report_id, "markdown")
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
                file_path = self.download_report(report_id, "pdf")
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
                report_writer = ReportWriterAgent(output_dir=self.output_dir)
                report_writer.delete_report(report_id)
                # Cập nhật lại danh sách báo cáo
                return f"Đã xóa báo cáo {selected_row[1]}", self.get_reports_dataframe()

            return "Nhấp vào nút 'Tải Markdown', 'Tải PDF/HTML' hoặc 'Xóa' để tương tác với báo cáo", reports_data

        except Exception as e:
            print(f"Lỗi khi xử lý click báo cáo: {str(e)}")
            return f"Lỗi khi xử lý: {str(e)}", reports_data

    def reports_select_handler(self, evt: gr.SelectData):
        """
        Xử lý sự kiện khi người dùng chọn một báo cáo trong danh sách
        
        Args:
            evt: Sự kiện SelectData từ Gradio
            
        Returns:
            Tuple (message, updated_reports_dataframe, file_path)
        """
        try:
            reports_data = self.get_reports_dataframe()
            result, updated_df = self.handle_reports_click(evt, reports_data)

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
            return f"Lỗi: {str(e)}", self.get_reports_dataframe(), None
