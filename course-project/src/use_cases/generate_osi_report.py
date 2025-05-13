import os
# Đảm bảo import này hoạt động sau khi cấu trúc thư mục đúng
# Nếu có lỗi import ở đây, cần kiểm tra lại PYTHONPATH hoặc cấu trúc dự án
from src.infrastructure.report_generators.osi_report_writer_agent import OSIReportWriterAgent

class OsiReportUseCase:
    def __init__(self, output_dir: str = "reports/osi_analysis"):
        self.output_dir = output_dir
        # Đảm bảo thư mục output tồn tại
        os.makedirs(self.output_dir, exist_ok=True)
        # Khởi tạo OSI Report Writer Agent
        try:
            self.report_writer = OSIReportWriterAgent(reports_dir=self.output_dir)
        except Exception as e:
            print(f"Lỗi khi khởi tạo OSIReportWriterAgent: {e}")
            self.report_writer = None

    def execute(self, analysis_results: dict) -> tuple[str | None, str | None]:
        """
        Thực thi use case tạo báo cáo OSI.

        Args:
            analysis_results: Dictionary chứa kết quả phân tích.

        Returns:
            Tuple chứa đường dẫn đến file Markdown và file PDF đã tạo, hoặc (None, None) nếu lỗi.
            (markdown_path, pdf_path)
        """
        if not self.report_writer:
             print("Lỗi: Report writer chưa được khởi tạo thành công.")
             return None, None
             
        print("Bắt đầu tạo báo cáo OSI...")

        try:
            # Gọi OSI Report Writer Agent để tạo báo cáo
            md_path, pdf_path = self.report_writer.generate_report(analysis_results)
            print(f"Đã tạo báo cáo thành công: {md_path}, {pdf_path}")
            return md_path, pdf_path
        except Exception as e:
            print(f"Lỗi khi tạo báo cáo trong OsiReportUseCase: {e}")
            # In stack trace để debug dễ hơn
            import traceback
            traceback.print_exc()
            return None, None

# Ví dụ cách sử dụng (chỉ chạy khi file này được thực thi trực tiếp):
# if __name__ == '__main__':
#     # Ví dụ dữ liệu đầu vào (thay thế bằng dữ liệu thực tế)
#     sample_analysis_results = {
#         "metadata": {"analysis_id": "test-123", "timestamp": "2023-10-28T12:00:00Z", "source": "test.pcap"},
#         "summary": {"critical_findings": 1, "high_findings": 2, "medium_findings": 5, "overall_status": "Cảnh báo"},
#         "layers": {
#             "Application": [{"id": "APP-001", "finding": "HTTP Detected", "severity": "Info", "recommendation": "Use HTTPS"}],
#             "Network": [{"id": "NET-001", "finding": "ICMP Ping", "severity": "Low", "recommendation": "Monitor"}]
#         },
#         "conclusion": {"main_points": "Test report.", "next_steps": "Review findings."}
#     }
# 
#     reporter = OsiReportUseCase()
#     md_path, pdf_path = reporter.execute(sample_analysis_results)
# 
#     if md_path and pdf_path:
#         print(f"Hoàn thành. Kiểm tra file tại: {reporter.output_dir}")
#     else:
#         print("Tạo báo cáo thất bại.") 