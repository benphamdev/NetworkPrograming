"""
ReportWriterAgent - Thành phần chịu trách nhiệm tạo và quản lý báo cáo phân tích mạng.
Hỗ trợ xuất báo cáo dưới dạng Markdown và PDF.
"""
import os
import time
import datetime
import markdown
from typing import Dict, Any, List

class ReportWriterAgent:
    """
    Agent chịu trách nhiệm tạo báo cáo phân tích mạng theo định dạng Markdown và PDF.
    """
    
    def __init__(self, output_dir: str = "reports"):
        """
        Khởi tạo ReportWriterAgent.
        
        Args:
            output_dir: Thư mục lưu các báo cáo
        """
        self.output_dir = output_dir
        
        # Đảm bảo thư mục báo cáo tồn tại
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_report(self, 
                        analysis_data: Dict[str, Any], 
                        report_title: str = "Báo Cáo Phân Tích Mạng",
                        include_recommendations: bool = True) -> Dict[str, str]:
        """
        Tạo báo cáo từ dữ liệu phân tích mạng.
        
        Args:
            analysis_data: Từ điển chứa dữ liệu phân tích
            report_title: Tiêu đề báo cáo
            include_recommendations: Có bao gồm khuyến nghị hay không
            
        Returns:
            Thông tin về báo cáo đã tạo (timestamp, filename, path)
        """
        # Tạo timestamp cho báo cáo
        timestamp = int(time.time())
        readable_time = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        # Tạo tên file ngắn hơn và thêm tiền tố OSI để dễ tìm
        filename = f"OSI_report_{timestamp}.md"
        filepath = os.path.join(self.output_dir, filename)
        
        # Chuẩn bị nội dung báo cáo
        report_content = self._build_report_content(
            analysis_data, 
            report_title, 
            timestamp,
            readable_time,
            include_recommendations
        )
        
        # Lưu báo cáo Markdown
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        # Tạo báo cáo PDF
        download_path = self._convert_to_pdf(filepath)
        file_basename = os.path.basename(download_path)
        
        # Xác định loại file để tải xuống
        download_type = "pdf" if download_path.endswith(".pdf") else "html"
        
        # Tạo đường dẫn trực tiếp dạng file= để tải xuống file
        md_download_path = os.path.join("file=reports", os.path.basename(filepath))
        output_download_path = os.path.join("file=reports", file_basename)
        
        return {
            'timestamp': str(timestamp),
            'readable_time': readable_time,
            'filename': filename,
            'filepath': filepath,
            'download_path': file_basename,
            'md_download_path': md_download_path,
            'output_download_path': output_download_path,
            'download_type': download_type,
            'report_title': report_title
        }
    
    def _build_report_content(self, 
                             analysis_data: Dict[str, Any],
                             title: str, 
                             timestamp: int,
                             readable_time: str,
                             include_recommendations: bool) -> str:
        """
        Xây dựng nội dung báo cáo Markdown dựa trên dữ liệu phân tích.
        
        Args:
            analysis_data: Dữ liệu phân tích
            title: Tiêu đề báo cáo
            timestamp: Timestamp báo cáo
            readable_time: Thời gian đọc được
            include_recommendations: Có bao gồm khuyến nghị hay không
            
        Returns:
            Nội dung báo cáo dạng Markdown
        """
        # Tiêu đề và thông tin chung
        content = f"# {title}\n\n"
        content += f"**Thời gian tạo:** {readable_time}\n\n"
        content += f"**ID báo cáo:** {timestamp}\n\n"
        
        # Tóm tắt phân tích
        content += "## Tóm tắt phân tích\n\n"
        
        # Thử lấy thông tin tổng quan từ analysis_data
        summary = self._extract_summary_from_data(analysis_data)
        content += f"{summary}\n\n"
        
        # Phân tích theo mô hình OSI
        content += "## Phân tích theo mô hình OSI\n\n"
        
        # Tạo phân tích cho từng tầng OSI
        osi_layers = [
            "Physical Layer (Tầng 1)",
            "Data Link Layer (Tầng 2)",
            "Network Layer (Tầng 3)",
            "Transport Layer (Tầng 4)",
            "Session Layer (Tầng 5)",
            "Presentation Layer (Tầng 6)",
            "Application Layer (Tầng 7)"
        ]
        
        # Phân tích từng tầng
        osi_analysis = self._extract_osi_analysis(analysis_data)
        
        for i, layer in enumerate(osi_layers):
            content += f"### {layer}\n\n"
            layer_num = i + 1
            layer_content = osi_analysis.get(layer_num, "Không có dữ liệu phân tích cho tầng này.")
            content += f"{layer_content}\n\n"
        
        # Thêm phần phát hiện tấn công nếu có
        attacks = self._extract_attacks(analysis_data)
        if attacks:
            content += "## Phát hiện tấn công\n\n"
            for attack in attacks:
                content += f"### {attack.get('name', 'Tấn công không xác định')}\n\n"
                content += f"**Mức độ nghiêm trọng:** {attack.get('severity', 'Không xác định')}\n\n"
                content += f"**Mô tả:** {attack.get('description', 'Không có mô tả')}\n\n"
        
        # Thêm khuyến nghị nếu được yêu cầu
        if include_recommendations:
            content += "## Khuyến nghị và biện pháp khắc phục\n\n"
            recommendations = self._extract_recommendations(analysis_data)
            
            if recommendations:
                for i, rec in enumerate(recommendations, 1):
                    content += f"{i}. {rec}\n\n"
            else:
                content += "Không có khuyến nghị cụ thể.\n\n"
        
        # Kết luận
        content += "## Kết luận\n\n"
        conclusion = self._extract_conclusion(analysis_data)
        content += f"{conclusion}\n\n"
        
        return content
    
    def _extract_summary_from_data(self, data: Dict[str, Any]) -> str:
        """Trích xuất tóm tắt từ dữ liệu phân tích."""
        if not data:
            return "Không có dữ liệu phân tích để tóm tắt."
        
        # Thử lấy từ các vị trí khác nhau trong dữ liệu
        if "summary" in data:
            return data["summary"]
        elif "analysis" in data:
            summary = data["analysis"]
            if isinstance(summary, str):
                # Giới hạn độ dài của tóm tắt
                max_len = 500
                if len(summary) > max_len:
                    return summary[:max_len] + "..."
                return summary
        elif "osi_analysis" in data and "summary" in data["osi_analysis"]:
            return data["osi_analysis"]["summary"]
        
        # Nếu không tìm thấy, tạo tóm tắt dựa trên các thông tin khác
        protocols = []
        attacks = []
        
        if "protocol_statistics" in data:
            protocol_stats = data["protocol_statistics"]
            protocols = [f"{proto}: {count}" for proto, count in protocol_stats.items()]
        
        if "attacks" in data:
            attacks = [attack.get("name", "Tấn công không xác định") for attack in data["attacks"]]
        
        # Tạo tóm tắt
        result = "Báo cáo này phân tích lưu lượng mạng và các vấn đề bảo mật.\n\n"
        
        if protocols:
            result += "**Các giao thức phát hiện được:**\n"
            for protocol_info in protocols[:5]:  # Giới hạn số lượng
                result += f"- {protocol_info}\n"
            if len(protocols) > 5:
                result += f"- ... và {len(protocols) - 5} giao thức khác\n"
            result += "\n"
        
        if attacks:
            result += "**Các mối đe dọa phát hiện được:**\n"
            for attack in attacks:
                result += f"- {attack}\n"
            result += "\n"
        
        return result
    
    def _extract_osi_analysis(self, data: Dict[str, Any]) -> Dict[int, str]:
        """Trích xuất phân tích cho từng tầng OSI."""
        result = {}
        
        # Thử các cấu trúc dữ liệu khác nhau
        if "osi_analysis" in data and isinstance(data["osi_analysis"], dict):
            osi_data = data["osi_analysis"]
            
            # Duyệt qua 7 tầng OSI
            for i in range(1, 8):
                layer_key = f"layer_{i}"
                if layer_key in osi_data:
                    result[i] = osi_data[layer_key]
                    
        elif "osi_layers" in data and isinstance(data["osi_layers"], dict):
            # Duyệt qua 7 tầng OSI
            for i in range(1, 8):
                if str(i) in data["osi_layers"]:
                    result[i] = data["osi_layers"][str(i)]
        
        # Nếu không tìm thấy dữ liệu cụ thể cho các tầng, thử tìm kiếm các từ khóa liên quan
        if not result:
            # Ánh xạ từ khóa đến các tầng
            keywords = {
                1: ["physical", "signal", "cable", "hardware"],
                2: ["data link", "ethernet", "mac", "arp", "vlan", "switch"],
                3: ["network", "ip", "icmp", "routing", "address"],
                4: ["transport", "tcp", "udp", "segment", "port"],
                5: ["session", "socks", "netbios", "rpc"],
                6: ["presentation", "tls", "ssl", "encode", "compress"],
                7: ["application", "http", "dns", "dhcp", "ftp", "telnet", "ssh"]
            }
            
            # Nếu có phân tích dạng văn bản, tìm các đoạn văn liên quan đến từng tầng
            if "analysis" in data and isinstance(data["analysis"], str):
                text = data["analysis"].lower()
                paragraphs = text.split("\n\n")
                
                for i, keywords_for_layer in keywords.items():
                    relevant_paragraphs = []
                    for p in paragraphs:
                        if any(kw in p.lower() for kw in keywords_for_layer):
                            relevant_paragraphs.append(p)
                    
                    if relevant_paragraphs:
                        result[i] = "\n\n".join(relevant_paragraphs)
        
        # Tạo nội dung mẫu cho các tầng không có dữ liệu
        for i in range(1, 8):
            if i not in result:
                if i == 1:
                    result[i] = "Không có dữ liệu về tầng vật lý (Physical). Tầng này liên quan đến các kết nối phần cứng, tín hiệu điện và kết nối vật lý."
                elif i == 2:
                    result[i] = "Không có thông tin cụ thể về tầng liên kết dữ liệu (Data Link). Tầng này xử lý các giao thức như Ethernet, ARP, và các vấn đề liên quan đến địa chỉ MAC."
                elif i == 3:
                    result[i] = "Không có dữ liệu về tầng mạng (Network). Tầng này xử lý định tuyến IP và giao thức ICMP."
                elif i == 4:
                    result[i] = "Không có thông tin cụ thể về tầng giao vận (Transport). Tầng này xử lý các giao thức như TCP, UDP và quản lý các cổng."
                elif i == 5:
                    result[i] = "Không có dữ liệu về tầng phiên (Session). Tầng này quản lý các phiên kết nối giữa các ứng dụng."
                elif i == 6:
                    result[i] = "Không có thông tin cụ thể về tầng trình diễn (Presentation). Tầng này xử lý mã hóa, nén và chuyển đổi dữ liệu."
                elif i == 7:
                    result[i] = "Không có dữ liệu về tầng ứng dụng (Application). Tầng này xử lý các giao thức như HTTP, DNS, DHCP."
        
        return result
    
    def _extract_attacks(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Trích xuất thông tin về các cuộc tấn công."""
        if "attacks" in data and isinstance(data["attacks"], list):
            return data["attacks"]
        return []
    
    def _extract_recommendations(self, data: Dict[str, Any]) -> List[str]:
        """Trích xuất các khuyến nghị."""
        recommendations = []
        
        # Thử các vị trí khác nhau trong dữ liệu
        if "recommendations" in data:
            if isinstance(data["recommendations"], list):
                return data["recommendations"]
            elif isinstance(data["recommendations"], str):
                # Nếu là chuỗi, tách thành danh sách
                rec_text = data["recommendations"]
                return [r.strip() for r in rec_text.split("\n") if r.strip()]
        
        # Nếu không tìm thấy khuyến nghị, tạo một số khuyến nghị chung
        if "attacks" in data and data["attacks"]:
            for attack in data["attacks"]:
                attack_name = attack.get("name", "").lower()
                if "arp" in attack_name:
                    recommendations.append("Triển khai Dynamic ARP Inspection (DAI) trên switch để ngăn chặn tấn công ARP spoofing.")
                elif "dns" in attack_name:
                    recommendations.append("Bảo vệ máy chủ DNS bằng cách triển khai DNSSEC và giám sát các truy vấn DNS bất thường.")
                elif "tcp" in attack_name or "syn" in attack_name:
                    recommendations.append("Cấu hình tường lửa để giới hạn số lượng kết nối TCP đồng thời và enable SYN cookies.")
        
        # Nếu vẫn không có khuyến nghị, thêm một số khuyến nghị chung
        if not recommendations:
            recommendations = [
                "Triển khai giám sát mạng 24/7 để phát hiện sớm các mối đe dọa bảo mật.",
                "Cập nhật firmware và phần mềm cho các thiết bị mạng thường xuyên.",
                "Thực hiện phân đoạn mạng để hạn chế phạm vi ảnh hưởng của các cuộc tấn công.",
                "Sử dụng phương pháp xác thực mạnh cho tất cả các tài khoản quản trị mạng.",
                "Thiết lập chính sách giám sát và ứng phó sự cố để đối phó với các mối đe dọa bảo mật."
            ]
        
        return recommendations
    
    def _extract_conclusion(self, data: Dict[str, Any]) -> str:
        """Trích xuất kết luận."""
        # Thử các vị trí khác nhau trong dữ liệu
        if "conclusion" in data:
            return data["conclusion"]
        
        # Tạo kết luận dựa trên số lượng tấn công
        attacks = self._extract_attacks(data)
        
        if attacks:
            return (f"Phân tích mạng đã phát hiện {len(attacks)} loại tấn công tiềm ẩn. "
                   f"Cần có biện pháp khắc phục kịp thời để đảm bảo an toàn cho hệ thống mạng.")
        else:
            return ("Không phát hiện tấn công rõ ràng trong dữ liệu được phân tích. "
                   "Tuy nhiên, nên tiếp tục giám sát và thực hiện các biện pháp bảo mật phòng ngừa.")
    
    def _convert_to_pdf(self, markdown_path: str) -> str:
        """
        Chuyển đổi file Markdown thành PDF.
        
        Args:
            markdown_path: Đường dẫn đến file Markdown
            
        Returns:
            Đường dẫn đến file PDF đã tạo
        """
        try:
            # Đường dẫn đến file PDF
            pdf_path = markdown_path.replace('.md', '.pdf')
            
            # Đọc nội dung Markdown
            with open(markdown_path, 'r', encoding='utf-8') as f:
                markdown_content = f.read()
            
            # Chuyển đổi Markdown sang HTML
            html_content = markdown.markdown(markdown_content, extensions=['tables', 'fenced_code'])
            
            # Thêm CSS cơ bản
            html_with_css = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <style>
                    body {{ 
                        font-family: Arial, sans-serif; 
                        line-height: 1.6;
                        max-width: 800px;
                        margin: 0 auto;
                        padding: 20px;
                    }}
                    h1 {{ color: #2c3e50; }}
                    h2 {{ color: #3498db; border-bottom: 1px solid #eee; padding-bottom: 5px; }}
                    h3 {{ color: #2980b9; }}
                    table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    code {{ background-color: #f8f8f8; border: 1px solid #ddd; padding: 2px 5px; }}
                    pre {{ background-color: #f8f8f8; border: 1px solid #ddd; padding: 10px; overflow-x: auto; }}
                    blockquote {{ background-color: #f9f9f9; border-left: 5px solid #ccc; padding: 10px 20px; margin: 15px 0; }}
                </style>
            </head>
            <body>
                {html_content}
            </body>
            </html>
            """
            
            # Tạo file HTML thay thế cho PDF
            html_path = markdown_path.replace('.md', '.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_with_css)
            
            # Thử tạo PDF với WeasyPrint
            try:
                import weasyprint
                weasyprint.HTML(html_path).write_pdf(pdf_path)
                
                print(f"PDF đã được tạo thành công: {pdf_path}")
                return pdf_path
            except Exception as pdf_error:
                print(f"Không thể tạo PDF, sử dụng HTML làm thay thế: {str(pdf_error)}")
                # Trả về đường dẫn HTML thay thế
                return html_path
            
        except ImportError as e:
            print(f"Không thể import thư viện cần thiết: {str(e)}")
            # Tạo một thông báo trong file HTML để hướng dẫn người dùng
            try:
                error_html_path = markdown_path.replace('.md', '.html')
                with open(markdown_path, 'r', encoding='utf-8') as f:
                    md_content = f.read()
                
                html_content = markdown.markdown(md_content, extensions=['tables', 'fenced_code'])
                html_with_notice = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <style>
                        body {{ font-family: Arial, sans-serif; line-height: 1.6; max-width: 800px; margin: 0 auto; padding: 20px; }}
                        .notice {{ background-color: #fff3cd; padding: 15px; border-left: 5px solid #ffc107; margin-bottom: 20px; }}
                    </style>
                </head>
                <body>
                    <div class="notice">
                        <h2>Không thể tạo file PDF</h2>
                        <p>WeasyPrint không được cài đặt đúng cách hoặc thiếu các thư viện phụ thuộc.</p>
                        <p>Vui lòng tham khảo <a href="https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation">hướng dẫn cài đặt</a> để cài đặt đầy đủ.</p>
                    </div>
                    {html_content}
                </body>
                </html>
                """
                with open(error_html_path, 'w', encoding='utf-8') as f:
                    f.write(html_with_notice)
                return error_html_path
            except Exception as html_error:
                print(f"Không thể tạo HTML thay thế: {str(html_error)}")
                return f"Error generating PDF: {str(e)}"
        except Exception as e:
            print(f"Lỗi không xác định khi tạo PDF: {str(e)}")
            return f"Error: {str(e)}"
    
    def get_report_list(self) -> List[Dict[str, str]]:
        """
        Lấy danh sách các báo cáo đã tạo.
        
        Returns:
            Danh sách các báo cáo dưới dạng từ điển
        """
        if not os.path.exists(self.output_dir):
            return []
            
        reports = []
        
        # Lấy tất cả các file .md trong thư mục báo cáo
        for file in os.listdir(self.output_dir):
            if file.endswith(".md") and (file.startswith("network_report_") or file.startswith("OSI_report_")):
                # Trích xuất timestamp từ tên file
                try:
                    if file.startswith("network_report_"):
                        timestamp = file.replace("network_report_", "").replace(".md", "")
                    else:
                        timestamp = file.replace("OSI_report_", "").replace(".md", "")
                        
                    readable_time = datetime.datetime.fromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Kiểm tra xem file PDF hoặc file HTML có tồn tại không
                    pdf_path = os.path.join(self.output_dir, file.replace(".md", ".pdf"))
                    html_path = os.path.join(self.output_dir, file.replace(".md", ".html"))
                    
                    pdf_exists = os.path.exists(pdf_path)
                    html_exists = os.path.exists(html_path)
                    
                    # Đường dẫn để tải xuống - ưu tiên PDF, nếu không có thì dùng HTML
                    download_path = file.replace(".md", ".pdf") if pdf_exists else file.replace(".md", ".html")
                    download_type = "pdf" if pdf_exists else "html"
                    
                    # Đọc file để trích xuất tiêu đề báo cáo
                    report_title = "Báo cáo phân tích mạng"
                    try:
                        with open(os.path.join(self.output_dir, file), 'r', encoding='utf-8') as f:
                            first_line = f.readline().strip()
                            if first_line.startswith('# '):
                                report_title = first_line[2:].strip()
                    except Exception:
                        pass
                    
                    reports.append({
                        'timestamp': timestamp,
                        'readable_time': readable_time,
                        'filename': file,
                        'filepath': os.path.join(self.output_dir, file),
                        'has_pdf': pdf_exists,
                        'has_html': html_exists,
                        'download_path': download_path,
                        'download_type': download_type,
                        'report_title': report_title
                    })
                except (ValueError, OSError):
                    # Bỏ qua file không đúng định dạng
                    continue
        
        # Sắp xếp theo thời gian giảm dần (mới nhất lên đầu)
        reports.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return reports
    
    def delete_report(self, report_id: str) -> bool:
        """
        Xóa báo cáo theo ID.
        
        Args:
            report_id: ID báo cáo (timestamp)
            
        Returns:
            True nếu xóa thành công, False nếu không
        """
        try:
            # Lấy đường dẫn các file cần xóa với cả hai định dạng tên file
            md_paths = [
                os.path.join(self.output_dir, f"network_report_{report_id}.md"),
                os.path.join(self.output_dir, f"OSI_report_{report_id}.md")
            ]
            
            # Tìm file markdown tồn tại
            md_path = None
            for path in md_paths:
                if os.path.exists(path):
                    md_path = path
                    break
            
            if not md_path:
                print(f"Không tìm thấy file báo cáo với ID: {report_id}")
                return False
                
            # Xác định tên file cơ sở
            base_name = os.path.basename(md_path).replace('.md', '')
            
            # Xóa file markdown
            os.remove(md_path)
            print(f"Đã xóa {md_path}")
            
            # Xóa các file liên quan
            for ext in ['.pdf', '.html']:
                related_file = os.path.join(self.output_dir, f"{base_name}{ext}")
                if os.path.exists(related_file):
                    os.remove(related_file)
                    print(f"Đã xóa {related_file}")
                
            return True
        except Exception as e:
            print(f"Lỗi khi xóa báo cáo: {str(e)}")
            return False
    
    def generate_sample_report(self) -> Dict[str, str]:
        """
        Tạo báo cáo mẫu khi không có dữ liệu phân tích.
        
        Returns:
            Thông tin về báo cáo đã tạo
        """
        # Tạo dữ liệu mẫu
        sample_data = {
            "summary": "Đây là báo cáo mẫu tạo ra khi không có dữ liệu phân tích thực tế.",
            "protocol_statistics": {
                "TCP": 150,
                "UDP": 75,
                "ICMP": 25,
                "ARP": 10,
                "DNS": 45,
                "HTTP": 30
            },
            "attacks": [
                {
                    "name": "ARP Spoofing (Mẫu)",
                    "severity": "Cao",
                    "description": "Phát hiện các gói tin ARP không hợp lệ. Có thể là dấu hiệu của tấn công ARP spoofing."
                },
                {
                    "name": "Port Scanning (Mẫu)",
                    "severity": "Trung bình",
                    "description": "Phát hiện quét cổng TCP trên nhiều dịch vụ. Có thể là dấu hiệu của việc thăm dò hệ thống."
                }
            ],
            "recommendations": [
                "Triển khai Dynamic ARP Inspection (DAI) để ngăn chặn tấn công ARP spoofing.",
                "Cấu hình tường lửa để phát hiện và chặn quét cổng.",
                "Giám sát lưu lượng mạng bất thường và các gói tin đáng ngờ.",
                "Cập nhật firmware và phần mềm các thiết bị mạng thường xuyên."
            ],
            "conclusion": "Đây là báo cáo mẫu để minh họa định dạng và cấu trúc của báo cáo phân tích mạng."
        }
        
        # Tạo báo cáo từ dữ liệu mẫu
        return self.generate_report(sample_data, "Báo Cáo Phân Tích Mạng (Mẫu)") 