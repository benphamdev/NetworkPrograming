"""
OSILayerAnalyzer - Specialized analyzer for OSI model layers in network traffic.
"""
from typing import Dict, Any
import json

class OSILayerAnalyzer:
    """Analyzer for network traffic according to the 7-layer OSI model."""
    
    def __init__(self, manager_agent):
        """
        Initialize the OSI layer analyzer.
        
        Args:
            manager_agent: Agent to use for generating analysis.
        """
        self.manager_agent = manager_agent
    
    def analyze(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Phân tích lưu lượng mạng theo các tầng của mô hình OSI.
        
        Args:
            results: Dictionary chứa kết quả phân tích gói tin.
        
        Returns:
            Kết quả phân tích theo mô hình OSI.
        """
        # Xây dựng prompt theo mô hình OSI
        prompt = self._build_osi_analysis_prompt(results)
        
        # Truy vấn agent
        response = self.manager_agent.run(prompt)
        
        # Xử lý phản hồi
        try:
            # Cố gắng phân tích JSON nếu có thể
            analyzed_results = json.loads(response)
        except (json.JSONDecodeError, TypeError):
            # Nếu không, sử dụng phản hồi gốc
            analyzed_results = {"analysis": response}
        
        return analyzed_results
    
    def _build_osi_analysis_prompt(self, results: Dict[str, Any]) -> str:
        """
        Xây dựng prompt để phân tích lưu lượng mạng theo mô hình OSI.
        
        Args:
            results: Dictionary chứa kết quả phân tích gói tin.
            
        Returns:
            Prompt string.
        """
        prompt = """
Là một chuyên gia điều tra số trong lĩnh vực mạng (Network Forensics Expert), hãy phân tích chi tiết lưu lượng mạng dưới đây theo mô hình OSI (7 tầng). 
Phân tích sâu về các dấu hiệu bất thường và các vấn đề bảo mật tiềm ẩn ở mỗi tầng.

Dưới đây là dữ liệu lưu lượng mạng cần phân tích:
"""
        
        # Thêm thống kê giao thức nếu có
        if "protocol_statistics" in results:
            proto_stats = results["protocol_statistics"]
            prompt += "\n## Thống kê giao thức:\n"
            for proto, count in proto_stats.items():
                prompt += f"- {proto}: {count} gói tin\n"
        
        # Thêm thống kê luồng nếu có
        if "flow_statistics" in results:
            flow_stats = results["flow_statistics"]
            prompt += "\n## Thống kê luồng:\n"
            for key, value in flow_stats.items():
                prompt += f"- {key}: {value}\n"
        
        # Thêm thông tin tấn công nếu có
        if "attacks" in results:
            attacks = results["attacks"]
            prompt += f"\n## Các cuộc tấn công đã phát hiện ({len(attacks)}):\n"
            for attack in attacks[:5]:  # Giới hạn 5 tấn công để tránh prompt quá dài
                attack_type = attack.get("attack_type", "Unknown")
                severity = attack.get("severity", 0)
                src = attack.get("src_ip", "unknown")
                dst = attack.get("dst_ip", "unknown")
                prompt += f"- {attack_type} (độ nghiêm trọng: {severity}/10): {src} -> {dst}\n"
            
            if len(attacks) > 5:
                prompt += f"- ... và {len(attacks) - 5} tấn công khác\n"
        
        # Thêm hướng dẫn phân tích theo mô hình OSI
        prompt += """
\nHãy phân tích dữ liệu trên theo 7 tầng của mô hình OSI như sau:

1. Tầng Vật lý (Physical Layer):
   - Phân tích các vấn đề liên quan đến phương tiện truyền dẫn, tín hiệu.

2. Tầng Liên kết dữ liệu (Data Link Layer):
   - Phân tích frame, ARP, MAC, các vấn đề về chuyển mạch.
   - Xác định dấu hiệu tấn công như ARP spoofing, MAC flooding.

3. Tầng Mạng (Network Layer):
   - Phân tích gói tin IP, định tuyến, phân mảnh.
   - Xác định dấu hiệu tấn công như IP spoofing, ICMP flood.

4. Tầng Giao vận (Transport Layer):
   - Phân tích kết nối TCP/UDP, port.
   - Xác định dấu hiệu tấn công như SYN flood, port scanning.

5. Tầng Phiên (Session Layer):
   - Phân tích phiên làm việc, các giao thức phiên.
   - Xác định dấu hiệu tấn công như session hijacking.

6. Tầng Trình diễn (Presentation Layer):
   - Phân tích mã hóa, nén, chuẩn hóa dữ liệu.
   - Xác định dấu hiệu tấn công như SSL exploitation.

7. Tầng Ứng dụng (Application Layer):
   - Phân tích giao thức ứng dụng (HTTP, DNS, FTP...).
   - Xác định dấu hiệu tấn công như DDoS, injection attacks.

Cho mỗi tầng, hãy:
1. Mô tả chi tiết các phát hiện chính
2. Xác định các dấu hiệu bất thường và mức độ nghiêm trọng (thấp/trung bình/cao)
3. Cung cấp các khuyến nghị bảo mật cụ thể
4. Liên kết các phát hiện với các kỹ thuật tấn công đã biết (nếu có)

Định dạng phân tích theo Markdown, với các đề mục rõ ràng và phân cấp phù hợp. Tập trung vào phân tích chuyên sâu nhưng ngắn gọn.
"""
        
        return prompt 