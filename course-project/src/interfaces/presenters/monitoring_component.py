"""
Monitoring Component - Xử lý giám sát mạng thời gian thực
"""
from typing import Tuple
import os
from src.interfaces.presenters.base_presenter import BasePresenter
from src.interfaces.presenters.chart_creator import ChartCreator

class MonitoringComponent:
    """Component xử lý giám sát mạng thời gian thực."""
    
    def __init__(self, base_presenter: BasePresenter):
        """
        Khởi tạo monitoring component.
        
        Args:
            base_presenter: BasePresenter instance
        """
        self.base_presenter = base_presenter
        self.chart_creator = ChartCreator()
    
    def start_monitoring(self, duration_minutes: int = 30) -> str:
        """
        Bắt đầu giám sát mạng thời gian thực.
        
        Args:
            duration_minutes: Số phút cần giám sát
            
        Returns:
            Kết quả giám sát dạng văn bản
        """
        # Khi không có tệp PCAP đã tải
        if not self.base_presenter.latest_pcap_file:
            return "Vui lòng tải lên file PCAP trước khi bắt đầu giám sát."
        
        file_name = os.path.basename(self.base_presenter.latest_pcap_file)
        
        try:
            # Gọi phương thức phát hiện tấn công của controller
            results = self.base_presenter.controller.detect_attacks_realtime(duration_minutes)
            
            # Xử lý kết quả
            attacks = results.get("attacks", [])
            attack_count = results.get("attack_count", 0)
            
            # Tạo kết quả giám sát
            if attack_count > 0:
                monitoring_results = f"## Kết quả giám sát ({file_name})\n\n"
                monitoring_results += f"⚠️ **Đã phát hiện {attack_count} cuộc tấn công!**\n\n"
                
                # Nhóm tấn công theo loại
                attack_types = {}
                for attack in attacks:
                    attack_type = attack.get("attack_type", "Unknown")
                    if attack_type not in attack_types:
                        attack_types[attack_type] = []
                    attack_types[attack_type].append(attack)
                
                for attack_type, type_attacks in attack_types.items():
                    monitoring_results += f"### {attack_type} ({len(type_attacks)} vụ)\n"
                    for attack in type_attacks:
                        monitoring_results += f"- **Mức độ nghiêm trọng**: {attack.get('severity', 0)}/10\n"
                        monitoring_results += f"- **Mô tả**: {attack.get('description', 'Không có mô tả')}\n"
                        monitoring_results += f"- **Thời gian**: {attack.get('timestamp', 'Không xác định')}\n"
                        monitoring_results += "---\n"
            else:
                monitoring_results = f"## Kết quả giám sát ({file_name})\n\n"
                monitoring_results += "✅ **Không phát hiện tấn công nào trong khoảng thời gian giám sát.**\n\n"
                monitoring_results += f"Đã giám sát lưu lượng mạng trong {duration_minutes} phút.\n"
                
            return monitoring_results
        except Exception as e:
            return f"Lỗi khi giám sát: {str(e)}"
    
    def display_attack_details(self, hours: int) -> Tuple:
        """
        Hiển thị chi tiết về các cuộc tấn công đã phát hiện.
        
        Args:
            hours: Số giờ cần xem lại
            
        Returns:
            Tuple chứa các thành phần UI cần thiết
        """
        # Phần này bạn có thể bổ sung theo nhu cầu
        return "Chức năng đang được phát triển", None, None
    
    def display_flow_stats(self, hours: int) -> Tuple:
        """
        Hiển thị thống kê luồng.
        
        Args:
            hours: Số giờ cần xem lại
            
        Returns:
            Tuple chứa các thành phần UI cần thiết
        """
        # Phần này bạn có thể bổ sung theo nhu cầu
        return "Chức năng đang được phát triển", None 