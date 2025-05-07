"""
Monitoring Component - Xử lý giám sát thời gian thực và hiển thị thống kê
"""
from typing import Dict, List, Tuple
from datetime import datetime
from src.interfaces.presenters.base_presenter import BasePresenter
from src.interfaces.presenters.chart_creator import ChartCreator

class MonitoringComponent:
    """Component xử lý giám sát thời gian thực và hiển thị thông tin thống kê."""
    
    def __init__(self, base_presenter: BasePresenter):
        """
        Khởi tạo monitoring component.
        
        Args:
            base_presenter: Instance BasePresenter
        """
        self.base_presenter = base_presenter
        self.chart_creator = ChartCreator()
    
    def start_monitoring(self, duration_minutes: int) -> str:
        """Bắt đầu giám sát thời gian thực để phát hiện tấn công."""
        if duration_minutes <= 0:
            return "Thời gian giám sát phải lớn hơn 0 phút."
            
        try:
            duration_minutes = int(duration_minutes)
            results = self.base_presenter.controller.detect_attacks_realtime(duration_minutes)
            
            summary = f"## Kết quả giám sát thời gian thực\n\n"
            start_time = datetime.fromisoformat(results["start_time"])
            end_time = datetime.fromisoformat(results["end_time"])
            
            summary += f"Thời gian giám sát: {start_time.strftime('%Y-%m-%d %H:%M:%S')} - {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            
            if results["attack_count"] > 0:
                summary += f"⚠️ **Phát hiện {results['attack_count']} cuộc tấn công!**\n\n"
                for i, attack in enumerate(results["attacks"], 1):
                    attack_type = attack.get("attack_type", "Unknown")
                    confidence = attack.get("confidence", 0)
                    severity = attack.get("severity", 0)
                    description = attack.get("description", "No description available")
                    
                    summary += f"### Tấn công #{i}: {attack_type}\n"
                    summary += f"- Mô tả: {description}\n"
                    summary += f"- Độ tin cậy: {confidence:.2f}\n"
                    summary += f"- Mức độ nghiêm trọng: {severity}/10\n\n"
            else:
                summary += "✅ **Không phát hiện tấn công nào trong thời gian giám sát.**\n"
            
            return summary
        except Exception as e:
            return f"Lỗi khi giám sát: {str(e)}"
    
    def display_attack_details(self, hours: int) -> Tuple:
        """Hiển thị chi tiết tấn công cho một khoảng thời gian cụ thể."""
        try:
            hours = int(hours)
            attacks = self.base_presenter.controller.get_attack_details(hours)
            
            summary = f"## Chi tiết tấn công (trong {hours} giờ qua)\n\n"
            
            if not attacks:
                summary += "✅ **Không phát hiện tấn công nào trong khoảng thời gian đã chọn.**\n"
                return summary, None, None
            
            summary += f"Phát hiện {len(attacks)} cuộc tấn công.\n\n"
            
            # Tạo bảng tấn công
            attack_table = self.base_presenter.format_attack_table(attacks)
            
            # Tạo biểu đồ mức độ nghiêm trọng của tấn công
            attack_chart = self.chart_creator.create_attack_severity_chart(attacks)
            
            return summary, attack_table, attack_chart
        except Exception as e:
            return f"Lỗi khi hiển thị chi tiết tấn công: {str(e)}", None, None
    
    def display_flow_stats(self, hours: int) -> Tuple:
        """Hiển thị thống kê luồng cho một khoảng thời gian cụ thể."""
        try:
            hours = int(hours)
            stats = self.base_presenter.controller.get_flow_statistics()
            
            summary = f"## Thống kê luồng (trong {hours} giờ qua)\n\n"
            
            if not stats:
                summary += "Không có thống kê luồng nào.\n"
                return summary, None
            
            for key, value in stats.items():
                formatted_key = key.replace('_', ' ').title()
                summary += f"- **{formatted_key}**: {value}\n"
            
            # Tạo biểu đồ giao thức
            protocol_chart = self.chart_creator.create_protocol_chart({"flow_statistics": stats})
            
            return summary, protocol_chart
        except Exception as e:
            return f"Lỗi khi hiển thị thống kê luồng: {str(e)}", None 