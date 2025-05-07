"""
Base Presenter - Lớp cơ sở cho Gradio Presenter
"""
from typing import Dict, List
import os
import pandas as pd
from datetime import datetime

class BasePresenter:
    """Lớp cơ sở cho Gradio Presenter."""
    
    def __init__(self, controller):
        """
        Khởi tạo presenter cơ sở.
        
        Args:
            controller: PacketAnalyzerController instance
        """
        self.controller = controller
        self.visualization_dir = "visualizations"
        os.makedirs(self.visualization_dir, exist_ok=True)
        
        # Lưu trữ kết quả phân tích gần nhất
        self.latest_results = None
        self.latest_pcap_file = None
        
    def format_attack_table(self, attacks: List[Dict]) -> pd.DataFrame:
        """Định dạng thông tin tấn công dưới dạng DataFrame để hiển thị."""
        if not attacks:
            return pd.DataFrame()
            
        data = []
        for attack in attacks:
            row = {
                "Loại tấn công": attack.get("attack_type", "Unknown"),
                "Mức độ nghiêm trọng": attack.get("severity", 0),
                "Độ tin cậy": f"{attack.get('confidence', 0):.2f}",
                "Địa chỉ IP nguồn": ", ".join(attack.get("source_ips", []))[:50],
                "Địa chỉ IP đích": ", ".join(attack.get("target_ips", []))[:50],
                "Mô tả": attack.get("description", "")[:100]
            }
            data.append(row)
            
        return pd.DataFrame(data)
    
    def format_flow_stats(self, stats: Dict) -> str:
        """Định dạng thống kê luồng thành chuỗi có thể đọc được."""
        if not stats:
            return "Không có thống kê luồng nào."
            
        result = "## Thống kê luồng\n\n"
        result += f"- **Tổng số luồng**: {stats.get('total_flows', 0)}\n"
        result += f"- **Luồng đã thiết lập**: {stats.get('established_count', 0)}\n"
        result += f"- **Luồng bị đặt lại**: {stats.get('reset_count', 0)}\n"
        result += f"- **Luồng đã đóng**: {stats.get('closed_count', 0)}\n"
        result += f"- **Luồng không đầy đủ**: {stats.get('incomplete_count', 0)}\n"
        
        return result 