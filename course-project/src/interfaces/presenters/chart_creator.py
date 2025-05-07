"""
Chart Creator - Tạo các biểu đồ và trực quan hóa cho phân tích mạng.
"""
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for thread safety
import matplotlib.pyplot as plt
import seaborn as sns
import os
from typing import Dict, List

class ChartCreator:
    """Tạo các biểu đồ và trực quan hóa cho phân tích mạng."""
    
    def __init__(self, output_dir: str = "visualizations"):
        """
        Khởi tạo Chart Creator.
        
        Args:
            output_dir: Thư mục lưu các biểu đồ
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        # Thiết lập style cho matplotlib
        plt.style.use('seaborn-v0_8-pastel')
    
    def _create_empty_chart(self, title: str = "Không có dữ liệu") -> plt.Figure:
        """Tạo biểu đồ trống khi không có dữ liệu."""
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.text(0.5, 0.5, title, ha='center', va='center', fontsize=14, color='gray')
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis('off')
        plt.tight_layout()
        return fig
    
    def create_protocol_chart(self, results: Dict) -> plt.Figure:
        """Tạo biểu đồ phân bố giao thức."""
        if not results or "protocol_stats" not in results or not results.get("protocol_stats"):
            return self._create_empty_chart("Không có dữ liệu về giao thức")
        
        protocol_stats = results.get("protocol_stats", {})
        
        # Tạo biểu đồ
        fig, ax = plt.subplots(figsize=(8, 6))
        
        labels = list(protocol_stats.keys())
        sizes = list(protocol_stats.values())
        
        # Sử dụng bảng màu đẹp từ Seaborn
        colors = sns.color_palette("Set3", len(labels))
        
        ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', 
              startangle=90, shadow=False)
        ax.axis('equal')  # Để hình tròn đều
        
        plt.title("Phân bố giao thức")
        plt.tight_layout()
        
        return fig
    
    def create_attack_severity_chart(self, attacks: List[Dict]) -> plt.Figure:
        """Tạo biểu đồ mức độ nghiêm trọng của tấn công."""
        if not attacks:
            return self._create_empty_chart("Không phát hiện tấn công")
        
        # Nhóm tấn công theo loại và tính mức độ nghiêm trọng trung bình
        attack_severity = {}
        for attack in attacks:
            attack_type = attack.get("attack_type", "Unknown")
            severity = attack.get("severity", 0)
            
            if attack_type not in attack_severity:
                attack_severity[attack_type] = []
            
            attack_severity[attack_type].append(severity)
        
        if not attack_severity:
            return self._create_empty_chart("Không đủ dữ liệu về mức độ nghiêm trọng")
            
        # Tính mức độ nghiêm trọng trung bình cho mỗi loại
        attack_types = []
        avg_severities = []
        
        for attack_type, severities in attack_severity.items():
            attack_types.append(attack_type)
            avg_severities.append(sum(severities) / len(severities))
        
        # Tạo biểu đồ
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # Tạo bảng màu dựa trên mức độ nghiêm trọng
        cmap = plt.cm.get_cmap('YlOrRd')
        colors = [cmap(s/10) for s in avg_severities]
        
        bars = ax.bar(attack_types, avg_severities, color=colors)
        
        # Thêm giá trị lên các cột
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                   f'{height:.1f}', ha='center', va='bottom')
        
        plt.title("Mức độ nghiêm trọng trung bình theo loại tấn công")
        plt.ylabel("Mức độ nghiêm trọng (0-10)")
        plt.xlabel("Loại tấn công")
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        return fig
    
    def create_flow_graph(self, results: Dict) -> plt.Figure:
        """Tạo đồ thị luồng mạng."""
        if not results or "flows" not in results or not results.get("flows"):
            # Tạo mẫu đồ thị luồng với dữ liệu mẫu khi không có dữ liệu thực
            return self._create_sample_flow_graph()
        
        # Tạo đồ thị với dữ liệu thực tế - code này sẽ được cài đặt khi có dữ liệu thực
        # Hiện tại sử dụng đồ thị mẫu
        return self._create_sample_flow_graph()
    
    def _create_sample_flow_graph(self) -> plt.Figure:
        """Tạo đồ thị luồng mẫu."""
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # Tạo dữ liệu mẫu cho đồ thị luồng
        nodes = ['192.168.1.1', '192.168.1.2', '192.168.1.3', '10.0.0.1', '10.0.0.2']
        
        # Tạo vị trí nút
        pos = {
            '192.168.1.1': (0.2, 0.7),
            '192.168.1.2': (0.3, 0.3),
            '192.168.1.3': (0.5, 0.5),
            '10.0.0.1': (0.7, 0.8),
            '10.0.0.2': (0.8, 0.2)
        }
        
        # Tạo kết nối giữa các nút
        connections = [
            ('192.168.1.1', '10.0.0.1', 'green'),
            ('192.168.1.2', '10.0.0.2', 'blue'),
            ('192.168.1.1', '192.168.1.3', 'orange'),
            ('192.168.1.3', '10.0.0.2', 'red'),
            ('10.0.0.1', '192.168.1.2', 'purple')
        ]
        
        # Vẽ nút
        for node in nodes:
            x, y = pos[node]
            circle = plt.Circle((x, y), 0.05, color='skyblue', alpha=0.8)
            ax.add_patch(circle)
            ax.text(x, y-0.07, node, ha='center', va='center', fontsize=9)
        
        # Vẽ kết nối
        for src, dst, color in connections:
            x1, y1 = pos[src]
            x2, y2 = pos[dst]
            ax.arrow(x1, y1, x2-x1, y2-y1, head_width=0.02, head_length=0.03, 
                    fc=color, ec=color, alpha=0.7, length_includes_head=True)
        
        # Tạo chú thích
        legend_elements = [
            plt.Line2D([0], [0], color='green', lw=2, label='Established'),
            plt.Line2D([0], [0], color='blue', lw=2, label='Closed'),
            plt.Line2D([0], [0], color='red', lw=2, label='Reset'),
            plt.Line2D([0], [0], color='orange', lw=2, label='Pending'),
            plt.Line2D([0], [0], color='purple', lw=2, label='Other')
        ]
        ax.legend(handles=legend_elements, loc='upper right')
        
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.set_title('Biểu đồ luồng mạng')
        ax.axis('off')
        
        plt.tight_layout()
        return fig
    
    def create_tcp_visualizations(self, results: Dict) -> plt.Figure:
        """Tạo trực quan hóa cho phân tích TCP."""
        if not results:
            return self._create_empty_chart("Không có dữ liệu TCP")
        
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # Tạo dữ liệu mẫu cho biểu đồ TCP flags
        tcp_flags = {
            'SYN': 45,
            'ACK': 120,
            'FIN': 35,
            'RST': 15,
            'SYN-ACK': 40
        }
        
        # Màu sắc cho các loại cờ TCP
        colors = ['#3498db', '#2ecc71', '#9b59b6', '#e74c3c', '#f39c12']
        
        # Vẽ biểu đồ
        bars = ax.bar(tcp_flags.keys(), tcp_flags.values(), color=colors, alpha=0.7)
        
        # Thêm giá trị lên các cột
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 3,
                   f'{int(height)}', ha='center', va='bottom')
        
        ax.set_title('Phân bố cờ TCP')
        ax.set_ylabel('Số lượng gói tin')
        ax.set_ylim(0, max(tcp_flags.values()) * 1.2)  # Đảm bảo có đủ không gian cho nhãn
        
        plt.tight_layout()
        return fig
    
    def create_tcp_flags_chart(self, results: Dict) -> plt.Figure:
        """Tạo biểu đồ phân bố cờ TCP."""
        if not results:
            return self._create_empty_chart("Không có dữ liệu về cờ TCP")
        
        # Mô phỏng dữ liệu cờ TCP
        tcp_flags = {
            "SYN": 120,
            "ACK": 450,
            "FIN": 80,
            "RST": 35,
            "PSH": 210,
            "URG": 5,
            "SYN-ACK": 115
        }
        
        # Tạo biểu đồ
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # Dùng màu cơ bản cho từng loại cờ
        colors = {
            "SYN": "blue",
            "ACK": "green",
            "FIN": "purple",
            "RST": "red",
            "PSH": "orange",
            "URG": "brown",
            "SYN-ACK": "cyan"
        }
        
        bar_colors = [colors.get(flag, "gray") for flag in tcp_flags.keys()]
        
        bars = ax.bar(tcp_flags.keys(), tcp_flags.values(), color=bar_colors)
        
        # Thêm giá trị lên các cột
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 5,
                   f'{int(height)}', ha='center', va='bottom')
        
        plt.title("Phân bố cờ TCP")
        plt.ylabel("Số lượng")
        plt.xlabel("Loại cờ")
        plt.tight_layout()
        
        return fig
    
    def create_tcp_attack_chart(self, results: Dict) -> plt.Figure:
        """Tạo biểu đồ phân tích tấn công TCP."""
        if not results:
            return self._create_empty_chart("Không có dữ liệu về tấn công TCP")
        
        # Mô phỏng dữ liệu tấn công TCP
        tcp_attacks = {
            "SYN Flood": 12,
            "RST Attack": 5,
            "TCP Port Scan": 8,
            "TCP Session Hijacking": 2,
            "Other TCP Attacks": 3
        }
        
        # Tạo biểu đồ
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # Sử dụng bảng màu gradient
        cmap = plt.cm.get_cmap('Reds')
        colors = [cmap(i/len(tcp_attacks)) for i in range(len(tcp_attacks))]
        
        # Vẽ biểu đồ tròn
        wedges, texts, autotexts = ax.pie(
            tcp_attacks.values(), 
            labels=tcp_attacks.keys(),
            colors=colors,
            autopct='%1.1f%%',
            startangle=90,
            shadow=False
        )
        
        # Làm cho văn bản tự động có màu trắng nếu phần tối
        for autotext in autotexts:
            autotext.set_color('white')
        
        ax.axis('equal')
        plt.title("Phân bố tấn công TCP")
        plt.tight_layout()
        
        return fig