"""
Chart Creator - Tạo các biểu đồ và trực quan hóa cho phân tích mạng.
"""
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for thread safety
import matplotlib.pyplot as plt
import seaborn as sns
import os
from typing import Dict, List
import random

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
        
        bars = ax.bar(attack_types, avg_severities, color=colors, alpha=0.7)
        
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
        if not results or "tcp_flags" not in results or not results.get("tcp_flags"):
            # Sử dụng dữ liệu mẫu khi không có dữ liệu thực
            tcp_flags = {
                "SYN": 120,
                "ACK": 450,
                "FIN": 80,
                "RST": 35,
                "PSH": 210,
                "URG": 5,
                "SYN-ACK": 115
            }
        else:
            # Sử dụng dữ liệu thực từ kết quả phân tích
            tcp_flags = results.get("tcp_flags")
        
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
    
    def create_device_status_chart(self, results: Dict) -> plt.Figure:
        """
        Tạo biểu đồ/bảng trạng thái thiết bị.
        
        Args:
            results: Kết quả phân tích gói tin

        Returns:
            Biểu đồ trạng thái thiết bị
        """
        if not results or "devices" not in results or not results.get("devices"):
            # Tạo bảng trạng thái mẫu khi không có dữ liệu thực
            return self._create_sample_device_status()
        
        devices = results.get("devices", [])
        # Tạo biểu đồ với dữ liệu thực tế
        return self._create_device_status_chart(devices)
    
    def _create_sample_device_status(self) -> plt.Figure:
        """Tạo biểu đồ trạng thái thiết bị mẫu."""
        # Tạo dữ liệu mẫu
        devices = [
            {"name": "Router-Core", "ip": "192.168.1.1", "status": "Online", "response_time": 5},
            {"name": "Switch-Floor1", "ip": "192.168.1.2", "status": "Online", "response_time": 3},
            {"name": "Firewall-Main", "ip": "192.168.1.3", "status": "High CPU", "response_time": 25},
            {"name": "Server-Web", "ip": "10.0.0.1", "status": "Online", "response_time": 8},
            {"name": "Server-DB", "ip": "10.0.0.2", "status": "Offline", "response_time": None},
            {"name": "Switch-Floor2", "ip": "192.168.1.4", "status": "High Memory", "response_time": 15}
        ]
        
        return self._create_device_status_chart(devices)
    
    def _create_device_status_chart(self, devices: List[Dict]) -> plt.Figure:
        """
        Tạo biểu đồ trạng thái thiết bị từ dữ liệu.
        
        Args:
            devices: Danh sách thiết bị với trạng thái

        Returns:
            Biểu đồ dạng bảng hiển thị trạng thái thiết bị
        """
        # Sắp xếp thiết bị - offline xuống cuối
        sorted_devices = sorted(devices, key=lambda x: x["status"] == "Offline")
        
        # Tạo bảng
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.axis('tight')
        ax.axis('off')
        
        # Chuẩn bị dữ liệu cho bảng
        headers = ["Thiết bị", "IP", "Trạng thái", "Thời gian phản hồi (ms)"]
        data = []
        colors = []
        
        # Định nghĩa màu cho trạng thái
        status_colors = {
            "Online": "#a0d995",       # Xanh lá nhạt
            "Offline": "#ff9999",      # Đỏ nhạt
            "High CPU": "#ffcc99",     # Cam nhạt
            "High Memory": "#ffcc99",  # Cam nhạt
            "Warning": "#ffffcc"       # Vàng nhạt
        }
        
        # Chuẩn bị dữ liệu và màu sắc
        for device in sorted_devices:
            name = device.get("name", "Unknown")
            ip = device.get("ip", "")
            status = device.get("status", "Unknown")
            response_time = device.get("response_time", None)
            
            # Định dạng thời gian phản hồi
            if response_time is None:
                response_str = "N/A"
            else:
                response_str = f"{response_time} ms"
                # Thêm biểu tượng cảnh báo nếu phản hồi cao
                if response_time > 20:
                    response_str += " ⚠️"
                elif response_time > 10:
                    response_str += " ⚡"
            
            # Thêm biểu tượng trạng thái
            if status == "Online":
                status_display = "✅ Online"
            elif status == "Offline":
                status_display = "❌ Offline"
            elif status == "High CPU":
                status_display = "⚠️ CPU cao"
            elif status == "High Memory":
                status_display = "⚠️ Bộ nhớ cao"
            else:
                status_display = "❓ " + status
            
            data.append([name, ip, status_display, response_str])
            colors.append(status_colors.get(status, "#ffffff"))
        
        # Tạo bảng
        table = ax.table(
            cellText=data, 
            colLabels=headers, 
            loc='center',
            cellLoc='center',
            colWidths=[0.25, 0.25, 0.25, 0.25]
        )
        
        # Định dạng bảng
        table.auto_set_font_size(False)
        table.set_fontsize(10)
        table.scale(1, 1.5)
        
        # Đặt màu nền cho các hàng dữ liệu
        for i in range(len(data)):
            for j in range(len(headers)):
                cell = table[(i+1, j)]  # +1 vì hàng 0 là header
                cell.set_facecolor(colors[i])
        
        # Định dạng header
        for j, header in enumerate(headers):
            cell = table[(0, j)]
            cell.set_facecolor('#4b6584')  # Màu xanh đậm
            cell.set_text_props(color='white')
        
        plt.title("Trạng thái thiết bị mạng", fontsize=14, pad=20)
        plt.tight_layout()
        
        return fig
    
    def create_link_quality_chart(self, results: Dict) -> plt.Figure:
        """
        Tạo biểu đồ chất lượng đường truyền.
        
        Args:
            results: Kết quả phân tích gói tin

        Returns:
            Biểu đồ chất lượng đường truyền
        """
        if not results or "link_quality" not in results or not results.get("link_quality"):
            # Tạo biểu đồ chất lượng đường truyền mẫu khi không có dữ liệu thực
            return self._create_sample_link_quality_chart()
        
        # Sử dụng dữ liệu thực về chất lượng đường truyền
        link_quality = results.get("link_quality")
        
        # Kiểm tra cấu trúc dữ liệu để tạo biểu đồ phù hợp
        if isinstance(link_quality, dict) and all(key in link_quality for key in ["latency", "packet_loss"]):
            # Tạo biểu đồ từ dữ liệu thực
            return self._create_link_quality_chart_from_data(link_quality)
        else:
            # Nếu dữ liệu không theo định dạng mong đợi, sử dụng mẫu
            return self._create_sample_link_quality_chart()
    
    def _create_sample_link_quality_chart(self) -> plt.Figure:
        """
        Tạo biểu đồ mẫu cho chất lượng đường truyền khi không có dữ liệu thực.
        
        Returns:
            Biểu đồ chất lượng đường truyền mẫu
        """
        # Tạo dữ liệu mẫu
        timestamps = ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10']
        
        links = {
            "Router-Core → Server-A": [15, 12, 35, 48, 52, 45, 20, 18, 16, 14],
            "Router-Core → Switch-1": [8, 9, 10, 12, 11, 9, 8, 7, 9, 8],
            "Switch-1 → Server-B": [12, 15, 18, 22, 20, 18, 16, 15, 14, 12]
        }
        
        packet_loss = {
            "Router-Core → Server-A": [0, 0, 3, 5, 7, 4, 1, 0, 0, 0],
            "Router-Core → Switch-1": [0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
            "Switch-1 → Server-B": [0, 1, 2, 2, 1, 1, 0, 0, 0, 0]
        }
        
        # Tạo biểu đồ
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8), gridspec_kw={'height_ratios': [2, 1]})
        
        # Vẽ biểu đồ độ trễ
        for link_name, latency_values in links.items():
            ax1.plot(timestamps, latency_values, marker='o', label=link_name)
        
        # Đánh dấu các điểm có vấn đề (độ trễ > 40ms)
        for link_name, latency_values in links.items():
            problem_points = [(t, l) for t, l in zip(timestamps, latency_values) if l > 40]
            if problem_points:
                x_points, y_points = zip(*problem_points)
                ax1.scatter(x_points, y_points, color='red', s=100, zorder=5, marker='X', label=f"{link_name} (Cao)")
        
        ax1.set_title("Độ trễ đường truyền (Latency)")
        ax1.set_ylabel("Độ trễ (ms)")
        ax1.set_ylim(bottom=0)
        ax1.grid(True, linestyle='--', alpha=0.7)
        
        # Thêm ngưỡng cảnh báo
        ax1.axhline(y=40, color='r', linestyle='--', alpha=0.5, label="Ngưỡng cảnh báo (40ms)")
        
        # Tạo legend
        handles, labels = ax1.get_legend_handles_labels()
        unique_handles = []
        unique_labels = []
        seen_labels = set()
        for handle, label in zip(handles, labels):
            if label not in seen_labels:
                seen_labels.add(label)
                unique_handles.append(handle)
                unique_labels.append(label)
        ax1.legend(unique_handles, unique_labels, loc='upper right', fontsize=8)
        
        # Vẽ biểu đồ mất gói
        bar_width = 0.25
        x = range(len(timestamps))
        
        for i, (link_name, loss_values) in enumerate(packet_loss.items()):
            pos = [j + i * bar_width for j in x]
            bars = ax2.bar(pos, loss_values, width=bar_width, label=link_name, alpha=0.7)
            
            # Đánh dấu cảnh báo cho các điểm có mất gói > 2%
            for j, val in enumerate(loss_values):
                if val > 2:
                    bars[j].set_color('red')
        
        ax2.set_title("Tỷ lệ mất gói (Packet Loss)")
        ax2.set_xlabel("Thời gian")
        ax2.set_ylabel("Số gói mất (%)")
        ax2.set_ylim(bottom=0)
        
        # Đặt ticks
        ax2.set_xticks([j + bar_width for j in x])
        ax2.set_xticklabels(timestamps)
        
        ax2.grid(True, linestyle='--', alpha=0.7)
        
        # Thêm ngưỡng cảnh báo
        ax2.axhline(y=2, color='r', linestyle='--', alpha=0.5, label="Ngưỡng cảnh báo (2%)")
        
        ax2.legend(loc='upper right', fontsize=8)
        
        plt.tight_layout()
        return fig
    
    def _create_link_quality_chart_from_data(self, link_quality: Dict) -> plt.Figure:
        """
        Tạo biểu đồ chất lượng đường truyền từ dữ liệu thực.
        
        Args:
            link_quality: Dict chứa dữ liệu về độ trễ và mất gói

        Returns:
            Biểu đồ chất lượng đường truyền
        """
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8), gridspec_kw={'height_ratios': [2, 1]})
        
        # Trích xuất dữ liệu
        latency_data = link_quality.get("latency", {})
        packet_loss_data = link_quality.get("packet_loss", {})
        
        # Xử lý dữ liệu độ trễ
        timestamps = latency_data.get("timestamps", [])
        links = latency_data.get("links", {})
        
        # Vẽ biểu đồ độ trễ
        for link_name, latency_values in links.items():
            ax1.plot(timestamps, latency_values, marker='o', label=link_name)
        
        # Đánh dấu các điểm có vấn đề (độ trễ > 40ms)
        for link_name, latency_values in links.items():
            problem_points = [(t, l) for t, l in zip(timestamps, latency_values) if l > 40]
            if problem_points:
                x_points, y_points = zip(*problem_points)
                ax1.scatter(x_points, y_points, color='red', s=100, zorder=5, marker='X', label=f"{link_name} (Cao)")
        
        ax1.set_title("Độ trễ đường truyền (Latency)")
        ax1.set_ylabel("Độ trễ (ms)")
        ax1.set_ylim(bottom=0)
        ax1.grid(True, linestyle='--', alpha=0.7)
        
        # Thêm ngưỡng cảnh báo
        ax1.axhline(y=40, color='r', linestyle='--', alpha=0.5, label="Ngưỡng cảnh báo (40ms)")
        
        # Tạo legend
        handles, labels = ax1.get_legend_handles_labels()
        unique_handles = []
        unique_labels = []
        seen_labels = set()
        for handle, label in zip(handles, labels):
            if label not in seen_labels:
                seen_labels.add(label)
                unique_handles.append(handle)
                unique_labels.append(label)
        ax1.legend(unique_handles, unique_labels, loc='upper right', fontsize=8)
        
        # Xử lý dữ liệu mất gói
        loss_timestamps = packet_loss_data.get("timestamps", [])
        loss_data = packet_loss_data.get("links", {})
        
        # Vẽ biểu đồ mất gói
        bar_width = 0.2
        positions = []
        for i, (link_name, loss_values) in enumerate(loss_data.items()):
            pos = [t + i * bar_width for t in range(len(loss_timestamps))]
            positions.append(pos)
            bars = ax2.bar(pos, loss_values, width=bar_width, label=link_name, alpha=0.7)
            
            # Đánh dấu cảnh báo cho các điểm có mất gói > 2%
            for j, val in enumerate(loss_values):
                if val > 2:
                    bars[j].set_color('red')
        
        ax2.set_title("Tỷ lệ mất gói (Packet Loss)")
        ax2.set_xlabel("Thời gian")
        ax2.set_ylabel("Số gói mất (%)")
        ax2.set_ylim(bottom=0)
        
        # Đặt ticks
        if positions:
            tick_positions = [positions[0][i] + (len(loss_data) * bar_width) / 2 for i in range(len(loss_timestamps))]
            ax2.set_xticks(tick_positions)
            ax2.set_xticklabels(loss_timestamps)
        
        ax2.grid(True, linestyle='--', alpha=0.7)
        
        # Thêm ngưỡng cảnh báo
        ax2.axhline(y=2, color='r', linestyle='--', alpha=0.5, label="Ngưỡng cảnh báo (2%)")
        ax2.legend(loc='upper right', fontsize=8)
        
        plt.tight_layout()
        return fig
    
    def create_arp_attack_chart(self, results: Dict) -> plt.Figure:
        """
        Tạo biểu đồ phát hiện dấu hiệu tấn công ARP.
        
        Args:
            results: Kết quả phân tích gói tin

        Returns:
            Biểu đồ cảnh báo ARP
        """
        if not results or "arp_analysis" not in results or not results.get("arp_analysis"):
            # Tạo biểu đồ cảnh báo ARP mẫu khi không có dữ liệu thực
            return self._create_sample_arp_attack_chart()
        
        # Sử dụng dữ liệu thực về ARP
        arp_analysis = results.get("arp_analysis")
        
        # Kiểm tra cấu trúc dữ liệu
        if isinstance(arp_analysis, dict) and "alerts" in arp_analysis and "traffic" in arp_analysis:
            # Tạo biểu đồ từ dữ liệu thực
            return self._create_arp_attack_chart_from_data(arp_analysis)
        else:
            # Sử dụng biểu đồ mẫu nếu cấu trúc dữ liệu không phù hợp
            return self._create_sample_arp_attack_chart()
            
    def _create_sample_arp_attack_chart(self) -> plt.Figure:
        """
        Tạo biểu đồ mẫu phát hiện tấn công ARP khi không có dữ liệu thực.
        
        Returns:
            Biểu đồ cảnh báo ARP mẫu
        """
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10), gridspec_kw={'height_ratios': [1, 2]})
        
        # Tạo dữ liệu mẫu cho cảnh báo
        alerts = [
            {
                "time": "11:25:30",
                "src_ip": "192.168.1.105",
                "src_mac": "00:0c:29:1a:2b:3c",
                "claimed_ip": "192.168.1.1",
                "real_mac": "00:1a:2b:3c:4d:5e",
                "alert_type": "ARP Spoofing",
                "severity": 9
            },
            {
                "time": "11:26:15",
                "src_ip": "192.168.1.110",
                "src_mac": "00:0c:29:5e:6f:7g",
                "claimed_ip": "192.168.1.1",
                "real_mac": "00:1a:2b:3c:4d:5e",
                "alert_type": "ARP Spoofing",
                "severity": 8
            }
        ]
        
        # Tạo dữ liệu mẫu cho lưu lượng
        timestamps = ['11:20', '11:21', '11:22', '11:23', '11:24', '11:25', '11:26', '11:27', '11:28', '11:29']
        arp_requests = [5, 8, 12, 15, 45, 65, 40, 20, 10, 5]
        arp_replies = [3, 5, 10, 12, 35, 55, 30, 15, 8, 3]
        arp_gratuitous = [0, 0, 0, 1, 5, 8, 2, 0, 0, 0]
        
        # Vẽ bảng cảnh báo
        ax1.axis('tight')
        ax1.axis('off')
        
        # Chuẩn bị dữ liệu cho bảng
        headers = ["Thời gian", "IP nguồn", "MAC nguồn", "IP được xác nhận", "MAC thực", "Loại cảnh báo", "Mức độ"]
        data = []
        colors = []
        
        for alert in alerts:
            # Định dạng dữ liệu
            claimed_ip = alert.get("claimed_ip", "N/A")
            real_mac = alert.get("real_mac", "N/A")
            severity = alert.get("severity", 0)
            
            # Chuyển mức độ thành biểu tượng
            if severity >= 8:
                severity_icon = "🔴 " + str(severity)
            elif severity >= 5:
                severity_icon = "🟠 " + str(severity)
            else:
                severity_icon = "🟡 " + str(severity)
            
            data.append([
                alert.get("time", ""),
                alert.get("src_ip", ""),
                alert.get("src_mac", ""),
                claimed_ip,
                real_mac,
                alert.get("alert_type", ""),
                severity_icon
            ])
            
            # Màu nền dựa trên mức độ nghiêm trọng
            if severity >= 8:
                colors.append("#ffcccc")  # Đỏ nhạt
            elif severity >= 5:
                colors.append("#ffe0cc")  # Cam nhạt
            else:
                colors.append("#ffffcc")  # Vàng nhạt
        
        # Tạo bảng
        table = ax1.table(
            cellText=data,
            colLabels=headers,
            loc='center',
            cellLoc='center'
        )
        
        # Định dạng bảng
        table.auto_set_font_size(False)
        table.set_fontsize(9)
        table.scale(1, 1.5)
        
        # Đặt màu nền cho các hàng dữ liệu
        for i in range(len(data)):
            for j in range(len(headers)):
                cell = table[(i+1, j)]  # +1 vì hàng 0 là header
                cell.set_facecolor(colors[i])
        
        # Định dạng header
        for j, header in enumerate(headers):
            cell = table[(0, j)]
            cell.set_facecolor('#4b6584')  # Màu xanh đậm
            cell.set_text_props(color='white')
        
        ax1.set_title("Cảnh báo tấn công ARP", fontsize=14, pad=20)
        
        # Vẽ biểu đồ số lượng gói ARP theo thời gian
        bar_width = 0.25
        x = range(len(timestamps))
        
        ax2.bar([i - bar_width for i in x], arp_requests, bar_width, label='ARP Requests', color='#3498db')
        ax2.bar([i for i in x], arp_replies, bar_width, label='ARP Replies', color='#2ecc71')
        ax2.bar([i + bar_width for i in x], arp_gratuitous, bar_width, label='Gratuitous ARP', color='#e74c3c')
        
        # Đánh dấu vùng bất thường
        ax2.axvspan(4, 6, alpha=0.2, color='red', label='Vùng bất thường')
        
        ax2.set_xlabel('Thời gian')
        ax2.set_ylabel('Số lượng gói tin')
        ax2.set_title('Phân tích lưu lượng ARP theo thời gian')
        ax2.set_xticks(x)
        ax2.set_xticklabels(timestamps)
        ax2.legend()
        ax2.grid(axis='y', linestyle='--', alpha=0.7)
        
        plt.tight_layout()
        return fig
    
    def _create_arp_attack_chart_from_data(self, arp_analysis: Dict) -> plt.Figure:
        """
        Tạo biểu đồ phát hiện tấn công ARP từ dữ liệu thực.
        
        Args:
            arp_analysis: Dict chứa dữ liệu phân tích ARP

        Returns:
            Biểu đồ cảnh báo ARP
        """
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10), gridspec_kw={'height_ratios': [1, 2]})
        
        # Trích xuất dữ liệu cảnh báo
        arp_alerts = arp_analysis.get("alerts", [])
        
        # Trích xuất dữ liệu lưu lượng
        traffic_data = arp_analysis.get("traffic", {})
        timestamps = traffic_data.get("timestamps", [])
        arp_requests = traffic_data.get("requests", [])
        arp_replies = traffic_data.get("replies", [])
        arp_gratuitous = traffic_data.get("gratuitous", [])
        
        # Vẽ bảng cảnh báo ARP
        ax1.axis('tight')
        ax1.axis('off')
        
        # Chuẩn bị dữ liệu cho bảng
        headers = ["Thời gian", "IP nguồn", "MAC nguồn", "IP được xác nhận", "MAC thực", "Loại cảnh báo", "Mức độ"]
        data = []
        colors = []
        
        for alert in arp_alerts:
            # Định dạng dữ liệu
            claimed_ip = alert.get("claimed_ip", "N/A")
            real_mac = alert.get("real_mac", "N/A")
            severity = alert.get("severity", 0)
            
            # Chuyển mức độ thành biểu tượng
            if severity >= 8:
                severity_icon = "🔴 " + str(severity)
            elif severity >= 5:
                severity_icon = "🟠 " + str(severity)
            else:
                severity_icon = "🟡 " + str(severity)
            
            data.append([
                alert.get("time", ""),
                alert.get("src_ip", ""),
                alert.get("src_mac", ""),
                claimed_ip,
                real_mac,
                alert.get("alert_type", ""),
                severity_icon
            ])
            
            # Màu nền dựa trên mức độ nghiêm trọng
            if severity >= 8:
                colors.append("#ffcccc")  # Đỏ nhạt
            elif severity >= 5:
                colors.append("#ffe0cc")  # Cam nhạt
            else:
                colors.append("#ffffcc")  # Vàng nhạt
        
        # Tạo bảng nếu có dữ liệu
        if data:
            table = ax1.table(
                cellText=data,
                colLabels=headers,
                loc='center',
                cellLoc='center'
            )
            
            # Định dạng bảng
            table.auto_set_font_size(False)
            table.set_fontsize(9)
            table.scale(1, 1.5)
            
            # Đặt màu nền cho các hàng dữ liệu
            for i in range(len(data)):
                for j in range(len(headers)):
                    cell = table[(i+1, j)]  # +1 vì hàng 0 là header
                    cell.set_facecolor(colors[i])
            
            # Định dạng header
            for j, header in enumerate(headers):
                cell = table[(0, j)]
                cell.set_facecolor('#4b6584')  # Màu xanh đậm
                cell.set_text_props(color='white')
        else:
            ax1.text(0.5, 0.5, "Không có cảnh báo ARP", ha='center', va='center', fontsize=14)
        
        ax1.set_title("Cảnh báo tấn công ARP", fontsize=14, pad=20)
        
        # Vẽ biểu đồ số lượng gói ARP theo thời gian
        if timestamps and (arp_requests or arp_replies or arp_gratuitous):
            bar_width = 0.25
            x = range(len(timestamps))
            
            if arp_requests:
                ax2.bar([i - bar_width for i in x], arp_requests, bar_width, label='ARP Requests', color='#3498db')
            if arp_replies:
                ax2.bar([i for i in x], arp_replies, bar_width, label='ARP Replies', color='#2ecc71')
            if arp_gratuitous:
                ax2.bar([i + bar_width for i in x], arp_gratuitous, bar_width, label='Gratuitous ARP', color='#e74c3c')
            
            # Đánh dấu vùng bất thường nếu có
            anomaly_start = traffic_data.get("anomaly_start", -1)
            anomaly_end = traffic_data.get("anomaly_end", -1)
            if anomaly_start >= 0 and anomaly_end >= 0 and anomaly_start < len(timestamps) and anomaly_end < len(timestamps):
                ax2.axvspan(anomaly_start, anomaly_end, alpha=0.2, color='red', label='Vùng bất thường')
            
            ax2.set_xlabel('Thời gian')
            ax2.set_ylabel('Số lượng gói tin')
            ax2.set_title('Phân tích lưu lượng ARP theo thời gian')
            ax2.set_xticks(x)
            ax2.set_xticklabels(timestamps)
            ax2.legend()
            ax2.grid(axis='y', linestyle='--', alpha=0.7)
        else:
            ax2.text(0.5, 0.5, "Không có dữ liệu lưu lượng ARP", ha='center', va='center', fontsize=14)
            ax2.set_title('Phân tích lưu lượng ARP theo thời gian')
            ax2.axis('off')
        
        plt.tight_layout()
        return fig
    
    def create_icmp_anomaly_chart(self, results: Dict) -> plt.Figure:
        """
        Tạo biểu đồ phát hiện dấu hiệu bất thường ICMP.
        
        Args:
            results: Kết quả phân tích gói tin

        Returns:
            Biểu đồ phát hiện bất thường ICMP
        """
        if not results or "icmp_analysis" not in results or not results.get("icmp_analysis"):
            # Tạo biểu đồ phát hiện bất thường ICMP mẫu khi không có dữ liệu thực
            return self._create_sample_icmp_anomaly_chart()
        
        # Sử dụng dữ liệu thực về ICMP
        icmp_analysis = results.get("icmp_analysis")
        
        # Kiểm tra cấu trúc dữ liệu
        if isinstance(icmp_analysis, dict) and all(key in icmp_analysis for key in ["alerts", "traffic"]):
            # Tạo biểu đồ từ dữ liệu thực
            return self._create_icmp_anomaly_chart_from_data(icmp_analysis)
        else:
            # Sử dụng biểu đồ mẫu nếu cấu trúc dữ liệu không phù hợp
            return self._create_sample_icmp_anomaly_chart()
    
    def _create_sample_icmp_anomaly_chart(self) -> plt.Figure:
        """
        Tạo biểu đồ mẫu phát hiện bất thường ICMP khi không có dữ liệu thực.
        
        Returns:
            Biểu đồ phát hiện bất thường ICMP mẫu
        """
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10), gridspec_kw={'height_ratios': [1, 2]})
        
        # Tạo dữ liệu mẫu cho cảnh báo
        alerts = [
            {
                "time": "10:15:30",
                "src_ip": "10.0.0.25",
                "dst_ip": "192.168.1.1",
                "icmp_type": 8,
                "icmp_code": 0,
                "payload_size": 1500,
                "alert_type": "ICMP Tunneling Suspected",
                "severity": 7
            },
            {
                "time": "10:20:15",
                "src_ip": "10.0.0.15",
                "dst_ip": "192.168.1.0/24",
                "icmp_type": 8,
                "icmp_code": 0,
                "payload_size": 64,
                "alert_type": "ICMP Echo Request Flood",
                "severity": 8
            }
        ]
        
        # Tạo dữ liệu mẫu cho lưu lượng
        timestamps = ['10:10', '10:12', '10:14', '10:16', '10:18', '10:20', '10:22', '10:24', '10:26', '10:28']
        echo_requests = [10, 12, 15, 20, 35, 85, 45, 25, 15, 12]
        echo_replies = [8, 10, 12, 18, 25, 40, 30, 20, 12, 10]
        dest_unreachable = [0, 1, 0, 2, 5, 10, 3, 1, 0, 0]
        time_exceeded = [0, 0, 0, 0, 1, 3, 1, 0, 0, 0]
        
        # Vẽ bảng cảnh báo
        ax1.axis('tight')
        ax1.axis('off')
        
        # Chuẩn bị dữ liệu cho bảng
        headers = ["Thời gian", "IP nguồn", "IP đích", "Loại ICMP", "Kích thước", "Loại cảnh báo", "Mức độ"]
        data = []
        colors = []
        
        for alert in alerts:
            # Định dạng dữ liệu
            icmp_type = f"Type {alert.get('icmp_type', 0)}"
            if alert.get('icmp_code', 0) > 0:
                icmp_type += f"/Code {alert.get('icmp_code', 0)}"
            
            payload_size = f"{alert.get('payload_size', 0)} bytes"
            severity = alert.get("severity", 0)
            
            # Chuyển mức độ thành biểu tượng
            if severity >= 8:
                severity_icon = "🔴 " + str(severity)
            elif severity >= 5:
                severity_icon = "🟠 " + str(severity)
            else:
                severity_icon = "🟡 " + str(severity)
            
            data.append([
                alert.get("time", ""),
                alert.get("src_ip", ""),
                alert.get("dst_ip", ""),
                icmp_type,
                payload_size,
                alert.get("alert_type", ""),
                severity_icon
            ])
            
            # Màu nền dựa trên mức độ nghiêm trọng
            if severity >= 8:
                colors.append("#ffcccc")  # Đỏ nhạt
            elif severity >= 5:
                colors.append("#ffe0cc")  # Cam nhạt
            else:
                colors.append("#ffffcc")  # Vàng nhạt
        
        # Tạo bảng
        table = ax1.table(
            cellText=data,
            colLabels=headers,
            loc='center',
            cellLoc='center'
        )
        
        # Định dạng bảng
        table.auto_set_font_size(False)
        table.set_fontsize(9)
        table.scale(1, 1.5)
        
        # Đặt màu nền cho các hàng dữ liệu
        for i in range(len(data)):
            for j in range(len(headers)):
                cell = table[(i+1, j)]  # +1 vì hàng 0 là header
                cell.set_facecolor(colors[i])
        
        # Định dạng header
        for j, header in enumerate(headers):
            cell = table[(0, j)]
            cell.set_facecolor('#4b6584')  # Màu xanh đậm
            cell.set_text_props(color='white')
        
        ax1.set_title("Cảnh báo bất thường ICMP", fontsize=14, pad=20)
        
        # Vẽ biểu đồ số lượng gói ICMP theo thời gian
        x = range(len(timestamps))
        
        ax2.plot(x, echo_requests, marker='o', linewidth=2, label='Echo Requests', color='#3498db')
        ax2.plot(x, echo_replies, marker='s', linewidth=2, label='Echo Replies', color='#2ecc71')
        ax2.plot(x, dest_unreachable, marker='^', linewidth=2, label='Dest Unreachable', color='#e74c3c')
        ax2.plot(x, time_exceeded, marker='D', linewidth=2, label='Time Exceeded', color='#f39c12')
        
        # Đánh dấu vùng bất thường
        ax2.axvspan(4, 6, alpha=0.2, color='red', label='Vùng bất thường')
        
        # Đánh dấu đỉnh đột biến
        peak_index = echo_requests.index(max(echo_requests))
        ax2.annotate('Peak Traffic', 
                   xy=(peak_index, echo_requests[peak_index]),
                   xytext=(peak_index-1, echo_requests[peak_index]+15),
                   arrowprops=dict(arrowstyle='->', lw=1.5, color='red'),
                   fontsize=10, color='red')
        
        ax2.set_xlabel('Thời gian')
        ax2.set_ylabel('Số lượng gói tin')
        ax2.set_title('Phân tích lưu lượng ICMP theo thời gian')
        ax2.set_xticks(x)
        ax2.set_xticklabels(timestamps)
        ax2.legend()
        ax2.grid(True, linestyle='--', alpha=0.7)
        
        plt.tight_layout()
        return fig
    
    def _create_icmp_anomaly_chart_from_data(self, icmp_analysis: Dict) -> plt.Figure:
        """
        Tạo biểu đồ phát hiện bất thường ICMP từ dữ liệu thực.
        
        Args:
            icmp_analysis: Dict chứa dữ liệu phân tích ICMP

        Returns:
            Biểu đồ phát hiện bất thường ICMP
        """
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10), gridspec_kw={'height_ratios': [1, 2]})
        
        # Trích xuất dữ liệu cảnh báo
        icmp_alerts = icmp_analysis.get("alerts", [])
        
        # Trích xuất dữ liệu lưu lượng
        traffic_data = icmp_analysis.get("traffic", {})
        timestamps = traffic_data.get("timestamps", [])
        echo_requests = traffic_data.get("echo_requests", [])
        echo_replies = traffic_data.get("echo_replies", [])
        dest_unreachable = traffic_data.get("dest_unreachable", [])
        time_exceeded = traffic_data.get("time_exceeded", [])
        other_types = traffic_data.get("other_types", [])
        
        # Vẽ bảng cảnh báo ICMP
        ax1.axis('tight')
        ax1.axis('off')
        
        # Chuẩn bị dữ liệu cho bảng
        headers = ["Thời gian", "IP nguồn", "IP đích", "Loại ICMP", "Kích thước", "Loại cảnh báo", "Mức độ"]
        data = []
        colors = []
        
        for alert in icmp_alerts:
            # Định dạng dữ liệu
            icmp_type = "N/A"
            if isinstance(alert.get("icmp_type"), int):
                icmp_type = f"Type {alert.get('icmp_type')}"
                if alert.get('icmp_code') is not None:
                    icmp_type += f"/Code {alert.get('icmp_code')}"
            elif alert.get("icmp_type") == "Multiple":
                icmp_type = "Multiple"
            
            payload_size = f"{alert.get('payload_size', 0)} bytes"
            severity = alert.get("severity", 0)
            
            # Chuyển mức độ thành biểu tượng
            if severity >= 8:
                severity_icon = "🔴 " + str(severity)
            elif severity >= 5:
                severity_icon = "🟠 " + str(severity)
            else:
                severity_icon = "🟡 " + str(severity)
            
            data.append([
                alert.get("time", ""),
                alert.get("src_ip", ""),
                alert.get("dst_ip", ""),
                icmp_type,
                payload_size,
                alert.get("alert_type", ""),
                severity_icon
            ])
            
            # Màu nền dựa trên mức độ nghiêm trọng
            if severity >= 8:
                colors.append("#ffcccc")  # Đỏ nhạt
            elif severity >= 5:
                colors.append("#ffe0cc")  # Cam nhạt
            else:
                colors.append("#ffffcc")  # Vàng nhạt
        
        # Tạo bảng nếu có dữ liệu
        if data:
            table = ax1.table(
                cellText=data,
                colLabels=headers,
                loc='center',
                cellLoc='center'
            )
            
            # Định dạng bảng
            table.auto_set_font_size(False)
            table.set_fontsize(9)
            table.scale(1, 1.5)
            
            # Đặt màu nền cho các hàng dữ liệu
            for i in range(len(data)):
                for j in range(len(headers)):
                    cell = table[(i+1, j)]  # +1 vì hàng 0 là header
                    cell.set_facecolor(colors[i])
            
            # Định dạng header
            for j, header in enumerate(headers):
                cell = table[(0, j)]
                cell.set_facecolor('#4b6584')  # Màu xanh đậm
                cell.set_text_props(color='white')
        else:
            ax1.text(0.5, 0.5, "Không có cảnh báo ICMP", ha='center', va='center', fontsize=14)
        
        ax1.set_title("Cảnh báo bất thường ICMP", fontsize=14, pad=20)
        
        # Vẽ biểu đồ số lượng gói ICMP theo thời gian
        if timestamps and any([echo_requests, echo_replies, dest_unreachable, time_exceeded, other_types]):
            x = range(len(timestamps))
            
            if echo_requests:
                ax2.plot(x, echo_requests, marker='o', linewidth=2, label='Echo Requests', color='#3498db')
            if echo_replies:
                ax2.plot(x, echo_replies, marker='s', linewidth=2, label='Echo Replies', color='#2ecc71')
            if dest_unreachable:
                ax2.plot(x, dest_unreachable, marker='^', linewidth=2, label='Dest Unreachable', color='#e74c3c')
            if time_exceeded:
                ax2.plot(x, time_exceeded, marker='D', linewidth=2, label='Time Exceeded', color='#f39c12')
            if other_types:
                ax2.plot(x, other_types, marker='X', linewidth=2, label='Other Types', color='#8e44ad')
            
            # Đánh dấu vùng bất thường nếu có
            anomaly_start = traffic_data.get("anomaly_start", -1)
            anomaly_end = traffic_data.get("anomaly_end", -1)
            if anomaly_start >= 0 and anomaly_end >= 0 and anomaly_start < len(timestamps) and anomaly_end < len(timestamps):
                ax2.axvspan(anomaly_start, anomaly_end, alpha=0.2, color='red', label='Vùng bất thường')
            
            # Đánh dấu đỉnh đột biến nếu có
            if echo_requests:
                peak_value = max(echo_requests)
                if peak_value > 50:  # Ngưỡng đỉnh đột biến
                    peak_index = echo_requests.index(peak_value)
                    ax2.annotate('Peak Traffic', 
                               xy=(peak_index, peak_value),
                               xytext=(peak_index-1, peak_value+15),
                               arrowprops=dict(arrowstyle='->', lw=1.5, color='red'),
                               fontsize=10, color='red')
            
            ax2.set_xlabel('Thời gian')
            ax2.set_ylabel('Số lượng gói tin')
            ax2.set_title('Phân tích lưu lượng ICMP theo thời gian')
            ax2.set_xticks(x)
            ax2.set_xticklabels(timestamps)
            ax2.legend()
            ax2.grid(True, linestyle='--', alpha=0.7)
        else:
            ax2.text(0.5, 0.5, "Không có dữ liệu lưu lượng ICMP", ha='center', va='center', fontsize=14)
            ax2.set_title('Phân tích lưu lượng ICMP theo thời gian')
            ax2.axis('off')
        
        plt.tight_layout()
        return fig
    
    def create_dhcp_attack_chart(self, results: Dict) -> plt.Figure:
        """
        Tạo biểu đồ phát hiện dấu hiệu tấn công DHCP.
        
        Args:
            results: Kết quả phân tích gói tin

        Returns:
            Biểu đồ cảnh báo DHCP
        """
        if not results or "dhcp_analysis" not in results or not results.get("dhcp_analysis"):
            # Tạo biểu đồ cảnh báo DHCP mẫu khi không có dữ liệu thực
            return self._create_sample_dhcp_attack_chart()
        
        # Sử dụng dữ liệu thực về DHCP
        dhcp_analysis = results.get("dhcp_analysis")
        
        # Kiểm tra cấu trúc dữ liệu
        if isinstance(dhcp_analysis, dict) and "alerts" in dhcp_analysis and "traffic" in dhcp_analysis:
            # Tạo biểu đồ từ dữ liệu thực
            return self._create_dhcp_attack_chart_from_data(dhcp_analysis)
        else:
            # Sử dụng biểu đồ mẫu nếu cấu trúc dữ liệu không phù hợp
            return self._create_sample_dhcp_attack_chart()
    
    def _create_sample_dhcp_attack_chart(self) -> plt.Figure:
        """
        Tạo biểu đồ mẫu phát hiện tấn công DHCP khi không có dữ liệu thực.
        
        Returns:
            Biểu đồ cảnh báo DHCP mẫu
        """
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10), gridspec_kw={'height_ratios': [1, 2]})
        
        # Tạo dữ liệu mẫu cho cảnh báo
        alerts = [
            {
                "time": "09:45:30",
                "src_ip": "10.0.0.25",
                "src_mac": "00:1c:23:4d:5e:6f",
                "server_ip": "192.168.1.5",
                "server_mac": "00:aa:bb:cc:dd:ee",
                "alert_type": "DHCP Starvation",
                "severity": 7
            },
            {
                "time": "09:50:15",
                "src_ip": "10.0.0.15",
                "src_mac": "00:2d:3e:4f:5g:6h",
                "server_ip": "192.168.1.1, 192.168.1.250",
                "server_mac": "Multiple",
                "alert_type": "Multiple DHCP Servers",
                "severity": 6
            }
        ]
        
        # Tạo dữ liệu mẫu cho lưu lượng
        timestamps = ['09:40', '09:42', '09:44', '09:46', '09:48', '09:50', '09:52', '09:54', '09:56', '09:58']
        dhcp_discover = [5, 8, 12, 55, 85, 45, 25, 15, 10, 5]
        dhcp_offer = [3, 6, 10, 45, 75, 40, 20, 12, 8, 3]
        dhcp_request = [2, 5, 8, 35, 65, 30, 18, 10, 5, 2]
        dhcp_ack = [2, 5, 8, 35, 60, 28, 15, 10, 5, 2]
        
        # Vẽ bảng cảnh báo
        ax1.axis('tight')
        ax1.axis('off')
        
        # Chuẩn bị dữ liệu cho bảng
        headers = ["Thời gian", "IP nguồn", "MAC nguồn", "IP server", "MAC server", "Loại cảnh báo", "Mức độ"]
        data = []
        colors = []
        
        for alert in alerts:
            # Định dạng dữ liệu
            severity = alert.get("severity", 0)
            
            # Chuyển mức độ thành biểu tượng
            if severity >= 8:
                severity_icon = "🔴 " + str(severity)
            elif severity >= 5:
                severity_icon = "🟠 " + str(severity)
            else:
                severity_icon = "🟡 " + str(severity)
            
            data.append([
                alert.get("time", ""),
                alert.get("src_ip", ""),
                alert.get("src_mac", ""),
                alert.get("server_ip", ""),
                alert.get("server_mac", ""),
                alert.get("alert_type", ""),
                severity_icon
            ])
            
            # Màu nền dựa trên mức độ nghiêm trọng
            if severity >= 8:
                colors.append("#ffcccc")  # Đỏ nhạt
            elif severity >= 5:
                colors.append("#ffe0cc")  # Cam nhạt
            else:
                colors.append("#ffffcc")  # Vàng nhạt
        
        # Tạo bảng
        table = ax1.table(
            cellText=data,
            colLabels=headers,
            loc='center',
            cellLoc='center'
        )
        
        # Định dạng bảng
        table.auto_set_font_size(False)
        table.set_fontsize(9)
        table.scale(1, 1.5)
        
        # Đặt màu nền cho các hàng dữ liệu
        for i in range(len(data)):
            for j in range(len(headers)):
                cell = table[(i+1, j)]  # +1 vì hàng 0 là header
                cell.set_facecolor(colors[i])
        
        # Định dạng header
        for j, header in enumerate(headers):
            cell = table[(0, j)]
            cell.set_facecolor('#4b6584')  # Màu xanh đậm
            cell.set_text_props(color='white')
        
        ax1.set_title("Cảnh báo tấn công DHCP", fontsize=14, pad=20)
        
        # Vẽ biểu đồ số lượng gói DHCP theo thời gian
        x = range(len(timestamps))
        
        width = 0.2
        ax2.bar([i - width*1.5 for i in x], dhcp_discover, width, label='DHCP Discover', color='#3498db')
        ax2.bar([i - width*0.5 for i in x], dhcp_offer, width, label='DHCP Offer', color='#2ecc71')
        ax2.bar([i + width*0.5 for i in x], dhcp_request, width, label='DHCP Request', color='#e74c3c')
        ax2.bar([i + width*1.5 for i in x], dhcp_ack, width, label='DHCP ACK', color='#f39c12')
        
        # Đánh dấu vùng bất thường
        ax2.axvspan(3, 5, alpha=0.2, color='red', label='Vùng bất thường')
        
        ax2.set_xlabel('Thời gian')
        ax2.set_ylabel('Số lượng gói tin')
        ax2.set_title('Phân tích lưu lượng DHCP theo thời gian')
        ax2.set_xticks(x)
        ax2.set_xticklabels(timestamps)
        ax2.legend()
        ax2.grid(axis='y', linestyle='--', alpha=0.7)
        
        plt.tight_layout()
        return fig
    
    def _create_dhcp_attack_chart_from_data(self, dhcp_analysis: Dict) -> plt.Figure:
        """
        Tạo biểu đồ phát hiện tấn công DHCP từ dữ liệu thực.
        
        Args:
            dhcp_analysis: Dict chứa dữ liệu phân tích DHCP

        Returns:
            Biểu đồ cảnh báo DHCP
        """
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10), gridspec_kw={'height_ratios': [1, 2]})
        
        # Trích xuất dữ liệu cảnh báo
        dhcp_alerts = dhcp_analysis.get("alerts", [])
        
        # Trích xuất dữ liệu lưu lượng
        traffic_data = dhcp_analysis.get("traffic", {})
        timestamps = traffic_data.get("timestamps", [])
        dhcp_discover = traffic_data.get("discover", [])
        dhcp_offer = traffic_data.get("offer", [])
        dhcp_request = traffic_data.get("request", [])
        dhcp_ack = traffic_data.get("ack", [])
        
        # Vẽ bảng cảnh báo DHCP
        ax1.axis('tight')
        ax1.axis('off')
        
        # Chuẩn bị dữ liệu cho bảng
        headers = ["Thời gian", "IP nguồn", "MAC nguồn", "IP server", "MAC server", "Loại cảnh báo", "Mức độ"]
        data = []
        colors = []
        
        for alert in dhcp_alerts:
            # Định dạng dữ liệu
            severity = alert.get("severity", 0)
            
            # Chuyển mức độ thành biểu tượng
            if severity >= 8:
                severity_icon = "🔴 " + str(severity)
            elif severity >= 5:
                severity_icon = "🟠 " + str(severity)
            else:
                severity_icon = "🟡 " + str(severity)
            
            data.append([
                alert.get("time", ""),
                alert.get("src_ip", ""),
                alert.get("src_mac", ""),
                alert.get("server_ip", ""),
                alert.get("server_mac", ""),
                alert.get("alert_type", ""),
                severity_icon
            ])
            
            # Màu nền dựa trên mức độ nghiêm trọng
            if severity >= 8:
                colors.append("#ffcccc")  # Đỏ nhạt
            elif severity >= 5:
                colors.append("#ffe0cc")  # Cam nhạt
            else:
                colors.append("#ffffcc")  # Vàng nhạt
        
        # Tạo bảng nếu có dữ liệu
        if data:
            table = ax1.table(
                cellText=data,
                colLabels=headers,
                loc='center',
                cellLoc='center'
            )
            
            # Định dạng bảng
            table.auto_set_font_size(False)
            table.set_fontsize(9)
            table.scale(1, 1.5)
            
            # Đặt màu nền cho các hàng dữ liệu
            for i in range(len(data)):
                for j in range(len(headers)):
                    cell = table[(i+1, j)]  # +1 vì hàng 0 là header
                    cell.set_facecolor(colors[i])
            
            # Định dạng header
            for j, header in enumerate(headers):
                cell = table[(0, j)]
                cell.set_facecolor('#4b6584')  # Màu xanh đậm
                cell.set_text_props(color='white')
        else:
            ax1.text(0.5, 0.5, "Không có cảnh báo DHCP", ha='center', va='center', fontsize=14)
        
        ax1.set_title("Cảnh báo tấn công DHCP", fontsize=14, pad=20)
        
        # Vẽ biểu đồ số lượng gói DHCP theo thời gian
        if timestamps and any([dhcp_discover, dhcp_offer, dhcp_request, dhcp_ack]):
            x = range(len(timestamps))
            
            width = 0.2
            if dhcp_discover:
                ax2.bar([i - width*1.5 for i in x], dhcp_discover, width, label='DHCP Discover', color='#3498db')
            if dhcp_offer:
                ax2.bar([i - width*0.5 for i in x], dhcp_offer, width, label='DHCP Offer', color='#2ecc71')
            if dhcp_request:
                ax2.bar([i + width*0.5 for i in x], dhcp_request, width, label='DHCP Request', color='#e74c3c')
            if dhcp_ack:
                ax2.bar([i + width*1.5 for i in x], dhcp_ack, width, label='DHCP ACK', color='#f39c12')
            
            # Đánh dấu vùng bất thường nếu có
            anomaly_start = traffic_data.get("anomaly_start", -1)
            anomaly_end = traffic_data.get("anomaly_end", -1)
            if anomaly_start >= 0 and anomaly_end >= 0 and anomaly_start < len(timestamps) and anomaly_end < len(timestamps):
                ax2.axvspan(anomaly_start, anomaly_end, alpha=0.2, color='red', label='Vùng bất thường')
            
            ax2.set_xlabel('Thời gian')
            ax2.set_ylabel('Số lượng gói tin')
            ax2.set_title('Phân tích lưu lượng DHCP theo thời gian')
            ax2.set_xticks(x)
            ax2.set_xticklabels(timestamps)
            ax2.legend()
            ax2.grid(axis='y', linestyle='--', alpha=0.7)
        else:
            ax2.text(0.5, 0.5, "Không có dữ liệu lưu lượng DHCP", ha='center', va='center', fontsize=14)
            ax2.set_title('Phân tích lưu lượng DHCP theo thời gian')
            ax2.axis('off')
        
        plt.tight_layout()
        return fig
    
    def create_dns_attack_chart(self, results: Dict) -> plt.Figure:
        """
        Tạo biểu đồ phát hiện dấu hiệu tấn công DNS.
        
        Args:
            results: Kết quả phân tích gói tin

        Returns:
            Biểu đồ cảnh báo DNS
        """
        if not results or "dns_analysis" not in results or not results.get("dns_analysis"):
            # Tạo biểu đồ cảnh báo DNS mẫu khi không có dữ liệu thực
            return self._create_sample_dns_attack_chart()
        
        # Sử dụng dữ liệu thực về DNS
        dns_analysis = results.get("dns_analysis")
        
        # Kiểm tra cấu trúc dữ liệu
        if isinstance(dns_analysis, dict) and "alerts" in dns_analysis and "traffic" in dns_analysis:
            # Tạo biểu đồ từ dữ liệu thực
            return self._create_dns_attack_chart_from_data(dns_analysis)
        else:
            # Sử dụng biểu đồ mẫu nếu cấu trúc dữ liệu không phù hợp
            return self._create_sample_dns_attack_chart()
    
    def _create_sample_dns_attack_chart(self) -> plt.Figure:
        """
        Tạo biểu đồ mẫu phát hiện tấn công DNS khi không có dữ liệu thực.
        
        Returns:
            Biểu đồ cảnh báo DNS mẫu
        """
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10), gridspec_kw={'height_ratios': [1, 2]})
        
        # Tạo dữ liệu mẫu cho cảnh báo
        alerts = [
            {
                "time": "15:25:30",
                "src_ip": "10.0.0.25",
                "domain": "d7xve2kjdl20s.cloudfront.net",
                "alert_type": "DNS Tunneling Suspected",
                "severity": 8,
                "details": "Kích thước gói lớn, lên đến 800 bytes"
            },
            {
                "time": "15:35:15",
                "src_ip": "10.0.0.15",
                "domain": "ksdjfskjfksjdf98s7df8sd7f8.malicious.com",
                "alert_type": "Suspicious DNS Queries",
                "severity": 6,
                "details": "Tên miền bất thường, có thể là C&C hoặc tunneling"
            }
        ]
        
        # Tạo dữ liệu mẫu cho lưu lượng
        timestamps = ['15:20', '15:22', '15:24', '15:26', '15:28', '15:30', '15:32', '15:34', '15:36', '15:38']
        dns_queries = [15, 18, 25, 65, 85, 45, 25, 35, 15, 10]
        dns_responses = [12, 16, 22, 55, 80, 40, 22, 30, 12, 8]
        dns_nxdomain = [0, 1, 2, 5, 20, 15, 5, 8, 3, 1]
        
        # Vẽ bảng cảnh báo
        ax1.axis('tight')
        ax1.axis('off')
        
        # Chuẩn bị dữ liệu cho bảng
        headers = ["Thời gian", "IP nguồn", "Tên miền", "Loại cảnh báo", "Mức độ", "Chi tiết"]
        data = []
        colors = []
        
        for alert in alerts:
            # Định dạng dữ liệu
            severity = alert.get("severity", 0)
            
            # Chuyển mức độ thành biểu tượng
            if severity >= 8:
                severity_icon = "🔴 " + str(severity)
            elif severity >= 5:
                severity_icon = "🟠 " + str(severity)
            else:
                severity_icon = "🟡 " + str(severity)
            
            data.append([
                alert.get("time", ""),
                alert.get("src_ip", ""),
                alert.get("domain", ""),
                alert.get("alert_type", ""),
                severity_icon,
                alert.get("details", "")
            ])
            
            # Màu nền dựa trên mức độ nghiêm trọng
            if severity >= 8:
                colors.append("#ffcccc")  # Đỏ nhạt
            elif severity >= 5:
                colors.append("#ffe0cc")  # Cam nhạt
            else:
                colors.append("#ffffcc")  # Vàng nhạt
        
        # Tạo bảng
        table = ax1.table(
            cellText=data,
            colLabels=headers,
            loc='center',
            cellLoc='center'
        )
        
        # Định dạng bảng
        table.auto_set_font_size(False)
        table.set_fontsize(9)
        table.scale(1, 1.5)
        
        # Đặt màu nền cho các hàng dữ liệu
        for i in range(len(data)):
            for j in range(len(headers)):
                cell = table[(i+1, j)]  # +1 vì hàng 0 là header
                cell.set_facecolor(colors[i])
        
        # Định dạng header
        for j, header in enumerate(headers):
            cell = table[(0, j)]
            cell.set_facecolor('#4b6584')  # Màu xanh đậm
            cell.set_text_props(color='white')
        
        ax1.set_title("Cảnh báo tấn công DNS", fontsize=14, pad=20)
        
        # Vẽ biểu đồ số lượng gói DNS theo thời gian
        x = range(len(timestamps))
        
        ax2.plot(x, dns_queries, marker='o', linewidth=2, label='DNS Queries', color='#3498db')
        ax2.plot(x, dns_responses, marker='s', linewidth=2, label='DNS Responses', color='#2ecc71')
        ax2.plot(x, dns_nxdomain, marker='^', linewidth=2, label='NXDOMAIN', color='#e74c3c')
        
        # Tạo đồ thị phụ để hiển thị tỷ lệ NXDOMAIN
        ax3 = ax2.twinx()
        nxdomain_ratio = []
        for q, nx in zip(dns_queries, dns_nxdomain):
            ratio = (nx / q * 100) if q > 0 else 0
            nxdomain_ratio.append(ratio)
        
        ax3.plot(x, nxdomain_ratio, marker='d', linestyle='--', linewidth=1.5, label='NXDOMAIN Ratio (%)', color='#9b59b6')
        ax3.set_ylabel('NXDOMAIN Ratio (%)')
        ax3.set_ylim(0, 100)
        
        # Đánh dấu vùng bất thường
        ax2.axvspan(3, 5, alpha=0.2, color='red', label='Vùng bất thường')
        
        ax2.set_xlabel('Thời gian')
        ax2.set_ylabel('Số lượng gói tin')
        ax2.set_title('Phân tích lưu lượng DNS theo thời gian')
        ax2.set_xticks(x)
        ax2.set_xticklabels(timestamps)
        
        # Thêm legend tổng hợp
        lines1, labels1 = ax2.get_legend_handles_labels()
        lines2, labels2 = ax3.get_legend_handles_labels()
        ax2.legend(lines1 + lines2, labels1 + labels2, loc='upper right')
        
        ax2.grid(True, linestyle='--', alpha=0.7)
        
        plt.tight_layout()
        return fig
    
    def _create_dns_attack_chart_from_data(self, dns_analysis: Dict) -> plt.Figure:
        """
        Tạo biểu đồ phát hiện tấn công DNS từ dữ liệu thực.
        
        Args:
            dns_analysis: Dict chứa dữ liệu phân tích DNS

        Returns:
            Biểu đồ cảnh báo DNS
        """
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10), gridspec_kw={'height_ratios': [1, 2]})
        
        # Trích xuất dữ liệu cảnh báo
        dns_alerts = dns_analysis.get("alerts", [])
        
        # Trích xuất dữ liệu lưu lượng
        traffic_data = dns_analysis.get("traffic", {})
        timestamps = traffic_data.get("timestamps", [])
        dns_queries = traffic_data.get("queries", [])
        dns_responses = traffic_data.get("responses", [])
        dns_nxdomain = traffic_data.get("nxdomain", [])
        top_domains = traffic_data.get("top_domains", [])
        
        # Vẽ bảng cảnh báo DNS
        ax1.axis('tight')
        ax1.axis('off')
        
        # Chuẩn bị dữ liệu cho bảng
        headers = ["Thời gian", "IP nguồn", "Tên miền", "Loại cảnh báo", "Mức độ", "Chi tiết"]
        data = []
        colors = []
        
        for alert in dns_alerts:
            # Định dạng dữ liệu
            severity = alert.get("severity", 0)
            
            # Chuyển mức độ thành biểu tượng
            if severity >= 8:
                severity_icon = "🔴 " + str(severity)
            elif severity >= 5:
                severity_icon = "🟠 " + str(severity)
            else:
                severity_icon = "🟡 " + str(severity)
            
            data.append([
                alert.get("time", ""),
                alert.get("src_ip", ""),
                alert.get("domain", ""),
                alert.get("alert_type", ""),
                severity_icon,
                alert.get("details", "")
            ])
            
            # Màu nền dựa trên mức độ nghiêm trọng
            if severity >= 8:
                colors.append("#ffcccc")  # Đỏ nhạt
            elif severity >= 5:
                colors.append("#ffe0cc")  # Cam nhạt
            else:
                colors.append("#ffffcc")  # Vàng nhạt
        
        # Tạo bảng nếu có dữ liệu
        if data:
            table = ax1.table(
                cellText=data,
                colLabels=headers,
                loc='center',
                cellLoc='center'
            )
            
            # Định dạng bảng
            table.auto_set_font_size(False)
            table.set_fontsize(9)
            table.scale(1, 1.5)
            
            # Đặt màu nền cho các hàng dữ liệu
            for i in range(len(data)):
                for j in range(len(headers)):
                    cell = table[(i+1, j)]  # +1 vì hàng 0 là header
                    cell.set_facecolor(colors[i])
            
            # Định dạng header
            for j, header in enumerate(headers):
                cell = table[(0, j)]
                cell.set_facecolor('#4b6584')  # Màu xanh đậm
                cell.set_text_props(color='white')
        else:
            ax1.text(0.5, 0.5, "Không có cảnh báo DNS", ha='center', va='center', fontsize=14)
        
        ax1.set_title("Cảnh báo tấn công DNS", fontsize=14, pad=20)
        
        # Vẽ biểu đồ số lượng gói DNS theo thời gian
        if timestamps and any([dns_queries, dns_responses, dns_nxdomain]):
            x = range(len(timestamps))
            
            if dns_queries:
                ax2.plot(x, dns_queries, marker='o', linewidth=2, label='DNS Queries', color='#3498db')
            if dns_responses:
                ax2.plot(x, dns_responses, marker='s', linewidth=2, label='DNS Responses', color='#2ecc71')
            if dns_nxdomain:
                ax2.plot(x, dns_nxdomain, marker='^', linewidth=2, label='NXDOMAIN', color='#e74c3c')
            
            # Tạo đồ thị phụ để hiển thị tỷ lệ NXDOMAIN
            if dns_queries and dns_nxdomain:
                ax3 = ax2.twinx()
                nxdomain_ratio = []
                for q, nx in zip(dns_queries, dns_nxdomain):
                    ratio = (nx / q * 100) if q > 0 else 0
                    nxdomain_ratio.append(ratio)
                
                ax3.plot(x, nxdomain_ratio, marker='d', linestyle='--', linewidth=1.5, label='NXDOMAIN Ratio (%)', color='#9b59b6')
                ax3.set_ylabel('NXDOMAIN Ratio (%)')
                ax3.set_ylim(0, 100)
                
                # Thêm legend tổng hợp
                lines1, labels1 = ax2.get_legend_handles_labels()
                lines2, labels2 = ax3.get_legend_handles_labels()
                ax2.legend(lines1 + lines2, labels1 + labels2, loc='upper right')
            else:
                ax2.legend(loc='upper right')
            
            # Đánh dấu vùng bất thường nếu có
            anomaly_start = traffic_data.get("anomaly_start", -1)
            anomaly_end = traffic_data.get("anomaly_end", -1)
            if anomaly_start >= 0 and anomaly_end >= 0 and anomaly_start < len(timestamps) and anomaly_end < len(timestamps):
                ax2.axvspan(anomaly_start, anomaly_end, alpha=0.2, color='red', label='Vùng bất thường')
            
            ax2.set_xlabel('Thời gian')
            ax2.set_ylabel('Số lượng gói tin')
            ax2.set_title('Phân tích lưu lượng DNS theo thời gian')
            ax2.set_xticks(x)
            ax2.set_xticklabels(timestamps)
            ax2.grid(True, linestyle='--', alpha=0.7)
        else:
            ax2.text(0.5, 0.5, "Không có dữ liệu lưu lượng DNS", ha='center', va='center', fontsize=14)
            ax2.set_title('Phân tích lưu lượng DNS theo thời gian')
            ax2.axis('off')
        
        plt.tight_layout()
        return fig
    
    def create_top_talkers_chart(self, results: Dict, top_n: int = 10) -> plt.Figure:
        """
        Tạo biểu đồ Top Talkers/Chatters.
        
        Args:
            results: Kết quả phân tích gói tin
            top_n: Số lượng top hosts muốn hiển thị
            
        Returns:
            Biểu đồ Top Talkers/Chatters
        """
        if not results:
            return self._create_empty_chart("Không có dữ liệu để phân tích Top Talkers")
        
        # Sử dụng dữ liệu top talkers nếu có trong kết quả
        if "top_talkers" in results and results["top_talkers"]:
            top_talkers_data = results["top_talkers"]
            return self._create_top_talkers_chart_from_data(top_talkers_data, top_n)
        elif "ip_stats" in results and results["ip_stats"]:
            # Thử sử dụng ip_stats để tạo dữ liệu top talkers
            ip_stats = results["ip_stats"]
            return self._create_top_talkers_chart_from_ip_stats(ip_stats, top_n)
        else:
            # Nếu không có dữ liệu thực, tạo mẫu
            return self._create_sample_top_talkers_chart(top_n)
    
    def _create_sample_top_talkers_chart(self, top_n: int = 10) -> plt.Figure:
        """
        Tạo biểu đồ mẫu Top Talkers khi không có dữ liệu thực.
        
        Args:
            top_n: Số lượng top hosts muốn hiển thị
            
        Returns:
            Biểu đồ mẫu Top Talkers
        """
        # Giới hạn top_n
        top_n = min(top_n, 20)
        
        # Tạo dữ liệu mẫu
        source_ips = [f"192.168.1.{i}" for i in range(1, top_n + 1)]
        sent_packets = [random.randint(100, 1000) for _ in range(top_n)]
        
        destination_ips = [f"10.0.0.{i}" for i in range(1, top_n + 1)]
        received_packets = [random.randint(100, 1000) for _ in range(top_n)]
        
        # Sắp xếp giảm dần theo số lượng gói tin
        source_data = sorted(zip(source_ips, sent_packets), key=lambda x: x[1], reverse=True)
        dest_data = sorted(zip(destination_ips, received_packets), key=lambda x: x[1], reverse=True)
        
        source_ips, sent_packets = zip(*source_data)
        destination_ips, received_packets = zip(*dest_data)
        
        # Tạo figure với 2 subplots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 8))
        
        # Vẽ Top Source IPs
        bars1 = ax1.barh(source_ips, sent_packets, color=plt.cm.Blues(0.6))
        ax1.set_title(f"Top {top_n} Source IPs (Talkers)")
        ax1.set_xlabel("Số lượng gói tin gửi")
        ax1.set_ylabel("Địa chỉ IP nguồn")
        
        # Thêm giá trị trên mỗi thanh
        for bar in bars1:
            width = bar.get_width()
            ax1.text(width + 10, bar.get_y() + bar.get_height()/2, f"{width:,}",
                     ha='left', va='center', fontsize=9)
        
        # Vẽ Top Destination IPs
        bars2 = ax2.barh(destination_ips, received_packets, color=plt.cm.Reds(0.6))
        ax2.set_title(f"Top {top_n} Destination IPs (Listeners)")
        ax2.set_xlabel("Số lượng gói tin nhận")
        ax2.set_ylabel("Địa chỉ IP đích")
        
        # Thêm giá trị trên mỗi thanh
        for bar in bars2:
            width = bar.get_width()
            ax2.text(width + 10, bar.get_y() + bar.get_height()/2, f"{width:,}",
                     ha='left', va='center', fontsize=9)
        
        plt.tight_layout()
        plt.subplots_adjust(top=0.9)
        fig.suptitle(f"Top {top_n} Talkers & Listeners (Dữ liệu mẫu)", fontsize=16)
        
        return fig
    
    def _create_top_talkers_chart_from_data(self, top_talkers_data: Dict, top_n: int = 10) -> plt.Figure:
        """
        Tạo biểu đồ Top Talkers từ dữ liệu thực.
        
        Args:
            top_talkers_data: Dict chứa dữ liệu top talkers
            top_n: Số lượng top hosts muốn hiển thị
            
        Returns:
            Biểu đồ Top Talkers
        """
        # Giới hạn top_n
        top_n = min(top_n, 20)
        
        # Trích xuất dữ liệu
        source_data = top_talkers_data.get("sources", {})
        dest_data = top_talkers_data.get("destinations", {})
        
        # Chuyển dict thành danh sách và sắp xếp
        source_items = sorted(source_data.items(), key=lambda x: x[1], reverse=True)[:top_n]
        dest_items = sorted(dest_data.items(), key=lambda x: x[1], reverse=True)[:top_n]
        
        # Tách thành hai danh sách riêng biệt
        source_ips, sent_packets = [], []
        if source_items:
            source_ips, sent_packets = zip(*source_items)
        
        destination_ips, received_packets = [], []
        if dest_items:
            destination_ips, received_packets = zip(*dest_items)
        
        # Tạo figure với 2 subplots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 8))
        
        # Vẽ Top Source IPs nếu có dữ liệu
        if source_ips:
            bars1 = ax1.barh(source_ips, sent_packets, color=plt.cm.Blues(0.6))
            ax1.set_title(f"Top {len(source_ips)} Source IPs (Talkers)")
            ax1.set_xlabel("Số lượng gói tin gửi")
            ax1.set_ylabel("Địa chỉ IP nguồn")
            
            # Thêm giá trị trên mỗi thanh
            for bar in bars1:
                width = bar.get_width()
                ax1.text(width + 10, bar.get_y() + bar.get_height()/2, f"{width:,}",
                         ha='left', va='center', fontsize=9)
        else:
            ax1.text(0.5, 0.5, "Không có dữ liệu Source IPs", ha='center', va='center', fontsize=14)
            ax1.set_title("Top Source IPs (Talkers)")
            ax1.axis('off')
        
        # Vẽ Top Destination IPs nếu có dữ liệu
        if destination_ips:
            bars2 = ax2.barh(destination_ips, received_packets, color=plt.cm.Reds(0.6))
            ax2.set_title(f"Top {len(destination_ips)} Destination IPs (Listeners)")
            ax2.set_xlabel("Số lượng gói tin nhận")
            ax2.set_ylabel("Địa chỉ IP đích")
            
            # Thêm giá trị trên mỗi thanh
            for bar in bars2:
                width = bar.get_width()
                ax2.text(width + 10, bar.get_y() + bar.get_height()/2, f"{width:,}",
                         ha='left', va='center', fontsize=9)
        else:
            ax2.text(0.5, 0.5, "Không có dữ liệu Destination IPs", ha='center', va='center', fontsize=14)
            ax2.set_title("Top Destination IPs (Listeners)")
            ax2.axis('off')
        
        plt.tight_layout()
        plt.subplots_adjust(top=0.9)
        fig.suptitle(f"Top Talkers & Listeners", fontsize=16)
        
        return fig
    
    def _create_top_talkers_chart_from_ip_stats(self, ip_stats: Dict, top_n: int = 10) -> plt.Figure:
        """
        Tạo biểu đồ Top Talkers từ dữ liệu ip_stats.
        
        Args:
            ip_stats: Dict chứa thống kê IP
            top_n: Số lượng top hosts muốn hiển thị
            
        Returns:
            Biểu đồ Top Talkers
        """
        # Tạo dữ liệu top talkers từ ip_stats
        source_counts = ip_stats.get("source_counts", {})
        dest_counts = ip_stats.get("destination_counts", {})
        
        # Tạo figure và biểu đồ bằng cách sử dụng phương thức tạo từ dữ liệu
        top_talkers_data = {
            "sources": source_counts,
            "destinations": dest_counts
        }
        
        return self._create_top_talkers_chart_from_data(top_talkers_data, top_n)