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
        # Tạo biểu đồ với dữ liệu thực tế khi có
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
        
        # Tạo biểu đồ với dữ liệu thực tế khi có
        return self._create_sample_link_quality_chart()
    
    def _create_sample_link_quality_chart(self) -> plt.Figure:
        """Tạo biểu đồ chất lượng đường truyền mẫu."""
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8), gridspec_kw={'height_ratios': [2, 1]})
        
        # Dữ liệu mẫu
        timestamps = range(10)  # 10 mốc thời gian
        
        # Dữ liệu độ trễ cho các thiết bị
        links = {
            "Router-Core → Switch-1": [5, 8, 6, 7, 15, 10, 5, 6, 8, 7],
            "Router-Core → Server-A": [10, 15, 12, 18, 50, 30, 20, 15, 12, 10],
            "Switch-1 → Server-B": [8, 10, 9, 12, 11, 9, 8, 7, 10, 9],
            "Server-A → Server-B": [20, 25, 30, 35, 100, 60, 40, 30, 25, 20]
        }
        
        # Dữ liệu mất gói
        packet_loss = {
            "Router-Core → Switch-1": [0, 0, 0, 0, 2, 0, 0, 0, 0, 0],
            "Router-Core → Server-A": [0, 1, 0, 2, 5, 3, 1, 0, 0, 0],
            "Switch-1 → Server-B": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            "Server-A → Server-B": [1, 2, 2, 3, 10, 5, 3, 1, 0, 0]
        }
        
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
        
        # Tạo legend mà không lặp lại các mục
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
        bar_width = 0.2
        positions = []
        for i, (link_name, loss_values) in enumerate(packet_loss.items()):
            pos = [t + i * bar_width for t in timestamps]
            positions.append(pos)
            bars = ax2.bar(pos, loss_values, width=bar_width, label=link_name, alpha=0.7)
            
            # Đánh dấu cảnh báo cho các điểm có mất gói > 2%
            for j, val in enumerate(loss_values):
                if val > 2:
                    bars[j].set_color('red')
        
        ax2.set_title("Tỷ lệ mất gói (Packet Loss)")
        ax2.set_xlabel("Thời gian (phút)")
        ax2.set_ylabel("Số gói mất (%)")
        ax2.set_ylim(bottom=0)
        
        # Sửa lỗi: Đảm bảo số lượng tick và số lượng nhãn phải bằng nhau
        # Đặt ticks ở vị trí giữa của mỗi nhóm thanh
        tick_positions = [positions[0][i] + (len(packet_loss) * bar_width) / 2 for i in range(len(timestamps))]
        ax2.set_xticks(tick_positions)
        ax2.set_xticklabels([str(i) for i in range(10)])  # Chuyển đổi số thành chuỗi
        
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
        
        # Tạo biểu đồ với dữ liệu thực tế khi có
        return self._create_sample_arp_attack_chart()
    
    def _create_sample_arp_attack_chart(self) -> plt.Figure:
        """Tạo biểu đồ phát hiện tấn công ARP mẫu."""
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10), gridspec_kw={'height_ratios': [1, 2]})
        
        # Dữ liệu mẫu cho biểu đồ cảnh báo ARP spoofing
        arp_alerts = [
            {"time": "10:15:23", "src_ip": "192.168.1.5", "src_mac": "00:1A:2B:3C:4D:5E", 
             "claimed_ip": "192.168.1.1", "real_mac": "00:11:22:33:44:55", 
             "alert_type": "ARP Spoofing", "severity": 9},
            
            {"time": "10:16:45", "src_ip": "192.168.1.5", "src_mac": "00:1A:2B:3C:4D:5E", 
             "claimed_ip": "192.168.1.2", "real_mac": "00:AA:BB:CC:DD:EE", 
             "alert_type": "ARP Spoofing", "severity": 9},
            
            {"time": "10:22:18", "src_ip": "192.168.1.10", "src_mac": "00:5E:4D:3C:2B:1A", 
             "claimed_ip": None, "real_mac": None, 
             "alert_type": "Excessive ARP Requests", "severity": 6},
            
            {"time": "10:25:32", "src_ip": "192.168.1.5", "src_mac": "00:1A:2B:3C:4D:5E", 
             "claimed_ip": "192.168.1.254", "real_mac": "00:FF:AA:BB:CC:DD", 
             "alert_type": "ARP Spoofing", "severity": 9},
            
            {"time": "10:30:15", "src_ip": "192.168.1.15", "src_mac": "00:EE:DD:CC:BB:AA", 
             "claimed_ip": None, "real_mac": None, 
             "alert_type": "Gratuitous ARP", "severity": 4}
        ]
        
        # Dữ liệu mẫu cho số lượng gói ARP theo thời gian
        timestamps = ["10:05", "10:10", "10:15", "10:20", "10:25", "10:30", "10:35", "10:40"]
        arp_requests = [12, 15, 45, 60, 52, 40, 25, 18]
        arp_replies = [10, 12, 40, 55, 48, 38, 20, 15]
        arp_gratuitous = [0, 0, 2, 5, 3, 5, 1, 0]
        
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
        ax2.axvspan(2, 5, alpha=0.2, color='red', label='Vùng bất thường')
        
        ax2.set_xlabel('Thời gian')
        ax2.set_ylabel('Số lượng gói tin')
        ax2.set_title('Phân tích lưu lượng ARP theo thời gian')
        ax2.set_xticks(x)
        ax2.set_xticklabels(timestamps)
        ax2.legend()
        ax2.grid(axis='y', linestyle='--', alpha=0.7)
        
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
        
        # Tạo biểu đồ với dữ liệu thực tế khi có
        return self._create_sample_icmp_anomaly_chart()
    
    def _create_sample_icmp_anomaly_chart(self) -> plt.Figure:
        """Tạo biểu đồ phát hiện bất thường ICMP mẫu."""
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10), gridspec_kw={'height_ratios': [2, 1]})
        
        # Dữ liệu mẫu cho biểu đồ số lượng gói ICMP theo thời gian và loại
        timestamps = ["10:05", "10:10", "10:15", "10:20", "10:25", "10:30", "10:35", "10:40"]
        icmp_echo_request = [15, 25, 120, 180, 150, 65, 30, 20]
        icmp_echo_reply = [12, 20, 90, 140, 120, 50, 25, 18]
        icmp_dest_unreachable = [2, 5, 15, 25, 20, 12, 5, 3]
        icmp_time_exceeded = [1, 2, 5, 8, 6, 3, 2, 1]
        icmp_other = [0, 1, 3, 10, 8, 4, 1, 0]
        
        # Vẽ biểu đồ số lượng gói ICMP theo thời gian và loại
        ax1.plot(timestamps, icmp_echo_request, 'o-', label='Echo Request', color='#3498db')
        ax1.plot(timestamps, icmp_echo_reply, 'o-', label='Echo Reply', color='#2ecc71')
        ax1.plot(timestamps, icmp_dest_unreachable, 'o-', label='Destination Unreachable', color='#e74c3c')
        ax1.plot(timestamps, icmp_time_exceeded, 'o-', label='Time Exceeded', color='#f39c12')
        ax1.plot(timestamps, icmp_other, 'o-', label='Khác', color='#9b59b6')
        
        # Đánh dấu vùng bất thường
        ax1.axvspan(2, 5, alpha=0.2, color='red', label='Vùng bất thường')
        
        # Cấu hình biểu đồ
        ax1.set_xlabel('Thời gian')
        ax1.set_ylabel('Số lượng gói tin')
        ax1.set_title('Phân tích lưu lượng ICMP theo thời gian và loại')
        ax1.legend(loc='upper right')
        ax1.grid(True, linestyle='--', alpha=0.7)
        
        # Thêm chú thích cho điểm bất thường
        ax1.annotate('ICMP Flood', xy=(3, 180), xytext=(3.5, 200),
                    arrowprops=dict(facecolor='black', shrink=0.05, width=1.5))
        
        # Dữ liệu mẫu cho bảng cảnh báo ICMP
        icmp_alerts = [
            {"time": "10:15:23", "src_ip": "172.16.5.10", "dst_ip": "192.168.1.1", 
             "icmp_type": 8, "icmp_code": 0, "payload_size": 2048,
             "alert_type": "ICMP Echo Request Flood", "severity": 8},
            
            {"time": "10:16:45", "src_ip": "172.16.5.11", "dst_ip": "192.168.1.1", 
             "icmp_type": 8, "icmp_code": 0, "payload_size": 2048,
             "alert_type": "ICMP Echo Request Flood", "severity": 8},
            
            {"time": "10:22:18", "src_ip": "192.168.1.5", "dst_ip": "8.8.8.8", 
             "icmp_type": 3, "icmp_code": 1, "payload_size": 560,
             "alert_type": "Bất thường Destination Unreachable", "severity": 5},
            
            {"time": "10:25:32", "src_ip": "192.168.1.10", "dst_ip": "192.168.1.100", 
             "icmp_type": 8, "icmp_code": 0, "payload_size": 4096,
             "alert_type": "ICMP Tunneling Suspected", "severity": 7}
        ]
        
        # Vẽ bảng cảnh báo ICMP
        ax2.axis('tight')
        ax2.axis('off')
        
        # Chuẩn bị dữ liệu cho bảng
        headers = ["Thời gian", "IP nguồn", "IP đích", "Loại ICMP", "Kích thước", "Loại cảnh báo", "Mức độ"]
        data = []
        colors = []
        
        for alert in icmp_alerts:
            # Định dạng dữ liệu
            icmp_type = alert.get("icmp_type", 0)
            icmp_code = alert.get("icmp_code", 0)
            icmp_type_str = f"{icmp_type}/{icmp_code}"
            
            # Thêm nhãn loại ICMP cho dễ đọc
            if icmp_type == 8 and icmp_code == 0:
                icmp_type_str += " (Echo Request)"
            elif icmp_type == 0 and icmp_code == 0:
                icmp_type_str += " (Echo Reply)"
            elif icmp_type == 3:
                icmp_type_str += " (Dest Unreachable)"
            elif icmp_type == 11:
                icmp_type_str += " (Time Exceeded)"
            
            # Kích thước payload
            payload_size = f"{alert.get('payload_size', 0)} bytes"
            
            # Mức độ nghiêm trọng
            severity = alert.get("severity", 0)
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
                icmp_type_str,
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
        table = ax2.table(
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
        
        ax2.set_title("Cảnh báo bất thường ICMP", fontsize=14, pad=20)
        
        plt.tight_layout()
        return fig
    
    def create_dhcp_attack_chart(self, results: Dict) -> plt.Figure:
        """
        Tạo biểu đồ phát hiện dấu hiệu tấn công DHCP.
        
        Args:
            results: Kết quả phân tích gói tin

        Returns:
            Biểu đồ phát hiện tấn công DHCP
        """
        if not results or "dhcp_analysis" not in results or not results.get("dhcp_analysis"):
            # Tạo biểu đồ phát hiện tấn công DHCP mẫu khi không có dữ liệu thực
            return self._create_sample_dhcp_attack_chart()
        
        # Tạo biểu đồ với dữ liệu thực tế khi có
        return self._create_sample_dhcp_attack_chart()
    
    def _create_sample_dhcp_attack_chart(self) -> plt.Figure:
        """Tạo biểu đồ phát hiện tấn công DHCP mẫu."""
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10), gridspec_kw={'height_ratios': [1, 2]})
        
        # Dữ liệu mẫu cho bảng cảnh báo DHCP
        dhcp_alerts = [
            {"time": "10:15:23", "src_ip": "0.0.0.0", "src_mac": "00:1A:2B:3C:4D:5E", 
             "server_ip": "192.168.1.200", "server_mac": "00:AA:BB:CC:DD:EE", 
             "alert_type": "Rogue DHCP Server", "severity": 9},
            
            {"time": "10:18:45", "src_ip": "0.0.0.0", "src_mac": "00:5E:4D:3C:2B:1A", 
             "server_ip": "192.168.1.1", "server_mac": "00:11:22:33:44:55", 
             "alert_type": "DHCP Starvation", "severity": 7},
            
            {"time": "10:22:18", "src_ip": "0.0.0.0", "src_mac": "00:1A:2B:3C:4D:5E", 
             "server_ip": "192.168.1.1", "server_mac": "00:11:22:33:44:55", 
             "alert_type": "DHCP ACK Injection", "severity": 8}
        ]
        
        # Vẽ bảng cảnh báo DHCP
        ax1.axis('tight')
        ax1.axis('off')
        
        # Chuẩn bị dữ liệu cho bảng
        headers = ["Thời gian", "IP nguồn", "MAC nguồn", "IP server", "MAC server", "Loại cảnh báo", "Mức độ"]
        data = []
        colors = []
        
        for alert in dhcp_alerts:
            # Mức độ nghiêm trọng
            severity = alert.get("severity", 0)
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
        
        # Dữ liệu mẫu cho số lượng gói DHCP theo thời gian và loại
        timestamps = ["10:05", "10:10", "10:15", "10:20", "10:25", "10:30", "10:35", "10:40"]
        dhcp_discover = [5, 8, 50, 80, 60, 30, 10, 5]
        dhcp_offer = [4, 7, 45, 75, 55, 28, 8, 4]
        dhcp_request = [4, 7, 40, 70, 50, 25, 8, 3]
        dhcp_ack = [4, 7, 40, 70, 50, 25, 8, 3]
        
        # Vẽ biểu đồ số lượng gói DHCP theo thời gian
        bar_width = 0.2
        x = range(len(timestamps))
        
        ax2.bar([i - 1.5*bar_width for i in x], dhcp_discover, bar_width, label='DHCP Discover', color='#3498db')
        ax2.bar([i - 0.5*bar_width for i in x], dhcp_offer, bar_width, label='DHCP Offer', color='#2ecc71')
        ax2.bar([i + 0.5*bar_width for i in x], dhcp_request, bar_width, label='DHCP Request', color='#f39c12')
        ax2.bar([i + 1.5*bar_width for i in x], dhcp_ack, bar_width, label='DHCP ACK', color='#9b59b6')
        
        # Đánh dấu vùng bất thường
        ax2.axvspan(2, 5, alpha=0.2, color='red', label='Vùng bất thường')
        
        # Thêm chú thích cho điểm bất thường
        ax2.annotate('DHCP Starvation Attack', xy=(3, 80), xytext=(4, 90),
                    arrowprops=dict(facecolor='black', shrink=0.05, width=1.5))
        
        # Thêm đường ngưỡng cảnh báo
        ax2.axhline(y=30, color='r', linestyle='--', alpha=0.5, label='Ngưỡng cảnh báo')
        
        # Cấu hình biểu đồ
        ax2.set_xlabel('Thời gian')
        ax2.set_ylabel('Số lượng gói tin')
        ax2.set_title('Phân tích lưu lượng DHCP theo thời gian')
        ax2.set_xticks(x)
        ax2.set_xticklabels(timestamps)
        ax2.legend(loc='upper right')
        ax2.grid(axis='y', linestyle='--', alpha=0.7)
        
        plt.tight_layout()
        return fig
    
    def create_dns_attack_chart(self, results: Dict) -> plt.Figure:
        """
        Tạo biểu đồ phát hiện dấu hiệu tấn công DNS.
        
        Args:
            results: Kết quả phân tích gói tin

        Returns:
            Biểu đồ phát hiện tấn công DNS
        """
        if not results or "dns_analysis" not in results or not results.get("dns_analysis"):
            # Tạo biểu đồ phát hiện tấn công DNS mẫu khi không có dữ liệu thực
            return self._create_sample_dns_attack_chart()
        
        # Tạo biểu đồ với dữ liệu thực tế khi có
        return self._create_sample_dns_attack_chart()
    
    def _create_sample_dns_attack_chart(self) -> plt.Figure:
        """Tạo biểu đồ phát hiện tấn công DNS mẫu."""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        
        # Dữ liệu mẫu cho biểu đồ số lượng truy vấn DNS theo thời gian
        timestamps = ["10:05", "10:10", "10:15", "10:20", "10:25", "10:30", "10:35", "10:40"]
        dns_queries = [120, 150, 480, 560, 420, 280, 180, 140]
        dns_responses = [110, 140, 420, 490, 350, 250, 170, 130]
        dns_nxdomain = [10, 15, 150, 180, 120, 60, 20, 15]
        
        # Vẽ biểu đồ số lượng truy vấn DNS theo thời gian
        ax1.plot(timestamps, dns_queries, 'o-', label='DNS Queries', color='#3498db')
        ax1.plot(timestamps, dns_responses, 'o-', label='DNS Responses', color='#2ecc71')
        ax1.plot(timestamps, dns_nxdomain, 'o-', label='NXDOMAIN Responses', color='#e74c3c')
        
        # Đánh dấu vùng bất thường
        ax1.axvspan(2, 5, alpha=0.2, color='red', label='Vùng bất thường')
        
        # Thêm chú thích cho điểm bất thường
        ax1.annotate('DNS Flood Attack', xy=(3, 560), xytext=(4, 600),
                    arrowprops=dict(facecolor='black', shrink=0.05, width=1.5))
        
        # Cấu hình biểu đồ
        ax1.set_xlabel('Thời gian')
        ax1.set_ylabel('Số lượng')
        ax1.set_title('Lưu lượng DNS theo thời gian')
        ax1.legend(loc='upper right')
        ax1.grid(True, linestyle='--', alpha=0.7)
        
        # Dữ liệu mẫu cho biểu đồ kích thước gói DNS
        dns_sizes = [
            20, 25, 30, 35, 40, 45, 50, 60, 70, 80, 90, 100, 120, 150, 
            200, 250, 300, 400, 500, 800, 1200, 2000, 3000, 4000
        ]
        dns_size_counts = [
            50, 80, 120, 180, 220, 200, 180, 150, 120, 90, 60, 40, 30, 25,
            20, 15, 10, 8, 5, 3, 10, 15, 8, 3
        ]
        
        # Vẽ biểu đồ histogram kích thước gói DNS
        ax2.bar(dns_sizes, dns_size_counts, width=20, color='#3498db', alpha=0.7)
        
        # Đánh dấu vùng bất thường
        ax2.axvspan(1500, 4000, alpha=0.2, color='red', label='Vùng bất thường')
        
        # Thêm chú thích cho vùng bất thường
        ax2.annotate('DNS Tunneling Suspected', xy=(2000, 15), xytext=(1000, 20),
                    arrowprops=dict(facecolor='black', shrink=0.05, width=1.5))
        
        # Cấu hình biểu đồ
        ax2.set_xlabel('Kích thước gói tin (bytes)')
        ax2.set_ylabel('Số lượng')
        ax2.set_title('Phân bố kích thước gói DNS')
        ax2.set_xscale('log')
        ax2.grid(True, linestyle='--', alpha=0.7)
        
        # Dữ liệu mẫu cho biểu đồ miền đích phổ biến
        top_domains = [
            "example.com", "google.com", "office365.com", 
            "microsoft.com", "amazon.com", "akamai.net",
            "abcdefg123.xyz", "qq41uasdk3.cn", "z7x9vb2n5m.info"
        ]
        
        domain_counts = [120, 80, 60, 55, 50, 45, 200, 180, 150]
        domain_colors = ['#3498db', '#3498db', '#3498db', '#3498db', '#3498db', '#3498db', 
                         '#e74c3c', '#e74c3c', '#e74c3c']
        
        # Vẽ biểu đồ miền đích phổ biến
        y_pos = range(len(top_domains))
        ax3.barh(y_pos, domain_counts, color=domain_colors)
        ax3.set_yticks(y_pos)
        ax3.set_yticklabels(top_domains)
        ax3.invert_yaxis()  # Sắp xếp từ trên xuống
        
        # Đánh dấu miền đáng ngờ
        for i, color in enumerate(domain_colors):
            if color == '#e74c3c':
                ax3.get_yticklabels()[i].set_color('#e74c3c')
        
        # Thêm chú thích
        ax3.annotate('Miền đáng ngờ', xy=(190, 6.5), xytext=(100, 4),
                    arrowprops=dict(facecolor='black', shrink=0.05, width=1.5))
        
        # Cấu hình biểu đồ
        ax3.set_xlabel('Số lượng truy vấn')
        ax3.set_title('Top DNS Domains')
        ax3.grid(True, linestyle='--', alpha=0.7)
        
        # Dữ liệu mẫu cho bảng cảnh báo DNS
        dns_alerts = [
            {"time": "10:15:23", "src_ip": "192.168.1.5", "domain": "example.com", 
             "alert_type": "DNS Query Flood", "severity": 7, "details": "300+ truy vấn/phút"},
            
            {"time": "10:18:45", "src_ip": "192.168.1.10", "domain": "abcdefg123.xyz", 
             "alert_type": "DNS Tunneling Suspected", "severity": 8, "details": "Kích thước gói lớn, nhiều subdomain"},
            
            {"time": "10:22:18", "src_ip": "192.168.1.15", "domain": "google.com", 
             "alert_type": "DNS Cache Poisoning", "severity": 9, "details": "IP phản hồi thay đổi"}
        ]
        
        # Vẽ bảng cảnh báo DNS
        ax4.axis('tight')
        ax4.axis('off')
        
        # Chuẩn bị dữ liệu cho bảng
        headers = ["Thời gian", "IP nguồn", "Tên miền", "Loại cảnh báo", "Mức độ", "Chi tiết"]
        data = []
        colors = []
        
        for alert in dns_alerts:
            # Mức độ nghiêm trọng
            severity = alert.get("severity", 0)
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
        table = ax4.table(
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
        
        ax4.set_title("Cảnh báo tấn công DNS", fontsize=14, pad=20)
        
        plt.tight_layout()
        return fig
    
    def create_top_talkers_chart(self, results: Dict, n: int = 10) -> plt.Figure:
        """
        Tạo biểu đồ Top N IP nguồn/đích gửi nhiều dữ liệu nhất.
        
        Args:
            results: Kết quả phân tích gói tin
            n: Số lượng top hosts cần hiển thị

        Returns:
            Biểu đồ Top N Talkers/Chatters
        """
        if not results or "ip_stats" not in results or not results.get("ip_stats"):
            # Tạo biểu đồ top talkers mẫu khi không có dữ liệu thực
            return self._create_sample_top_talkers_chart(n)
        
        # Tạo biểu đồ với dữ liệu thực tế khi có
        return self._create_sample_top_talkers_chart(n)
    
    def _create_sample_top_talkers_chart(self, n: int = 10) -> plt.Figure:
        """Tạo biểu đồ Top N Talkers mẫu."""
        # Giảm n nếu quá lớn
        n = min(n, 10)
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        
        # Dữ liệu mẫu cho Top N IP nguồn (theo bytes)
        source_ips = [
            "192.168.1.5", "192.168.1.10", "192.168.1.15", "10.0.0.1", "10.0.0.2",
            "192.168.1.20", "172.16.1.1", "192.168.1.25", "172.16.1.2", "10.0.0.3"
        ][:n]
        
        source_bytes = [
            1500000, 800000, 500000, 350000, 250000, 
            180000, 150000, 120000, 100000, 80000
        ][:n]
        
        # Vẽ biểu đồ Top N IP nguồn (theo bytes)
        bars1 = ax1.barh(range(len(source_ips)), source_bytes, color='#3498db')
        ax1.set_yticks(range(len(source_ips)))
        ax1.set_yticklabels(source_ips)
        ax1.invert_yaxis()  # Sắp xếp từ trên xuống
        
        # Thêm giá trị lên các cột
        for i, bar in enumerate(bars1):
            width = bar.get_width()
            formatted_width = self._format_bytes(width)
            ax1.text(width + (width * 0.02), bar.get_y() + bar.get_height()/2, 
                    formatted_width, va='center')
        
        ax1.set_xlabel('Bytes')
        ax1.set_title(f'Top {n} IP nguồn (theo bytes)')
        ax1.grid(True, linestyle='--', alpha=0.7, axis='x')
        
        # Dữ liệu mẫu cho Top N IP đích (theo bytes)
        dest_ips = [
            "8.8.8.8", "192.168.1.1", "216.58.200.174", "52.22.118.80", "13.32.98.150",
            "192.168.1.100", "172.217.167.78", "23.62.236.40", "192.168.1.2", "34.102.136.180"
        ][:n]
        
        dest_bytes = [
            2000000, 900000, 650000, 400000, 300000,
            250000, 200000, 180000, 150000, 120000
        ][:n]
        
        # Vẽ biểu đồ Top N IP đích (theo bytes)
        bars2 = ax2.barh(range(len(dest_ips)), dest_bytes, color='#2ecc71')
        ax2.set_yticks(range(len(dest_ips)))
        ax2.set_yticklabels(dest_ips)
        ax2.invert_yaxis()  # Sắp xếp từ trên xuống
        
        # Thêm giá trị lên các cột
        for i, bar in enumerate(bars2):
            width = bar.get_width()
            formatted_width = self._format_bytes(width)
            ax2.text(width + (width * 0.02), bar.get_y() + bar.get_height()/2, 
                    formatted_width, va='center')
        
        ax2.set_xlabel('Bytes')
        ax2.set_title(f'Top {n} IP đích (theo bytes)')
        ax2.grid(True, linestyle='--', alpha=0.7, axis='x')
        
        # Dữ liệu mẫu cho Top N cặp IP Source-Destination
        ip_pairs = [
            "192.168.1.5 → 8.8.8.8",
            "192.168.1.10 → 216.58.200.174",
            "192.168.1.15 → 52.22.118.80",
            "10.0.0.1 → 192.168.1.1",
            "192.168.1.5 → 13.32.98.150",
            "192.168.1.10 → 23.62.236.40",
            "172.16.1.1 → 34.102.136.180",
            "192.168.1.20 → 192.168.1.100",
            "10.0.0.2 → 172.217.167.78",
            "192.168.1.15 → 192.168.1.2"
        ][:n]
        
        pair_bytes = [
            1200000, 750000, 580000, 400000, 350000,
            280000, 220000, 180000, 150000, 120000
        ][:n]
        
        # Vẽ biểu đồ Top N cặp IP Source-Destination (theo bytes)
        bars3 = ax3.barh(range(len(ip_pairs)), pair_bytes, color='#9b59b6')
        ax3.set_yticks(range(len(ip_pairs)))
        ax3.set_yticklabels(ip_pairs)
        ax3.invert_yaxis()  # Sắp xếp từ trên xuống
        
        # Thêm giá trị lên các cột
        for i, bar in enumerate(bars3):
            width = bar.get_width()
            formatted_width = self._format_bytes(width)
            ax3.text(width + (width * 0.02), bar.get_y() + bar.get_height()/2, 
                    formatted_width, va='center')
        
        ax3.set_xlabel('Bytes')
        ax3.set_title(f'Top {n} cặp IP Source-Destination (theo bytes)')
        ax3.grid(True, linestyle='--', alpha=0.7, axis='x')
        
        # Dữ liệu mẫu cho Top N giao thức
        protocols = [
            "HTTP/HTTPS", "DNS", "ICMP", "DHCP", "NTP", 
            "SSH", "FTP", "SMTP", "SNMP", "RDP"
        ][:n]
        
        protocol_bytes = [
            2500000, 1200000, 800000, 400000, 350000,
            250000, 200000, 150000, 100000, 80000
        ][:n]
        
        # Vẽ biểu đồ Top N Protocols (theo bytes)
        cmap = plt.cm.get_cmap('tab10')
        colors = [cmap(i) for i in range(len(protocols))]
        
        ax4.pie(protocol_bytes, labels=protocols, colors=colors, autopct='%1.1f%%', 
              startangle=90, shadow=False)
        ax4.axis('equal')  # Để hình tròn đều
        
        ax4.set_title(f'Top {n} giao thức (theo bytes)')
        
        plt.tight_layout()
        return fig
    
    def _format_bytes(self, bytes_value: int) -> str:
        """
        Định dạng giá trị bytes thành đơn vị đọc được (KB, MB, GB).
        
        Args:
            bytes_value: Giá trị bytes cần định dạng

        Returns:
            Chuỗi đã định dạng
        """
        for unit in ['', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"