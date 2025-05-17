"""
Dashboard Presenter - Xử lý hiển thị dashboard và thống kê.
"""
import os
from src.domain.entities.packet_analyzer import PacketAnalyzer

class DashboardPresenter:
    """Xử lý hiển thị dashboard và thống kê mạng."""

    def __init__(self, base_presenter, chart_creator):
        """
        Khởi tạo Dashboard Presenter.
        
        Args:
            base_presenter: BasePresenter instance
            chart_creator: ChartCreator instance
        """
        self.base_presenter = base_presenter
        self.chart_creator = chart_creator
        self.packet_analyzer = PacketAnalyzer()
        self.pcap_data = None

    def extract_pcap_data(self, pcap_file):
        """
        Trích xuất dữ liệu từ file PCAP.
        
        Args:
            pcap_file: Đường dẫn đến file PCAP
            
        Returns:
            Dict chứa dữ liệu phân tích từ file PCAP
        """
        if not pcap_file or not os.path.exists(pcap_file):
            return None
            
        try:
            # Sử dụng PacketAnalyzer để phân tích file PCAP
            packets = self.packet_analyzer.read_pcap(pcap_file)
            if not packets:
                return None
                
            # Phân tích các gói tin và tạo dữ liệu cho biểu đồ
            data = {
                "protocol_stats": self.packet_analyzer.get_protocol_stats(packets),
                "tcp_flags": self.packet_analyzer.get_tcp_flags(packets),
                "ip_stats": self.packet_analyzer.get_ip_stats(packets),
                "arp_analysis": self.packet_analyzer.analyze_arp(packets),
                "icmp_analysis": self.packet_analyzer.analyze_icmp(packets),
                "dns_analysis": self.packet_analyzer.analyze_dns(packets),
                "dhcp_analysis": self.packet_analyzer.analyze_dhcp(packets),
                "devices": self.packet_analyzer.get_device_info(packets),
                "link_quality": self.packet_analyzer.get_link_quality(packets),
                "flows": self.packet_analyzer.get_flow_data(packets),
            }
            
            return data
        except Exception as e:
            print(f"Lỗi khi trích xuất dữ liệu từ file PCAP: {str(e)}")
            return None

    def update_dashboard(self, pcap_file, top_n, display_options):
        """
        Cập nhật tất cả các biểu đồ trong dashboard.
        
        Args:
            pcap_file: File PCAP được sử dụng
            top_n: Số lượng Top N
            display_options: Các tùy chọn hiển thị
            
        Returns:
            Tuple của các biểu đồ dashboard
        """
        # Nếu không có file PCAP, trả về biểu đồ mẫu
        if not pcap_file:
            empty_chart = self.chart_creator._create_empty_chart("Chưa có dữ liệu. Vui lòng tải lên file PCAP.")
            return empty_chart, empty_chart, empty_chart, empty_chart, empty_chart, empty_chart, empty_chart

        # Trích xuất dữ liệu từ file PCAP nếu chưa có
        if self.pcap_data is None or self.base_presenter.current_pcap_file != pcap_file:
            self.pcap_data = self.extract_pcap_data(pcap_file)
            self.base_presenter.current_pcap_file = pcap_file
            
            # Cập nhật latest_results trong base_presenter
            if self.pcap_data:
                self.base_presenter.latest_results = self.pcap_data

        # Sử dụng dữ liệu từ PCAP nếu có, nếu không sử dụng dữ liệu từ base_presenter
        data = self.pcap_data if self.pcap_data else self.base_presenter.latest_results

        # Tạo các biểu đồ từ dữ liệu phân tích
        device_status = self.chart_creator.create_device_status_chart(data)
        link_quality = self.chart_creator.create_link_quality_chart(data)
        arp_attack = self.chart_creator.create_arp_attack_chart(data)
        icmp_anomaly = self.chart_creator.create_icmp_anomaly_chart(data)
        dhcp_attack = self.chart_creator.create_dhcp_attack_chart(data)
        dns_attack = self.chart_creator.create_dns_attack_chart(data)
        top_talkers = self.chart_creator.create_top_talkers_chart(data, top_n)

        return device_status, link_quality, arp_attack, icmp_anomaly, dhcp_attack, dns_attack, top_talkers

    def update_top_n(self, pcap_file, top_n):
        """
        Cập nhật biểu đồ Top N Talkers/Chatters
        
        Args:
            pcap_file: File PCAP được sử dụng
            top_n: Số lượng Top N
            
        Returns:
            Biểu đồ Top Talkers/Chatters
        """
        # Nếu có dữ liệu từ PCAP, sử dụng nó
        if self.pcap_data:
            return self.chart_creator.create_top_talkers_chart(self.pcap_data, top_n)
        # Nếu không có dữ liệu từ PCAP nhưng có trong base_presenter
        elif self.base_presenter.latest_results:
            return self.chart_creator.create_top_talkers_chart(
                self.base_presenter.latest_results, top_n)
        # Không có dữ liệu, trả về biểu đồ trống
        return self.chart_creator._create_empty_chart("Không có dữ liệu")
