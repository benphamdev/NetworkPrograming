"""
Dashboard Presenter - Xử lý hiển thị dashboard và thống kê.
"""

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

        # Tạo các biểu đồ từ dữ liệu phân tích
        device_status = self.chart_creator.create_device_status_chart(self.base_presenter.latest_results)
        link_quality = self.chart_creator.create_link_quality_chart(self.base_presenter.latest_results)
        arp_attack = self.chart_creator.create_arp_attack_chart(self.base_presenter.latest_results)
        icmp_anomaly = self.chart_creator.create_icmp_anomaly_chart(self.base_presenter.latest_results)
        dhcp_attack = self.chart_creator.create_dhcp_attack_chart(self.base_presenter.latest_results)
        dns_attack = self.chart_creator.create_dns_attack_chart(self.base_presenter.latest_results)
        top_talkers = self.chart_creator.create_top_talkers_chart(self.base_presenter.latest_results, top_n)

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
        if self.base_presenter.latest_results:
            return self.chart_creator.create_top_talkers_chart(
                self.base_presenter.latest_results, top_n)
        return self.chart_creator._create_empty_chart("Không có dữ liệu")
