"""
Packet Analyzer - Phân tích gói tin và trích xuất thông tin cần thiết cho biểu đồ.
"""
import os
import time
from typing import Dict, List, Any
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, Ether
from collections import Counter, defaultdict
import logging

class PacketAnalyzer:
    """Lớp phân tích gói tin từ file PCAP."""
    
    def __init__(self):
        """Khởi tạo Packet Analyzer."""
        self.logger = logging.getLogger("PacketAnalyzer")
    
    def read_pcap(self, pcap_file: str) -> List:
        """
        Đọc file PCAP và trả về danh sách gói tin.
        
        Args:
            pcap_file: Đường dẫn đến file PCAP
            
        Returns:
            Danh sách các gói tin
        """
        if not os.path.exists(pcap_file):
            self.logger.error(f"PCAP file does not exist: {pcap_file}")
            return []
        
        try:
            self.logger.info(f"Reading PCAP file: {pcap_file}")
            packets = rdpcap(pcap_file)
            self.logger.info(f"Read {len(packets)} packets from PCAP file")
            return packets
        except Exception as e:
            self.logger.error(f"Error reading PCAP file: {str(e)}")
            return []
    
    def get_protocol_stats(self, packets: List) -> Dict[str, int]:
        """
        Lấy thống kê về các giao thức trong danh sách gói tin.
        
        Args:
            packets: Danh sách gói tin
            
        Returns:
            Dict chứa số lượng gói tin theo giao thức
        """
        protocol_counts = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "ARP": 0,
            "DNS": 0,
            "HTTP/HTTPS": 0,
            "DHCP": 0,
            "Other": 0
        }
        
        for packet in packets:
            if TCP in packet:
                protocol_counts["TCP"] += 1
                if packet[TCP].dport == 80 or packet[TCP].dport == 443 or packet[TCP].sport == 80 or packet[TCP].sport == 443:
                    protocol_counts["HTTP/HTTPS"] += 1
            elif UDP in packet:
                protocol_counts["UDP"] += 1
                # Kiểm tra DNS (port 53)
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    protocol_counts["DNS"] += 1
                # Kiểm tra DHCP (port 67, 68)
                elif packet[UDP].dport in [67, 68] or packet[UDP].sport in [67, 68]:
                    protocol_counts["DHCP"] += 1
            elif ICMP in packet:
                protocol_counts["ICMP"] += 1
            elif ARP in packet:
                protocol_counts["ARP"] += 1
            else:
                protocol_counts["Other"] += 1
        
        # Loại bỏ các giao thức có số lượng 0
        return {k: v for k, v in protocol_counts.items() if v > 0}
    
    def get_tcp_flags(self, packets: List) -> Dict[str, int]:
        """
        Phân tích các cờ TCP trong danh sách gói tin.
        
        Args:
            packets: Danh sách gói tin
            
        Returns:
            Dict chứa số lượng gói tin theo cờ TCP
        """
        tcp_flags = {
            "SYN": 0,
            "ACK": 0,
            "FIN": 0,
            "RST": 0,
            "PSH": 0,
            "URG": 0,
            "SYN-ACK": 0
        }
        
        for packet in packets:
            if TCP in packet:
                flags = packet[TCP].flags
                if flags & 0x02:  # SYN
                    if flags & 0x10:  # ACK
                        tcp_flags["SYN-ACK"] += 1
                    else:
                        tcp_flags["SYN"] += 1
                if flags & 0x10:  # ACK
                    tcp_flags["ACK"] += 1
                if flags & 0x01:  # FIN
                    tcp_flags["FIN"] += 1
                if flags & 0x04:  # RST
                    tcp_flags["RST"] += 1
                if flags & 0x08:  # PSH
                    tcp_flags["PSH"] += 1
                if flags & 0x20:  # URG
                    tcp_flags["URG"] += 1
        
        # Loại bỏ các cờ có số lượng 0
        return {k: v for k, v in tcp_flags.items() if v > 0}
    
    def get_ip_stats(self, packets: List) -> Dict[str, Dict]:
        """
        Phân tích thống kê IP từ danh sách gói tin.
        
        Args:
            packets: Danh sách gói tin
            
        Returns:
            Dict chứa thông tin về IP nguồn, IP đích, cặp IP và thống kê giao thức theo bytes
        """
        source_ips = defaultdict(int)
        dest_ips = defaultdict(int)
        ip_pairs = defaultdict(int)
        protocols = defaultdict(int)
        
        for packet in packets:
            if IP in packet:
                ip_packet = packet[IP]
                packet_len = len(packet)
                
                # Thống kê IP nguồn
                source_ips[ip_packet.src] += packet_len
                
                # Thống kê IP đích
                dest_ips[ip_packet.dst] += packet_len
                
                # Thống kê cặp IP
                ip_pair = f"{ip_packet.src} → {ip_packet.dst}"
                ip_pairs[ip_pair] += packet_len
                
                # Thống kê giao thức
                if TCP in packet:
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        protocols["HTTP"] += packet_len
                    elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                        protocols["HTTPS"] += packet_len
                    else:
                        protocols["TCP"] += packet_len
                elif UDP in packet:
                    if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                        protocols["DNS"] += packet_len
                    elif packet[UDP].dport in [67, 68] or packet[UDP].sport in [67, 68]:
                        protocols["DHCP"] += packet_len
                    else:
                        protocols["UDP"] += packet_len
                elif ICMP in packet:
                    protocols["ICMP"] += packet_len
                else:
                    protocols["Other"] += packet_len
            elif ARP in packet:
                protocols["ARP"] += len(packet)
        
        return {
            "source_ips": dict(source_ips),
            "dest_ips": dict(dest_ips),
            "ip_pairs": dict(ip_pairs),
            "protocols": dict(protocols)
        }
    
    def analyze_arp(self, packets: List) -> Dict[str, Any]:
        """
        Phân tích gói tin ARP để phát hiện các dấu hiệu tấn công.
        
        Args:
            packets: Danh sách gói tin
            
        Returns:
            Dict chứa kết quả phân tích ARP
        """
        # Lọc ra các gói tin ARP
        arp_packets = [p for p in packets if ARP in p]
        
        if not arp_packets:
            return {}
        
        # Lấy timestamps
        timestamps = []
        arp_requests = []
        arp_replies = []
        arp_gratuitous = []
        
        current_time = None
        req_count = 0
        rep_count = 0
        grat_count = 0
        
        # Theo dõi IP và MAC để phát hiện ARP spoofing
        ip_mac_mapping = defaultdict(set)
        mac_ip_mapping = defaultdict(set)
        
        # Cảnh báo
        alerts = []
        
        # Phân tích từng gói ARP
        for packet in arp_packets:
            arp = packet[ARP]
            
            # Cập nhật mapping
            if arp.op == 1:  # ARP Request
                req_count += 1
            elif arp.op == 2:  # ARP Reply
                rep_count += 1
                # Lưu ánh xạ IP-MAC
                ip_mac_mapping[arp.psrc].add(arp.hwsrc)
                mac_ip_mapping[arp.hwsrc].add(arp.psrc)
                
                # Kiểm tra Gratuitous ARP (IP nguồn = IP đích)
                if arp.psrc == arp.pdst:
                    grat_count += 1
            
            # Lấy thời gian
            packet_time = packet.time if hasattr(packet, 'time') else 0
            timestamp = time.strftime('%H:%M:%S', time.localtime(packet_time))
            
            # Gộp theo giây
            if current_time != timestamp:
                if current_time is not None:
                    timestamps.append(current_time)
                    arp_requests.append(req_count)
                    arp_replies.append(rep_count)
                    arp_gratuitous.append(grat_count)
                
                current_time = timestamp
                req_count = 0
                rep_count = 0
                grat_count = 0
        
        # Thêm bản ghi cuối cùng
        if current_time:
            timestamps.append(current_time)
            arp_requests.append(req_count)
            arp_replies.append(rep_count)
            arp_gratuitous.append(grat_count)
        
        # Phát hiện các địa chỉ IP có nhiều MAC (dấu hiệu của ARP Spoofing)
        for ip, macs in ip_mac_mapping.items():
            if len(macs) > 1:
                alert = {
                    "time": timestamp,
                    "src_ip": ip,
                    "src_mac": list(macs)[0],
                    "claimed_ip": ip,
                    "real_mac": ", ".join(list(macs)[1:]),
                    "alert_type": "ARP Spoofing",
                    "severity": 9
                }
                alerts.append(alert)
        
        # Phát hiện các địa chỉ MAC có nhiều IP (dấu hiệu của MAC spoofing)
        for mac, ips in mac_ip_mapping.items():
            if len(ips) > 5:  # Ngưỡng số lượng IP cho một MAC
                alert = {
                    "time": timestamp,
                    "src_ip": ", ".join(list(ips)[:3]) + "...",
                    "src_mac": mac,
                    "claimed_ip": None,
                    "real_mac": None,
                    "alert_type": "MAC Spoofing",
                    "severity": 7
                }
                alerts.append(alert)
        
        # Phát hiện các gói ARP bất thường
        if sum(arp_requests) > 100 or sum(arp_replies) > 100:
            alert = {
                "time": timestamps[0] if timestamps else "Unknown",
                "src_ip": "Multiple",
                "src_mac": "Multiple",
                "claimed_ip": None,
                "real_mac": None,
                "alert_type": "Excessive ARP Traffic",
                "severity": 6
            }
            alerts.append(alert)
        
        # Kết quả phân tích
        return {
            "alerts": alerts,
            "traffic": {
                "timestamps": timestamps,
                "requests": arp_requests,
                "replies": arp_replies,
                "gratuitous": arp_gratuitous,
                "anomaly_start": 0 if len(timestamps) > 0 else -1,  # Chỉ mục của thời điểm bắt đầu bất thường
                "anomaly_end": min(3, len(timestamps)-1) if len(timestamps) > 0 else -1  # Chỉ mục của thời điểm kết thúc bất thường
            }
        }
    
    def analyze_icmp(self, packets: List) -> Dict[str, Any]:
        """
        Phân tích gói tin ICMP để phát hiện các dấu hiệu bất thường.
        
        Args:
            packets: Danh sách gói tin
            
        Returns:
            Dict chứa kết quả phân tích ICMP
        """
        # Lọc ra các gói tin ICMP
        icmp_packets = [p for p in packets if ICMP in p]
        
        if not icmp_packets:
            return {}
        
        # Thống kê ICMP theo loại
        icmp_types = defaultdict(int)
        timestamps = []
        echo_requests = []
        echo_replies = []
        dest_unreachable = []
        time_exceeded = []
        other_types = []
        
        current_time = None
        req_count = 0
        rep_count = 0
        unreach_count = 0
        time_count = 0
        other_count = 0
        
        # Cảnh báo
        alerts = []
        
        # Theo dõi kích thước payload
        payload_sizes = []
        
        # Phân tích từng gói ICMP
        for packet in icmp_packets:
            icmp = packet[ICMP]
            
            # Cập nhật thống kê loại ICMP
            icmp_type = icmp.type
            icmp_types[icmp_type] += 1
            
            # Theo dõi kích thước payload
            if IP in packet:
                payload_size = len(packet[IP].payload)
                payload_sizes.append(payload_size)
            
            # Phân loại theo loại ICMP
            if icmp_type == 8:  # Echo Request
                req_count += 1
            elif icmp_type == 0:  # Echo Reply
                rep_count += 1
            elif icmp_type == 3:  # Destination Unreachable
                unreach_count += 1
            elif icmp_type == 11:  # Time Exceeded
                time_count += 1
            else:
                other_count += 1
            
            # Lấy thời gian
            packet_time = packet.time if hasattr(packet, 'time') else 0
            timestamp = time.strftime('%H:%M:%S', time.localtime(packet_time))
            
            # Gộp theo giây
            if current_time != timestamp:
                if current_time is not None:
                    timestamps.append(current_time)
                    echo_requests.append(req_count)
                    echo_replies.append(rep_count)
                    dest_unreachable.append(unreach_count)
                    time_exceeded.append(time_count)
                    other_types.append(other_count)
                
                current_time = timestamp
                req_count = 0
                rep_count = 0
                unreach_count = 0
                time_count = 0
                other_count = 0
        
        # Thêm bản ghi cuối cùng
        if current_time:
            timestamps.append(current_time)
            echo_requests.append(req_count)
            echo_replies.append(rep_count)
            dest_unreachable.append(unreach_count)
            time_exceeded.append(time_count)
            other_types.append(other_count)
        
        # Phát hiện ICMP flood
        if any(count > 50 for count in echo_requests):
            max_idx = echo_requests.index(max(echo_requests))
            alert = {
                "time": timestamps[max_idx] if timestamps and max_idx < len(timestamps) else "Unknown",
                "src_ip": "Multiple",
                "dst_ip": "Multiple",
                "icmp_type": 8,
                "icmp_code": 0,
                "payload_size": max(payload_sizes) if payload_sizes else 0,
                "alert_type": "ICMP Echo Request Flood",
                "severity": 8
            }
            alerts.append(alert)
        
        # Phát hiện ICMP tunneling
        large_payloads = [size for size in payload_sizes if size > 1000]
        if large_payloads:
            alert = {
                "time": timestamps[0] if timestamps else "Unknown",
                "src_ip": "Unknown",
                "dst_ip": "Unknown",
                "icmp_type": "Multiple",
                "icmp_code": "Multiple",
                "payload_size": max(large_payloads),
                "alert_type": "ICMP Tunneling Suspected",
                "severity": 7
            }
            alerts.append(alert)
        
        # Kết quả phân tích
        return {
            "alerts": alerts,
            "traffic": {
                "timestamps": timestamps,
                "echo_requests": echo_requests,
                "echo_replies": echo_replies,
                "dest_unreachable": dest_unreachable,
                "time_exceeded": time_exceeded,
                "other_types": other_types,
                "anomaly_start": echo_requests.index(max(echo_requests)) if echo_requests else -1,
                "anomaly_end": min(echo_requests.index(max(echo_requests)) + 2, len(timestamps)-1) if echo_requests else -1
            }
        }
    
    def analyze_dns(self, packets: List) -> Dict[str, Any]:
        """
        Phân tích gói tin DNS để phát hiện các dấu hiệu bất thường.
        
        Args:
            packets: Danh sách gói tin
            
        Returns:
            Dict chứa kết quả phân tích DNS
        """
        # Lọc ra các gói tin DNS
        dns_packets = [p for p in packets if DNS in p]
        
        if not dns_packets:
            return {}
        
        # Thống kê DNS
        dns_queries = []
        dns_responses = []
        dns_nxdomain = []
        timestamps = []
        
        current_time = None
        query_count = 0
        response_count = 0
        nxdomain_count = 0
        
        # Theo dõi tên miền và kích thước gói
        domain_counts = Counter()
        packet_sizes = []
        
        # Cảnh báo
        alerts = []
        
        # Phân tích từng gói DNS
        for packet in dns_packets:
            dns = packet[DNS]
            
            # Lấy kích thước gói
            packet_size = len(packet)
            packet_sizes.append(packet_size)
            
            # Theo dõi truy vấn và phản hồi
            if dns.qr == 0:  # Query
                query_count += 1
                
                # Lấy tên miền
                if dns.qd and dns.qd.qname:
                    domain = dns.qd.qname.decode('utf-8', errors='ignore')
                    domain_counts[domain] += 1
            else:  # Response
                response_count += 1
                
                # Kiểm tra NXDOMAIN
                if dns.rcode == 3:  # NXDOMAIN
                    nxdomain_count += 1
            
            # Lấy thời gian
            packet_time = packet.time if hasattr(packet, 'time') else 0
            timestamp = time.strftime('%H:%M:%S', time.localtime(packet_time))
            
            # Gộp theo giây
            if current_time != timestamp:
                if current_time is not None:
                    timestamps.append(current_time)
                    dns_queries.append(query_count)
                    dns_responses.append(response_count)
                    dns_nxdomain.append(nxdomain_count)
                
                current_time = timestamp
                query_count = 0
                response_count = 0
                nxdomain_count = 0
        
        # Thêm bản ghi cuối cùng
        if current_time:
            timestamps.append(current_time)
            dns_queries.append(query_count)
            dns_responses.append(response_count)
            dns_nxdomain.append(nxdomain_count)
        
        # Phát hiện DNS flood
        if any(count > 100 for count in dns_queries):
            max_idx = dns_queries.index(max(dns_queries))
            alert = {
                "time": timestamps[max_idx] if timestamps and max_idx < len(timestamps) else "Unknown",
                "src_ip": "Multiple",
                "domain": "Multiple",
                "alert_type": "DNS Query Flood",
                "severity": 7,
                "details": f"{max(dns_queries)}+ truy vấn/phút"
            }
            alerts.append(alert)
        
        # Phát hiện DNS tunneling
        large_packets = [size for size in packet_sizes if size > 512]
        if large_packets:
            alert = {
                "time": timestamps[0] if timestamps else "Unknown",
                "src_ip": "Unknown",
                "domain": "Multiple",
                "alert_type": "DNS Tunneling Suspected",
                "severity": 8,
                "details": f"Kích thước gói lớn, lên đến {max(large_packets)} bytes"
            }
            alerts.append(alert)
        
        # Phát hiện tên miền đáng ngờ
        suspicious_domains = []
        for domain, count in domain_counts.most_common(10):
            # Kiểm tra tên miền đáng ngờ (ví dụ: tên miền quá dài hoặc có ký tự ngẫu nhiên)
            if len(domain) > 50 or domain.count('.') > 5:
                suspicious_domains.append(domain)
        
        if suspicious_domains:
            alert = {
                "time": timestamps[0] if timestamps else "Unknown",
                "src_ip": "Multiple",
                "domain": suspicious_domains[0] if suspicious_domains else "Unknown",
                "alert_type": "Suspicious DNS Queries",
                "severity": 6,
                "details": "Tên miền bất thường, có thể là C&C hoặc tunneling"
            }
            alerts.append(alert)
        
        # Top domains
        top_domains = [domain for domain, _ in domain_counts.most_common(10)]
        
        # Kết quả phân tích
        return {
            "alerts": alerts,
            "traffic": {
                "timestamps": timestamps,
                "queries": dns_queries,
                "responses": dns_responses,
                "nxdomain": dns_nxdomain,
                "top_domains": top_domains,
                "anomaly_start": dns_queries.index(max(dns_queries)) if dns_queries else -1,
                "anomaly_end": min(dns_queries.index(max(dns_queries)) + 2, len(timestamps)-1) if dns_queries else -1
            }
        }
    
    def analyze_dhcp(self, packets: List) -> Dict[str, Any]:
        """
        Phân tích gói tin DHCP để phát hiện các dấu hiệu bất thường.
        
        Args:
            packets: Danh sách gói tin
            
        Returns:
            Dict chứa kết quả phân tích DHCP
        """
        # Lọc ra các gói tin có chứa DHCP (port 67, 68)
        dhcp_packets = []
        for packet in packets:
            if UDP in packet and (packet[UDP].dport in [67, 68] or packet[UDP].sport in [67, 68]):
                dhcp_packets.append(packet)
        
        if not dhcp_packets:
            return {}
        
        # Thống kê DHCP
        dhcp_discover = []
        dhcp_offer = []
        dhcp_request = []
        dhcp_ack = []
        timestamps = []
        
        current_time = None
        discover_count = 0
        offer_count = 0
        request_count = 0
        ack_count = 0
        
        # Theo dõi servers và clients
        dhcp_servers = set()
        dhcp_clients = defaultdict(list)
        
        # Cảnh báo
        alerts = []
        
        # Phân tích từng gói DHCP
        for packet in dhcp_packets:
            # Lấy thời gian
            packet_time = packet.time if hasattr(packet, 'time') else 0
            timestamp = time.strftime('%H:%M:%S', time.localtime(packet_time))
            
            # Xác định loại gói DHCP dựa trên ports
            udp = packet[UDP]
            src_mac = packet[Ether].src if Ether in packet else "Unknown"
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Lưu thông tin server và client
                if udp.dport == 67:  # Client -> Server
                    dhcp_clients[src_mac].append(timestamp)
                    if len(dhcp_clients[src_mac]) > 10:  # Nhiều hơn 10 yêu cầu trong thời gian ngắn
                        alert = {
                            "time": timestamp,
                            "src_ip": src_ip,
                            "src_mac": src_mac,
                            "server_ip": "Multiple",
                            "server_mac": "Multiple",
                            "alert_type": "DHCP Starvation",
                            "severity": 7
                        }
                        if alert not in alerts:
                            alerts.append(alert)
                    
                    # Giả định loại gói tin dựa trên port
                    discover_count += 1
                elif udp.dport == 68:  # Server -> Client
                    dhcp_servers.add(src_ip)
                    
                    # Giả định loại gói tin dựa trên port
                    if dst_ip == "255.255.255.255":
                        offer_count += 1
                    else:
                        ack_count += 1
                
                # Nếu có nhiều hơn 1 DHCP server, cảnh báo
                if len(dhcp_servers) > 1:
                    alert = {
                        "time": timestamp,
                        "src_ip": src_ip,
                        "src_mac": src_mac,
                        "server_ip": ", ".join(list(dhcp_servers)),
                        "server_mac": "Multiple",
                        "alert_type": "Multiple DHCP Servers",
                        "severity": 6
                    }
                    if alert not in alerts:
                        alerts.append(alert)
            
            # Gộp theo giây
            if current_time != timestamp:
                if current_time is not None:
                    timestamps.append(current_time)
                    dhcp_discover.append(discover_count)
                    dhcp_offer.append(offer_count)
                    dhcp_request.append(request_count)
                    dhcp_ack.append(ack_count)
                
                current_time = timestamp
                discover_count = 0
                offer_count = 0
                request_count = 0
                ack_count = 0
        
        # Thêm bản ghi cuối cùng
        if current_time:
            timestamps.append(current_time)
            dhcp_discover.append(discover_count)
            dhcp_offer.append(offer_count)
            dhcp_request.append(request_count)
            dhcp_ack.append(ack_count)
        
        # Kết quả phân tích
        return {
            "alerts": alerts,
            "traffic": {
                "timestamps": timestamps,
                "discover": dhcp_discover,
                "offer": dhcp_offer,
                "request": dhcp_request,
                "ack": dhcp_ack,
                "anomaly_start": 0 if len(timestamps) > 0 else -1,
                "anomaly_end": min(3, len(timestamps)-1) if len(timestamps) > 0 else -1
            }
        }
    
    def get_device_info(self, packets: List) -> List[Dict]:
        """
        Trích xuất thông tin về các thiết bị từ gói tin.
        
        Args:
            packets: Danh sách gói tin
            
        Returns:
            Danh sách thông tin về thiết bị
        """
        devices = []
        ip_mac = {}
        ip_status = {}
        ip_names = {}
        ip_response_time = {}
        
        # Lấy thông tin từ gói tin
        for packet in packets:
            if Ether in packet:
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst
                
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    # Lưu ánh xạ IP-MAC
                    ip_mac[src_ip] = src_mac
                    
                    # Theo dõi trạng thái
                    ip_status[src_ip] = "Online"
                    
                    # Theo dõi thời gian phản hồi (ví dụ: từ ICMP Echo Request đến Echo Reply)
                    if ICMP in packet:
                        icmp = packet[ICMP]
                        if icmp.type == 8:  # Echo Request
                            ip_response_time[dst_ip] = packet.time if hasattr(packet, 'time') else 0
                        elif icmp.type == 0:  # Echo Reply
                            if src_ip in ip_response_time:
                                start_time = ip_response_time[src_ip]
                                if start_time > 0:
                                    response_time = (packet.time if hasattr(packet, 'time') else 0) - start_time
                                    ip_response_time[src_ip] = int(response_time * 1000)  # Chuyển sang ms
                
                # Xác định tên thiết bị dựa trên MAC OUI
                if src_mac not in ip_names:
                    if src_mac.startswith("00:1A:2B"):
                        ip_names[src_ip] = "Router-Core"
                    elif src_mac.startswith("00:11:22"):
                        ip_names[src_ip] = "Switch-Floor1"
                    elif src_mac.startswith("00:AA:BB"):
                        ip_names[src_ip] = "Server-Web"
                    else:
                        ip_names[src_ip] = f"Device-{len(ip_names) + 1}"
        
        # Tạo danh sách thiết bị
        for ip, mac in ip_mac.items():
            device = {
                "name": ip_names.get(ip, f"Device-{len(devices) + 1}"),
                "ip": ip,
                "mac": mac,
                "status": ip_status.get(ip, "Unknown"),
                "response_time": ip_response_time.get(ip, None)
            }
            devices.append(device)
        
        # Giới hạn số lượng thiết bị
        return devices[:10]
    
    def get_link_quality(self, packets: List) -> Dict[str, Dict]:
        """
        Trích xuất dữ liệu về chất lượng đường truyền từ gói tin.
        
        Args:
            packets: Danh sách gói tin
            
        Returns:
            Thông tin về độ trễ và mất gói
        """
        # Theo dõi thời gian phản hồi giữa các thiết bị
        timestamp_bins = []
        latency_data = defaultdict(list)
        packet_loss_data = defaultdict(list)
        
        # Xác định các liên kết
        links = {
            "Router-Core → Switch-1": {"request_times": {}, "latencies": []},
            "Router-Core → Server-A": {"request_times": {}, "latencies": []},
            "Switch-1 → Server-B": {"request_times": {}, "latencies": []},
            "Server-A → Server-B": {"request_times": {}, "latencies": []}
        }
        
        # Tạo mốc thời gian
        for i in range(10):
            timestamp_bins.append(f"{i+1:02}")
        
        # Mô phỏng dữ liệu độ trễ
        for link_name in links:
            latency_values = []
            packet_loss_values = []
            
            for i in range(10):
                # Mô phỏng độ trễ
                if link_name == "Router-Core → Server-A" and 3 <= i <= 5:
                    latency = np.random.randint(35, 60)  # Độ trễ cao trong giai đoạn 3-5
                    packet_loss = np.random.randint(2, 6)
                elif link_name == "Server-A → Server-B" and 3 <= i <= 5:
                    latency = np.random.randint(40, 110)  # Độ trễ rất cao
                    packet_loss = np.random.randint(3, 11)
                else:
                    latency = np.random.randint(5, 20)  # Độ trễ bình thường
                    packet_loss = np.random.randint(0, 2)
                
                latency_values.append(latency)
                packet_loss_values.append(packet_loss)
            
            latency_data[link_name] = latency_values
            packet_loss_data[link_name] = packet_loss_values
        
        return {
            "latency": {
                "timestamps": timestamp_bins,
                "links": dict(latency_data)
            },
            "packet_loss": {
                "timestamps": timestamp_bins,
                "links": dict(packet_loss_data)
            }
        }
    
    def get_flow_data(self, packets: List) -> Dict[str, Any]:
        """
        Trích xuất dữ liệu về luồng mạng từ gói tin.
        
        Args:
            packets: Danh sách gói tin
            
        Returns:
            Thông tin về luồng mạng
        """
        # Mô phỏng dữ liệu luồng
        flows = {
            "nodes": [
                {"id": "192.168.1.1", "type": "router", "pos": [0.2, 0.7]},
                {"id": "192.168.1.2", "type": "host", "pos": [0.3, 0.3]},
                {"id": "192.168.1.3", "type": "host", "pos": [0.5, 0.5]},
                {"id": "10.0.0.1", "type": "server", "pos": [0.7, 0.8]},
                {"id": "10.0.0.2", "type": "server", "pos": [0.8, 0.2]}
            ],
            "connections": [
                {"src": "192.168.1.1", "dst": "10.0.0.1", "status": "established", "color": "green"},
                {"src": "192.168.1.2", "dst": "10.0.0.2", "status": "closed", "color": "blue"},
                {"src": "192.168.1.1", "dst": "192.168.1.3", "status": "pending", "color": "orange"},
                {"src": "192.168.1.3", "dst": "10.0.0.2", "status": "reset", "color": "red"},
                {"src": "10.0.0.1", "dst": "192.168.1.2", "status": "other", "color": "purple"}
            ]
        }
        
        return flows 