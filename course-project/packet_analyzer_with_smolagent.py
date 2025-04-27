from scapy.all import *
import sys
import matplotlib.pyplot as plt
from collections import Counter

# Hàm đọc tệp PCAP và phân tích TCP segment
def analyze_tcp_segments(pcap_file):
    print(f"[Smolagent] Đang phân tích tệp PCAP: {pcap_file}")
    
    # Đọc tệp PCAP
    packets = rdpcap(pcap_file)
    
    # Biến để lưu trữ thông tin
    syn_count = 0
    rst_count = 0
    fin_count = 0
    retransmissions = 0
    seq_numbers = {}  # Theo dõi sequence number để phát hiện retransmission
    ports = []  # Theo dõi cổng đích để phát hiện port scanning
    
    # Phân tích từng gói tin
    for pkt in packets:
        if TCP in pkt:
            tcp = pkt[TCP]
            
            # Đếm các loại flags
            if tcp.flags & 0x02:  # SYN flag
                syn_count += 1
                ports.append(tcp.dport)  # Lưu cổng đích để kiểm tra port scanning
            if tcp.flags & 0x04:  # RST flag
                rst_count += 1
            if tcp.flags & 0x01:  # FIN flag
                fin_count += 1
            
            # Phát hiện retransmission
            key = (pkt[IP].src, pkt[IP].dst, tcp.sport, tcp.dport)
            if key in seq_numbers:
                if seq_numbers[key] == tcp.seq:
                    retransmissions += 1
                else:
                    seq_numbers[key] = tcp.seq
            else:
                seq_numbers[key] = tcp.seq
    
    # Phân tích bất thường
    print("\n[Smolagent] Kết quả phân tích TCP Segment:")
    print(f"- Tổng số gói SYN: {syn_count}")
    print(f"- Tổng số gói RST: {rst_count}")
    print(f"- Tổng số gói FIN: {fin_count}")
    print(f"- Số lần retransmission: {retransmissions}")
    
    # Phát hiện SYN flood
    if syn_count > 500:  # Ngưỡng giả định
        print(f"[CẢNH BÁO] Phát hiện SYN flood: {syn_count} gói SYN!")
    
    # Phát hiện port scanning
    port_counts = Counter(ports)
    if len(port_counts) > 50:  # Nếu có quá nhiều cổng đích
        print(f"[CẢNH BÁO] Phát hiện port scanning: {len(port_counts)} cổng đích khác nhau!")
        print("Top 5 cổng đích phổ biến:", port_counts.most_common(5))
    
    # Phát hiện RST bất thường (RST không đi sau FIN)
    if rst_count > fin_count + 10:  # Ngưỡng giả định
        print(f"[CẢNH BÁO] Phát hiện RST bất thường: {rst_count} gói RST, chỉ có {fin_count} gói FIN!")
    
    # Tái tạo luồng TCP (ví dụ: nội dung HTTP)
    print("\n[Smolagent] Tái tạo luồng TCP (HTTP):")
    http_payload = ""
    for pkt in packets:
        if TCP in pkt and pkt[TCP].dport == 80 and Raw in pkt:
            http_payload += pkt[Raw].load.decode(errors='ignore')
    if http_payload:
        print("Nội dung HTTP (một phần):", http_payload[:100])  # Hiển thị 100 ký tự đầu
    else:
        print("Không tìm thấy nội dung HTTP.")
    
    # Vẽ biểu đồ phân bố gói
    labels = ['SYN', 'RST', 'FIN']
    counts = [syn_count, rst_count, fin_count]
    plt.bar(labels, counts)
    plt.title("Phân bố các loại gói TCP")
    plt.savefig("tcp_flags_distribution.png")
    print("\nBiểu đồ phân bố gói đã được lưu tại: tcp_flags_distribution.png")

# Chạy smolagent
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Cách dùng: python3 smolagent.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    analyze_tcp_segments(pcap_file)