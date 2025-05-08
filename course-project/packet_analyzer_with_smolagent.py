import sys
import matplotlib.pyplot as plt
from collections import Counter, defaultdict
from scapy.all import *
import subprocess
import re
import networkx as nx

# Import smolagents và các thành phần liên quan
from smolagents import (
    ToolCallingAgent,
    DuckDuckGoSearchTool,
    VisitWebpageTool,
    LiteLLMModel,
)
from dotenv import load_dotenv
import os

# Thiết lập môi trường và DeepSeek API
load_dotenv()
apikey = os.getenv("DEEPSEEK_API_KEY")
if not apikey:
    raise ValueError("Set DEEPSEEK_API_KEY in your .env file")

# Đăng ký và khởi tạo instrumentation
# register()
# SmolagentsInstrumentor().instrument()

# Khởi tạo model DeepSeek
model = LiteLLMModel(
    model_id="deepseek/deepseek-chat",
    api_key=apikey,
    messages=[
        {
            "role": "system",
            "content": "You are a helpful AI assistant capable of using tools to perform tasks. "
            "When given a query, analyze it and use available tools to gather information. "
            "Return JSON responses when possible.",
        }
    ],
    temperature=0.1,
    max_tokens=512,
    top_p=0.9,
    top_k=50,
    frequency_penalty=0.0,
    presence_penalty=0.0,
    stream=False,
    request_timeout=60,
)

# Khởi tạo search_agent để tìm kiếm thông tin
search_agent = ToolCallingAgent(
    tools=[DuckDuckGoSearchTool(), VisitWebpageTool()],
    model=model,
    name="search_agent",
    description="This is an agent that can do web search.",
)

# Khởi tạo manager_agent để quản lý và phân tích
manager_agent = ToolCallingAgent(
    tools=[],
    model=model,
    name="analyst_agent",
    description="This is an agent that analyzes network traffic patterns.",
)

# Hàm chạy lệnh tcpdump và ghi lại lưu lượng
def capture_tcp_traffic(interface="eth0", output_file="tcp_capture.pcap", port=None):
    print(f"[tcpdump] Ghi lại lưu lượng TCP trên giao diện {interface}...")
    cmd = ["sudo", "tcpdump", "-i", interface, "tcp"]
    if port:
        cmd.extend(["port", str(port)])
    cmd.extend(["-w", output_file])
    try:
        subprocess.run(cmd, timeout=10)  # Ghi trong 10 giây
    except subprocess.TimeoutExpired:
        print("[tcpdump] Dừng ghi lưu lượng.")
    return output_file

# Hàm phân tích TCP segment bằng tcpdump
def analyze_with_tcpdump(pcap_file):
    print(f"[tcpdump] Phân tích tệp PCAP: {pcap_file}")
    
    # Đếm gói SYN
    cmd_syn = f"tcpdump -r {pcap_file} 'tcp[tcpflags] & tcp-syn != 0' | wc -l"
    syn_count = int(subprocess.check_output(cmd_syn, shell=True).decode().strip())
    
    # Đếm gói RST
    cmd_rst = f"tcpdump -r {pcap_file} 'tcp[tcpflags] & tcp-rst != 0' | wc -l"
    rst_count = int(subprocess.check_output(cmd_rst, shell=True).decode().strip())
    
    # Đếm gói FIN
    cmd_fin = f"tcpdump -r {pcap_file} 'tcp[tcpflags] & tcp-fin != 0' | wc -l"
    fin_count = int(subprocess.check_output(cmd_fin, shell=True).decode().strip())
    
    return {"syn_count": syn_count, "rst_count": rst_count, "fin_count": fin_count}

# Hàm phân tích TCP segment bằng Scapy (bổ sung cho smolagent)
def analyze_tcp_segments_with_scapy(pcap_file):
    print(f"[Smolagent] Phân tích TCP Segment với Scapy: {pcap_file}")
    
    packets = rdpcap(pcap_file)
    syn_count = 0
    rst_count = 0
    fin_count = 0
    retransmissions = 0
    seq_numbers = {}
    ports = []
    
    for pkt in packets:
        if TCP in pkt:
            tcp = pkt[TCP]
            if tcp.flags & 0x02:  # SYN
                syn_count += 1
                ports.append(tcp.dport)
            if tcp.flags & 0x04:  # RST
                rst_count += 1
            if tcp.flags & 0x01:  # FIN
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
    
    return {
        "syn_count": syn_count,
        "rst_count": rst_count,
        "fin_count": fin_count,
        "retransmissions": retransmissions,
        "ports": ports
    }

# Parse tcpdump output for detailed analysis
def parse_tcpdump_output(pcap_file):
    print(f"[tcpdump] Parsing tcpdump output for {pcap_file}")
    cmd = f"tcpdump -r {pcap_file} -n"
    result = subprocess.check_output(cmd, shell=True).decode('utf-8', errors='ignore')
    
    # Store connections and their states
    connections = defaultdict(list)
    http_transactions = []
    
    # Parse each line of tcpdump output
    for line in result.splitlines():
        # Skip non-data lines
        if not line or line.startswith('reading from'):
            continue
            
        # Extract timestamp
        timestamp_match = re.search(r'^(\d+:\d+:\d+\.\d+)', line)
        if not timestamp_match:
            continue
        timestamp = timestamp_match.group(1)
            
        # Extract IP addresses and ports
        ip_port_pattern = r'IP (\d+\.\d+\.\d+\.\d+)\.(\w+) > (\d+\.\d+\.\d+\.\d+)\.(\w+)'
        alt_ip_port_pattern = r'IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\w+)'
        
        ip_match = re.search(ip_port_pattern, line) or re.search(alt_ip_port_pattern, line)
        if not ip_match:
            continue
            
        src_ip = ip_match.group(1)
        src_port = ip_match.group(2)
        dst_ip = ip_match.group(3)
        dst_port = ip_match.group(4)
        
        # Extract TCP flags
        flags_match = re.search(r'Flags \[([^\]]+)\]', line)
        if not flags_match:
            continue
        flags = flags_match.group(1)
        
        # Extract sequence and ack numbers
        seq_match = re.search(r'seq (\d+)(?::(\d+))?', line)
        seq = seq_match.group(1) if seq_match else "N/A"
        if seq_match and seq_match.group(2):  # Range of sequence numbers
            payload_len = int(seq_match.group(2)) - int(seq_match.group(1))
        else:
            payload_len_match = re.search(r'length (\d+)', line)
            payload_len = int(payload_len_match.group(1)) if payload_len_match else 0
            
        ack_match = re.search(r'ack (\d+)', line)
        ack = ack_match.group(1) if ack_match else "N/A"
        
        # Extract HTTP content if present
        http_match = re.search(r'HTTP: (.+)', line)
        http_content = http_match.group(1) if http_match else None
        
        # Create connection key
        conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        
        # Store connection info
        connections[conn_key].append({
            'timestamp': timestamp,
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'flags': flags,
            'seq': seq,
            'ack': ack,
            'payload_len': payload_len,
            'http_content': http_content
        })
        
        # Track HTTP transactions
        if http_content:
            http_transactions.append({
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'content': http_content,
                'conn_key': conn_key
            })
    
    return {
        'connections': connections,
        'http_transactions': http_transactions
    }

# Analyze TCP flows from parsed data
def analyze_tcp_flows(parsed_data):
    connections = parsed_data['connections']
    flows = {}
    
    for conn_key, packets in connections.items():
        src_ip, src_port = packets[0]['src_ip'], packets[0]['src_port']
        dst_ip, dst_port = packets[0]['dst_ip'], packets[0]['dst_port']
        
        # Analyze connection establishment
        handshake_completed = False
        syn_sent = False
        syn_ack_sent = False
        
        # Track retransmissions
        seq_numbers = set()
        retransmissions = 0
        
        # Analyze completion
        fin_sent = 0
        rst_sent = 0
        
        for packet in packets:
            flags = packet['flags']
            
            # Check for handshake steps
            if 'S' in flags and not '.' in flags:  # SYN
                syn_sent = True
            elif 'S' in flags and '.' in flags:  # SYN-ACK
                syn_ack_sent = True
            elif '.' in flags and not 'S' in flags and syn_sent and syn_ack_sent:
                handshake_completed = True
                
            # Check for connection termination
            if 'F' in flags:
                fin_sent += 1
            if 'R' in flags:
                rst_sent += 1
                
            # Check for retransmissions
            seq_number = packet['seq']
            if seq_number in seq_numbers and seq_number != "N/A":
                retransmissions += 1
            else:
                seq_numbers.add(seq_number)
                
        # Determine connection state
        if handshake_completed:
            if fin_sent >= 2:
                state = "Properly Closed"
            elif rst_sent > 0:
                state = "Reset"
            else:
                state = "Established"
        else:
            state = "Incomplete Handshake"
            
        # Store flow info
        flows[conn_key] = {
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'state': state,
            'packet_count': len(packets),
            'retransmissions': retransmissions,
            'handshake_completed': handshake_completed,
            'rst_count': rst_sent,
            'fin_count': fin_sent
        }
        
    return flows

# Visualize TCP flows as a graph
def visualize_tcp_flows(flows):
    G = nx.DiGraph()
    
    # Add nodes and edges for each connection
    for conn_key, flow in flows.items():
        src = f"{flow['src_ip']}:{flow['src_port']}"
        dst = f"{flow['dst_ip']}:{flow['dst_port']}"
        
        G.add_node(src, ip=flow['src_ip'], port=flow['src_port'])
        G.add_node(dst, ip=flow['dst_ip'], port=flow['dst_port'])
        G.add_edge(src, dst, state=flow['state'], packets=flow['packet_count'])
    
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G)
    
    # Draw nodes
    nx.draw_networkx_nodes(G, pos, node_size=300, alpha=0.8)
    
    # Draw edges with different colors based on state
    edge_colors = []
    for _, _, attrs in G.edges(data=True):
        if attrs['state'] == "Established":
            edge_colors.append('green')
        elif attrs['state'] == "Properly Closed":
            edge_colors.append('blue')
        elif attrs['state'] == "Reset":
            edge_colors.append('red')
        else:
            edge_colors.append('yellow')
    
    nx.draw_networkx_edges(G, pos, width=1.0, alpha=0.5, edge_color=edge_colors)
    
    nx.draw_networkx_labels(G, pos)
    
    plt.title('TCP Connection Flow Graph')
    plt.axis('off')
    plt.savefig("tcp_flow_graph.png", dpi=300, bbox_inches='tight')
    print("\nTCP flow graph saved to: tcp_flow_graph.png")
    
    return G

# Enhance the smolagent_with_deepseek function
def smolagent_with_deepseek(pcap_file):
    # Bước 1: Phân tích TCP segment bằng tcpdump
    tcpdump_results = analyze_with_tcpdump(pcap_file)
    
    # Bước 2: Phân tích TCP segment bằng Scapy
    scapy_results = analyze_tcp_segments_with_scapy(pcap_file)
    
    # Bước 3: Parse tcpdump output for detailed analysis
    parsed_data = parse_tcpdump_output(pcap_file)
    
    # Bước 4: Analyze TCP flows
    flows = analyze_tcp_flows(parsed_data)
    
    # Print HTTP transactions
    if parsed_data['http_transactions']:
        print("\n--- HTTP Transactions ---")
        for idx, http in enumerate(parsed_data['http_transactions']):
            print(f"{idx+1}. {http['timestamp']} {http['src_ip']} → {http['dst_ip']}: {http['content']}")
    
    # Print flow statistics
    print("\n--- TCP Flow Statistics ---")
    established_count = sum(1 for flow in flows.values() if flow['state'] == "Established")
    reset_count = sum(1 for flow in flows.values() if flow['state'] == "Reset")
    incomplete_count = sum(1 for flow in flows.values() if flow['state'] == "Incomplete Handshake")
    closed_count = sum(1 for flow in flows.values() if flow['state'] == "Properly Closed")
    
    print(f"Total Connections: {len(flows)}")
    print(f"Established: {established_count}")
    print(f"Properly Closed: {closed_count}")
    print(f"Reset: {reset_count}")
    print(f"Incomplete Handshakes: {incomplete_count}")
    
    # Bước 5: Phát hiện bất thường
    syn_count = scapy_results["syn_count"]
    rst_count = scapy_results["rst_count"]
    fin_count = scapy_results["fin_count"]
    retransmissions = scapy_results["retransmissions"]
    port_counts = Counter(scapy_results["ports"])
    
    anomalies = []
    if syn_count > 500:
        anomalies.append(f"SYN flood: {syn_count} gói SYN")
    if rst_count > fin_count + 10:
        anomalies.append(f"RST bất thường: {rst_count} gói RST, chỉ có {fin_count} gói FIN")
    if len(port_counts) > 50:
        anomalies.append(f"Port scanning: {len(port_counts)} cổng đích khác nhau")
    
    # Dùng manager_agent để phân tích sâu và tìm kiếm thông tin
    analysis_query = (
        f"Phân tích kết quả: {syn_count} gói SYN, {rst_count} gói RST, {fin_count} gói FIN, "
        f"{retransmissions} lần retransmission. Có các bất thường: {', '.join(anomalies) if anomalies else 'Không có'}. "
        "Đề xuất cách xử lý các bất thường này."
    )
    print(f"[Smolagent] Gửi truy vấn tới manager_agent: {analysis_query}")
    
    deepseek_response = manager_agent.run(analysis_query)
    print(f"[DeepSeek Response] {deepseek_response}")
    
    # Bước 6: Visualize TCP flows
    visualize_tcp_flows(flows)
    
    # Bước 7: Create traditional TCP flag distribution chart  
    labels = ['SYN', 'RST', 'FIN']
    counts = [scapy_results["syn_count"], scapy_results["rst_count"], scapy_results["fin_count"]]
    plt.figure(figsize=(8, 6))
    plt.bar(labels, counts)
    plt.title("Phân bố các loại gói TCP")
    plt.savefig("tcp_flags_distribution.png")
    print("\nBiểu đồ phân bố gói đã được lưu tại: tcp_flags_distribution.png")

# Chạy chương trình
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Cách dùng: python3 smolagent_with_deepseek.py <pcap_file>")
        print("Nếu không có tệp PCAP, chương trình sẽ ghi lại lưu lượng mới.")
        # Ghi lại lưu lượng mới nếu không có tệp PCAP
        pcap_file = capture_tcp_traffic(interface="eth0", output_file="tcp_capture.pcap", port=80)
    else:
        pcap_file = sys.argv[1]
    
    smolagent_with_deepseek(pcap_file)