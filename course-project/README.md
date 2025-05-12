# Network Packet Analyzer cho Network Engineer

Công cụ chuyên nghiệp hỗ trợ kỹ sư mạng (Network Engineer) trong việc debug vấn đề kết nối, phát hiện lỗi mạng, và phân
tích các cuộc tấn công mạng.

## Tính năng chính

- **Debug vấn đề kết nối mạng**:
    - Phân tích tại sao các thiết bị không ping được đến nhau
    - Xác định chính xác thành phần mạng nào đang gặp trục trặc (Router, Switch, Firewall, DNS, v.v.)
    - Phân tích timeout, latency và retransmission

- **Phân tích theo mô hình OSI**:
    - Phân tích các vấn đề ở từng tầng của mô hình OSI
    - Tầng vật lý: Lỗi cáp, port, tín hiệu
    - Tầng liên kết dữ liệu: Xung đột MAC, ARP poisoning, VLAN issues
    - Tầng mạng: IP routing, ICMP, fragmentation, TTL issues
    - Tầng giao vận: TCP handshake, RST packets, port availability
    - Tầng ứng dụng: DNS resolution, HTTP errors, TLS issues

- **Phát hiện các loại tấn công mạng**:
    - ARP: Spoofing, Poisoning, Man-in-the-Middle
    - DHCP: Spoofing, Starvation, DOS, Rogue DHCP Server
    - DNS: Cache Poisoning, Tunneling, Spoofing, Amplification
    - ICMP: Ping Flooding, Tunneling, Smurf Attack
    - TCP/IP: SYN Flood, RST Attack, Session Hijacking, Port Scanning
    - DDoS: Reflection/Amplification, Slowloris, HTTP Flooding

- **Tư vấn và đề xuất giải pháp**:
    - Đề xuất các lệnh debug và công cụ phù hợp (tcpdump, Wireshark, netstat, ping, v.v.)
    - Cung cấp quy trình kiểm tra có hệ thống
    - Hướng dẫn chi tiết để khắc phục vấn đề

- **Phân tích và trực quan hóa**:
    - Phân tích file pcap
    - Trực quan hóa luồng mạng và các cuộc tấn công
    - Phân tích cờ TCP để xác định tình trạng kết nối
    - Tích hợp SmolaAgent AI để phân tích chi tiết và thông minh

## Cài đặt

### Yêu cầu

- Python 3.8+
- Scapy
- Matplotlib, NetworkX, Seaborn, Plotly
- Gradio (cho giao diện web)
- SmolaAgent (cho phân tích AI)

### Cài đặt thông qua pip

```bash
# Clone repository
git clone https://github.com/username/network-packet-analyzer.git
cd network-packet-analyzer

# Cài đặt các thư viện phụ thuộc
pip install -r requirements.txt
```

### Cấu hình SmolaAgent

Để sử dụng SmolaAgent, bạn cần:

1. Tạo file `.env` trong thư mục gốc của dự án bằng cách sao chép từ mẫu `example.env`
2. Thêm API key của bạn vào file `.env`. Bạn có thể sử dụng một trong các API key sau:

```
OPENAI_API_KEY=your-openai-api-key
GROQ_API_KEY=your-groq-api-key
GEMINI_API_KEY=your-gemini-api-key
DEEPSEEK_API_KEY=your-deepseek-api-key
HUGGINGFACEHUB_API_TOKEN=your-huggingface-token
```

Lưu ý: Bạn chỉ cần cung cấp ít nhất một API key để sử dụng SmolaAgent.

## Sử dụng

### Giao diện web (Khuyến nghị)

Chạy giao diện web tương tác:

```bash
python web_interface.py
```

Truy cập giao diện web tại http://localhost:7860 trong trình duyệt của bạn.

Giao diện web bao gồm các tab:

- **Phân tích PCAP**: Tải lên và phân tích file pcap
- **ChatBox Tư Vấn**: Tư vấn debug mạng và rủi ro bảo mật
- **Phân tích theo mô hình OSI**: Phân tích chi tiết các vấn đề ở từng tầng OSI
- **Giám sát thời gian thực**: Theo dõi lưu lượng mạng theo thời gian thực
- **Chi tiết tấn công**: Xem chi tiết các cuộc tấn công đã phát hiện
- **Thống kê luồng**: Xem thống kê về luồng mạng

### Giao diện dòng lệnh

#### Phân tích file pcap

```bash
python main.py analyze path/to/your/file.pcap
```

#### Liệt kê các file pcap có sẵn

```bash
python main.py list
```

#### Giám sát lưu lượng trong thời gian thực

```bash
python main.py monitor --duration 10
```

#### Xem thống kê luồng

```bash
python main.py stats --hours 1
```

#### Xem các cuộc tấn công đã phát hiện

```bash
python main.py attacks --hours 24
```

#### Sử dụng SmolaAgent cho phân tích nâng cao

```bash
python packet_analyzer_with_smolagent.py path/to/your/file.pcap
```

## Cách sử dụng công cụ cho Network Engineer

### Kịch bản 1: Debug vấn đề kết nối giữa các thiết bị

1. Tải lên file PCAP chứa gói tin từ thiết bị gặp vấn đề kết nối
2. Nhấn "Phân tích" để thực hiện phân tích tự động
3. Chuyển đến tab "Phân tích theo mô hình OSI" để xem chi tiết vấn đề ở từng tầng
4. Sử dụng ChatBox để hỏi cụ thể: "Tại sao thiết bị X không ping được đến thiết bị Y?"

### Kịch bản 2: Phát hiện tấn công mạng

1. Tải lên file PCAP cần phân tích
2. Xem tab "Chi tiết tấn công" để xem các cuộc tấn công đã phát hiện
3. Sử dụng ChatBox để hỏi thêm về tấn công: "Có dấu hiệu tấn công ARP spoofing không?"
4. Nhận đề xuất các biện pháp khắc phục và giảm thiểu rủi ro

### Kịch bản 3: Phân tích hiệu suất mạng

1. Sử dụng tab "Thống kê luồng" để xem phân bố giao thức và luồng mạng
2. Xác định các luồng có vấn đề (reset, retransmission, timeout)
3. Yêu cầu phân tích chi tiết về hiệu suất TCP/IP qua ChatBox

## Kiến trúc Clean Architecture

Dự án đã được thiết kế theo nguyên tắc Clean Architecture và OOP để cải thiện tính module, khả năng bảo trì, và khả năng
kiểm thử. Kiến trúc hiện tại tuân theo các nguyên tắc:

1. **Single Responsibility Principle (SRP)**: Mỗi lớp chỉ có một lý do để thay đổi
2. **Open/Closed Principle**: Mở rộng, không sửa đổi
3. **Phân tách các tầng**: Domain, Use Cases, Interfaces, Infrastructure

## Cấu trúc dự án

```
course-project/
  ├── data/                # Thư mục chứa dữ liệu
  │   ├── arp/             # Dữ liệu phân tích ARP
  │   ├── embeddings/      # Vector embeddings cho AI
  │   ├── icmp/            # Dữ liệu phân tích ICMP
  │   ├── packets/         # Dữ liệu gói tin
  │   ├── tcp/             # Dữ liệu phân tích TCP
  │   └── vector_store/    # Kho lưu trữ vector
  ├── src/                 # Mã nguồn chính
  │   ├── domain/          # Các thực thể và quy tắc nghiệp vụ cốt lõi
  │   │   ├── entities/    # Các lớp thực thể cơ bản
  │   │   └── repositories/# Interface cho các repository
  │   ├── use_cases/       # Logic nghiệp vụ của ứng dụng
  │   ├── interfaces/      # Adapter cho tương tác với người dùng và hệ thống bên ngoài
  │   │   ├── controllers/ # Controller xử lý input
  │   │   ├── gateways/    # Các lớp tương tác với dịch vụ bên ngoài
  │   │   └── presenters/  # Các lớp xử lý hiển thị kết quả
  │   ├── infrastructure/  # Triển khai cụ thể cho các interface
  │   │   ├── prompts/     # Nơi lưu trữ prompt và config model
  │   │   └── repositories/# Triển khai các repository
  │   └── utils/           # Tiện ích chung
  ├── visualizations/      # Kết quả trực quan hóa
  ├── .env                 # File cấu hình biến môi trường
  ├── example.env          # Mẫu file cấu hình
  ├── main.py              # Điểm vào chính của ứng dụng
  ├── web_interface.py     # Giao diện web
  └── requirements.txt     # Các thư viện phụ thuộc
```

## Dấu hiệu phát hiện các cuộc tấn công

Tool sẽ phát hiện các loại tấn công dựa trên các dấu hiệu sau:

1. **ARP Spoofing/Poisoning**:
    - Nhiều địa chỉ MAC khác nhau cho cùng một địa chỉ IP
    - Thông báo ARP không được yêu cầu
    - ARP reply không phù hợp với các request đã biết
    - Địa chỉ MAC của gateway bị thay đổi

2. **DHCP Starvation/Spoofing**:
    - Nhiều DHCP requests từ cùng một thiết bị với MAC khác nhau
    - DHCP server không được ủy quyền cung cấp địa chỉ IP
    - Cạn kiệt pool địa chỉ IP của DHCP server

3. **DNS Cache Poisoning/Tunneling**:
    - Gói tin DNS quá lớn
    - Mã hóa đáng ngờ trong truy vấn và phản hồi DNS
    - Nhiều truy vấn DNS đến tên miền lạ
    - Phản hồi DNS không khớp với truy vấn

4. **TCP/IP Attacks**:
    - SYN Flood: Nhiều gói SYN không hoàn tất handshake
    - RST Attack: Gói RST giả mạo cắt đứt kết nối
    - Port Scanning: Truy cập đến nhiều cổng trên cùng một host
    - Session Hijacking: Sequence number dự đoán được

5. **DDoS Attacks**:
    - Lưu lượng bất thường từ nhiều nguồn đến một đích
    - Tỷ lệ cao các kết nối không hoàn chỉnh
    - Tăng đột biến lưu lượng mạng đến các port hoặc dịch vụ cụ thể

## Đóng góp

Đóng góp rất được hoan nghênh! Vui lòng tạo issue hoặc pull request nếu bạn muốn cải thiện công cụ này.

## Giấy phép

MIT License
