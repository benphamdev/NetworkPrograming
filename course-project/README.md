# Network Packet Analyzer

Công cụ phân tích gói tin mạng để phát hiện các cuộc tấn công như ARP spoofing, SYN flood, ICMP flood và các hoạt động đáng ngờ khác.

## Tính năng

- Phân tích file pcap để phát hiện các cuộc tấn công mạng
- Hỗ trợ phân tích nhiều loại giao thức (TCP, UDP, ICMP, ARP)
- Phát hiện các loại tấn công phổ biến:
  - SYN flood
  - ARP spoofing
  - Port scanning
  - ICMP flood
  - Reset attacks
- Trực quan hóa luồng mạng và các cuộc tấn công
- Tích hợp SmolaAgent AI để phân tích thông minh (cần API key)
- Hai loại giao diện:
  - Giao diện dòng lệnh thân thiện với người dùng
  - Giao diện web trực quan với biểu đồ và đồ thị

## Cài đặt

### Yêu cầu
- Python 3.8+
- Scapy
- Matplotlib, NetworkX, Seaborn, Plotly
- Gradio (cho giao diện web)
- SmolaAgent (tùy chọn, cho phân tích AI)

### Cài đặt thông qua pip

        ```bash
# Clone repository
git clone https://github.com/username/network-packet-analyzer.git
cd network-packet-analyzer

# Cài đặt các thư viện phụ thuộc
pip install -r requirements.txt
```

### Cấu hình SmolaAgent (tùy chọn)

Để sử dụng SmolaAgent, bạn cần:

1. Tạo file `.env` trong thư mục gốc của dự án
2. Thêm API key của bạn vào file:

```
DEEPSEEK_API_KEY=your-api-key-here
```

## Sử dụng

### Giao diện web (Khuyến nghị)

Chạy giao diện web tương tác:

        ```bash
python web_interface.py
```

Truy cập giao diện web tại http://localhost:7860 trong trình duyệt của bạn.

Giao diện web bao gồm các tab:
- **Phân tích PCAP**: Tải lên và phân tích file pcap
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

## Cấu trúc dự án

Dự án tuân theo kiến trúc Clean Architecture:

```
src/
  ├── domain/                 # Core business entities
  │   ├── entities/           # Core domain entities
  │   │   ├── packet.py       # Basic packet entity
  │   │   ├── attack.py       # Attack entity
  │   │   └── flow.py         # Network flow entity
  │   └── repositories/       # Repository interfaces
  │       ├── packet_repository.py
  │       └── attack_repository.py
  ├── use_cases/              # Application business logic
  │   ├── analyze_packet_use_case.py
  │   ├── detect_attack_use_case.py
  │   └── visualize_flow_use_case.py
  ├── interfaces/             # Interface adapters
  │   ├── controllers/
  │   │   └── packet_analyzer_controller.py
  │   ├── gateways/
  │   │   ├── scapy_packet_gateway.py
  │   │   └── smolagent_gateway.py
  │   └── presenters/
  │       ├── cli_presenter.py 
  │       ├── visualization_presenter.py
  │       └── gradio_presenter.py
  └── infrastructure/         # External frameworks & tools
      ├── repositories/
      │   ├── file_packet_repository.py
      │   └── memory_attack_repository.py
      ├── smolagent/
      │   └── deep_seek_agent.py
      └── visualizers/
          └── matplotlib_visualizer.py
main.py                      # CLI entry point
web_interface.py            # Web interface entry point
```

## Các cảnh báo tấn công

Tool sẽ phát hiện các loại tấn công sau:

1. **SYN Flood**: Khi có một lượng lớn gói SYN được gửi đến một máy chủ
2. **ARP Spoofing**: Khi có nhiều địa chỉ MAC khác nhau cho cùng một địa chỉ IP
3. **Port Scanning**: Khi có nhiều cổng được quét từ cùng một địa chỉ nguồn
4. **ICMP Flood**: Khi có quá nhiều gói ICMP echo request gửi đến
5. **Reset Attacks**: Khi có bất thường về số lượng gói RST

## Đóng góp

Đóng góp rất được hoan nghênh! Vui lòng tạo issue hoặc pull request nếu bạn muốn cải thiện công cụ này.

## Giấy phép

MIT License
