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

## Kiến trúc Clean Architecture

Dự án đã được thiết kế theo nguyên tắc Clean Architecture và OOP để cải thiện tính module, khả năng bảo trì, và khả năng kiểm thử. Kiến trúc hiện tại tuân theo các nguyên tắc:

1. **Single Responsibility Principle (SRP)**: Mỗi lớp chỉ có một lý do để thay đổi
2. **Open/Closed Principle**: Mở rộng, không sửa đổi
3. **Phân tách các tầng**: Domain, Use Cases, Interfaces, Infrastructure

## Cấu trúc dự án

```
src/
  ├── domain/              # Các thực thể và quy tắc nghiệp vụ cốt lõi
  │   ├── entities/        # Các lớp thực thể cơ bản
  │   └── repositories/    # Interface cho các repository
  ├── use_cases/           # Logic nghiệp vụ của ứng dụng
  ├── interfaces/          # Adapter cho tương tác với người dùng và hệ thống bên ngoài
  │   ├── controllers/     # Controller xử lý input
  │   ├── gateways/        # Các lớp tương tác với dịch vụ bên ngoài
  │   └── presenters/      # Các lớp xử lý hiển thị kết quả
  └── infrastructure/      # Triển khai cụ thể cho các interface
      └── repositories/    # Triển khai các repository
  └── utils/               # Tiện ích chung
```

## Các lớp chính và trách nhiệm

### Domain Layer

Tập trung vào các thực thể và quy tắc nghiệp vụ cốt lõi. Lớp này không phụ thuộc vào bất kỳ lớp khác.

### Use Cases Layer

Chứa logic nghiệp vụ cụ thể, triển khai các trường hợp sử dụng của ứng dụng.

### Interfaces Layer

#### Presenters:
- **BasePresenter**: Lớp cơ sở cho các presenter với chức năng chung
- **AnalyzerComponent**: Xử lý việc phân tích PCAP và điều phối các lớp phân tích con
- **ChatHandler**: Quản lý hội thoại chat với người dùng về phân tích mạng
- **PCAPAnalyzer**: Phân tích file PCAP và định dạng kết quả cho UI
- **SummaryCreator**: Tạo các tóm tắt phân tích từ dữ liệu PCAP
- **ChartCreator**: Tạo các biểu đồ và trực quan hóa
- **GradioPresenter**: Giao diện web sử dụng Gradio
- **CLIPresenter**: Giao diện dòng lệnh

#### Gateways:
- **SmolagentGateway**: Tương tác với multiagent AI framework
- **OSILayerAnalyzer**: Phân tích lưu lượng mạng theo mô hình OSI
- **ResponseExtractor**: Trích xuất thông tin có cấu trúc từ phản hồi AI
- **ScapyPacketGateway**: Tương tác với thư viện Scapy để phân tích gói tin

#### Controllers:
- **PacketAnalyzerController**: Điều phối phân tích gói tin và tấn công

### Infrastructure Layer

Các triển khai cụ thể cho interfaces như repository, database, external service connectors.

## Cải tiến kiến trúc

1. **Giới hạn kích thước code**: Mỗi file giữ trong khoảng 200-300 dòng code
2. **Phân cấp rõ ràng**: Các lớp có trách nhiệm rõ ràng và tập trung
3. **Dependency Injection**: Các lớp nhận các phụ thuộc thông qua constructor
4. **Phân tách trách nhiệm**: Mỗi lớp có một trách nhiệm duy nhất
5. **Tính module hóa cao**: Các lớp có thể được thay thế hoặc điều chỉnh độc lập

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
