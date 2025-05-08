# Tài liệu Refactoring Packet Analyzer

## Kiến trúc Clean Architecture

Dự án đã được refactor theo nguyên tắc Clean Architecture và OOP để cải thiện tính module, khả năng bảo trì, và khả năng kiểm thử. Kiến trúc hiện tại tuân theo các nguyên tắc:

1. **Single Responsibility Principle (SRP)**: Mỗi lớp chỉ có một lý do để thay đổi
2. **Open/Closed Principle**: Mở rộng, không sửa đổi
3. **Phân tách các tầng**: Domain, Use Cases, Interfaces, Infrastructure

## Cấu trúc thư mục

```
src/
  domain/              # Các thực thể và quy tắc nghiệp vụ cốt lõi
    entities/          # Các lớp thực thể cơ bản
    repositories/      # Interface cho các repository
  use_cases/           # Logic nghiệp vụ của ứng dụng
  interfaces/          # Adapter cho tương tác với người dùng và hệ thống bên ngoài
    controllers/       # Controller xử lý input
    gateways/          # Các lớp tương tác với dịch vụ bên ngoài
    presenters/        # Các lớp xử lý hiển thị kết quả
  infrastructure/      # Triển khai cụ thể cho các interface
    repositories/      # Triển khai các repository
  utils/               # Tiện ích chung
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

## Các lớp mới được tách ra từ các lớp lớn

### Từ SmolagentGateway

- **ResponseExtractor**: Trích xuất thông tin từ phản hồi AI như attack_detection, confidence, recommendations
- **OSILayerAnalyzer**: Chuyên về phân tích mô hình OSI, tách khỏi logic chính

### Từ AnalyzerComponent

- **ChatHandler**: Quản lý hội thoại và phân tích yêu cầu chat
- **SummaryCreator**: Tạo các tóm tắt phân tích từ dữ liệu PCAP
- **PCAPAnalyzer**: Phân tích file PCAP và định dạng kết quả cho UI

## Cải tiến kiến trúc

1. **Giới hạn kích thước code**: Mỗi file giữ trong khoảng 200-300 dòng code
2. **Phân cấp rõ ràng**: Các lớp có trách nhiệm rõ ràng và tập trung
3. **Dependency Injection**: Các lớp nhận các phụ thuộc thông qua constructor
4. **Phân tách trách nhiệm**: Mỗi lớp có một trách nhiệm duy nhất
5. **Tính module hóa cao**: Các lớp có thể được thay thế hoặc điều chỉnh độc lập

## Lợi ích của cách tiếp cận này

- **Khả năng bảo trì tốt hơn**: Code nhỏ, tập trung và dễ hiểu
- **Kiểm thử dễ dàng hơn**: Các lớp có thể được kiểm thử độc lập với các mock phù hợp
- **Dễ dàng mở rộng**: Thêm tính năng mới mà không phải sửa đổi code hiện tại
- **Tái sử dụng code**: Các thành phần có thể được tái sử dụng trong các phần khác của ứng dụng
- **Cải thiện hiệu suất phát triển**: Nhiều người có thể làm việc đồng thời trên các module khác nhau 