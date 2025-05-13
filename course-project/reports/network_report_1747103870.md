# Báo Cáo Phân Tích OSI

**Thời gian tạo:** 2025-05-13 09:37:50

**ID báo cáo:** 1747103870

## Tóm tắt phân tích

Báo cáo này phân tích lưu lượng mạng và các vấn đề bảo mật.

**Các mối đe dọa phát hiện được:**
- Tấn công không xác định
- Tấn công không xác định



## Phân tích theo mô hình OSI

### Physical Layer (Tầng 1)

Không có dữ liệu về tầng vật lý (Physical). Tầng này liên quan đến các kết nối phần cứng, tín hiệu điện và kết nối vật lý.

### Data Link Layer (Tầng 2)

Không có thông tin cụ thể về tầng liên kết dữ liệu (Data Link). Tầng này xử lý các giao thức như Ethernet, ARP, và các vấn đề liên quan đến địa chỉ MAC.

### Network Layer (Tầng 3)

Không có dữ liệu về tầng mạng (Network). Tầng này xử lý định tuyến IP và giao thức ICMP.

### Transport Layer (Tầng 4)

Không có thông tin cụ thể về tầng giao vận (Transport). Tầng này xử lý các giao thức như TCP, UDP và quản lý các cổng.

### Session Layer (Tầng 5)

Không có dữ liệu về tầng phiên (Session). Tầng này quản lý các phiên kết nối giữa các ứng dụng.

### Presentation Layer (Tầng 6)

Không có thông tin cụ thể về tầng trình diễn (Presentation). Tầng này xử lý mã hóa, nén và chuyển đổi dữ liệu.

### Application Layer (Tầng 7)

Không có dữ liệu về tầng ứng dụng (Application). Tầng này xử lý các giao thức như HTTP, DNS, DHCP.

## Phát hiện tấn công

### Tấn công không xác định

**Mức độ nghiêm trọng:** 7

**Mô tả:** ARP spoofing (DEMO): 00:50:56:c0:00:04 giả mạo 192.168.255.134 (MAC thật: 00:50:56:c0:00:04)

### Tấn công không xác định

**Mức độ nghiêm trọng:** 8

**Mô tả:** ARP flooding phát hiện: 228 gói tin ARP từ 3 nguồn khác nhau với tỷ lệ 2.3 gói/giây

## Khuyến nghị và biện pháp khắc phục

1. Triển khai giám sát mạng 24/7 để phát hiện sớm các mối đe dọa bảo mật.

2. Cập nhật firmware và phần mềm cho các thiết bị mạng thường xuyên.

3. Thực hiện phân đoạn mạng để hạn chế phạm vi ảnh hưởng của các cuộc tấn công.

4. Sử dụng phương pháp xác thực mạnh cho tất cả các tài khoản quản trị mạng.

5. Thiết lập chính sách giám sát và ứng phó sự cố để đối phó với các mối đe dọa bảo mật.

## Kết luận

Phân tích mạng đã phát hiện 2 loại tấn công tiềm ẩn. Cần có biện pháp khắc phục kịp thời để đảm bảo an toàn cho hệ thống mạng.

