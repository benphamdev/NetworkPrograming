# Hệ thống Prompt YAML

Thư mục này chứa các file YAML định nghĩa prompt cho hệ thống phân tích mạng. Các file YAML này được thiết kế để tách biệt nội dung prompt khỏi mã nguồn, giúp dễ dàng quản lý và tùy chỉnh prompt mà không cần sửa đổi mã nguồn.

## Cấu trúc thư mục

```
src/infrastructure/prompts/
  ├── config.yaml              # Cấu hình chung cho hệ thống prompt
  ├── raw_packet_analysis.yaml # Prompt phân tích gói tin thô
  ├── protocol_analysis.yaml   # Prompt phân tích các giao thức cụ thể
  ├── attack_analysis.yaml     # Prompt phân tích các loại tấn công mạng
  └── README.md                # File này
```

## Cấu trúc file YAML

Mỗi file YAML có cấu trúc chung như sau:

```yaml
name: tên_prompt
description: "Mô tả về prompt"
version: "1.0"

# Prompt mặc định
prompt: |
  Nội dung prompt mặc định
  {{context}}

# Các loại prompt khác (tùy chọn)
loại_prompt_1: |
  Nội dung prompt loại 1
  {{context}}

loại_prompt_2: |
  Nội dung prompt loại 2
  {{context}}
```

Trong đó:
- `name`: Tên của prompt
- `description`: Mô tả về prompt
- `version`: Phiên bản của prompt
- `prompt`: Nội dung prompt mặc định
- Các khóa khác: Định nghĩa các loại prompt khác nhau

## Biến trong prompt

Các prompt có thể chứa các biến được đặt trong dấu ngoặc nhọn kép `{{variable}}`. Các biến này sẽ được thay thế bằng giá trị tương ứng khi prompt được sử dụng.

Biến thông dụng nhất là `{{context}}`, đại diện cho ngữ cảnh phân tích (ví dụ: thông tin về các gói tin).

## Cách sử dụng

### Trong mã nguồn

```python
from src.infrastructure.repositories.yaml_prompt_repository import YamlPromptRepository
from src.use_cases.prompt_service import PromptService

# Tạo repository
prompt_repository = YamlPromptRepository()

# Tạo service
prompt_service = PromptService(prompt_repository)

# Lấy prompt đã được format với context
prompt = prompt_service.get_formatted_prompt(
    "raw_packet_analysis",  # Tên file YAML (không bao gồm phần mở rộng)
    {"context": "Thông tin về gói tin..."},  # Context để thay thế biến
    "osi_analysis"  # Loại prompt (tùy chọn)
)

# Sử dụng prompt
result = llm_model.run(prompt)
```

### Tùy chỉnh prompt

Để tùy chỉnh prompt, bạn chỉ cần chỉnh sửa file YAML tương ứng. Không cần phải sửa đổi mã nguồn.

## Thêm prompt mới

Để thêm một prompt mới:

1. Tạo file YAML mới trong thư mục `src/infrastructure/prompts/`
2. Định nghĩa cấu trúc prompt theo mẫu ở trên
3. Sử dụng prompt trong mã nguồn qua `PromptService` 