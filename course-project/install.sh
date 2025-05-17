#!/bin/bash

# Thiết lập màu sắc cho terminal
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Kiểm tra cài đặt Python
echo -e "${GREEN}Kiểm tra phiên bản Python...${NC}"
if command -v python &>/dev/null; then
    PYTHON_CMD="python"
elif command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
else
    echo -e "${RED}Không tìm thấy Python! Vui lòng cài đặt Python >= 3.6 và thử lại.${NC}"
    exit 1
fi

echo -e "${GREEN}Sử dụng $($PYTHON_CMD --version)${NC}"

# Kiểm tra tham số
USE_GLOBAL=false
for arg in "$@"; do
    if [ "$arg" == "--global" ]; then
        USE_GLOBAL=true
    fi
done

echo -e "${GREEN}Bắt đầu cài đặt môi trường cho dự án...${NC}"

# Quyết định sử dụng môi trường ảo hay Python global
if [ "$USE_GLOBAL" = true ]; then
    echo -e "${YELLOW}Sử dụng Python global theo yêu cầu...${NC}"
else
    # Tạo môi trường ảo Python
    if [ -d "venv" ]; then
        echo -e "${YELLOW}Môi trường ảo đã tồn tại. Đang kích hoạt...${NC}"
    else
        echo -e "${GREEN}Đang tạo môi trường ảo Python...${NC}"
        $PYTHON_CMD -m venv venv
        if [ $? -ne 0 ]; then
            echo -e "${RED}Lỗi khi tạo môi trường ảo. Vui lòng cài đặt Python >= 3.6 và thử lại.${NC}"
            echo -e "${YELLOW}Bạn có thể chạy lại với tham số --global để sử dụng Python global.${NC}"
            exit 1
        fi
    fi

    # Kích hoạt môi trường ảo
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        source venv/Scripts/activate
    else
        source venv/bin/activate
    fi
fi

# Cài đặt các dependency
echo -e "${GREEN}Đang cài đặt các thư viện cần thiết...${NC}"
pip install --upgrade pip
pip install -r requirements.txt

# Thiết lập file .env nếu chưa tồn tại
if [ ! -f .env ]; then
    echo -e "${GREEN}Đang tạo file .env từ example.env...${NC}"
    cp example.env .env
    echo -e "${YELLOW}Vui lòng kiểm tra và cập nhật các biến môi trường trong file .env${NC}"
fi

# Tạo các thư mục cần thiết nếu chưa tồn tại
mkdir -p data/vector_store
mkdir -p reports
mkdir -p visualizations

echo -e "${GREEN}Cài đặt hoàn tất!${NC}"
if [ "$USE_GLOBAL" = false ]; then
    echo -e "${YELLOW}Để kích hoạt môi trường, chạy:${NC}"
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        echo -e "${YELLOW}source venv/Scripts/activate${NC}"
    else
        echo -e "${YELLOW}source venv/bin/activate${NC}"
    fi
else
    echo -e "${YELLOW}Đã cài đặt vào Python global.${NC}"
fi

echo -e "${GREEN}Sử dụng: ./install.sh [--global]${NC}"
echo -e "${YELLOW}  --global: Cài đặt vào Python global thay vì sử dụng môi trường ảo${NC}"
