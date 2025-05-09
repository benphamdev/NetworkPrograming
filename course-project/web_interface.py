#!/usr/bin/env python3
"""
Web Interface - Launch the web-based interface for Network Packet Analyzer.
Được thiết kế đặc biệt cho các Network Engineer để debug vấn đề mạng và phát hiện các cuộc tấn công.
"""
import os
from src.interfaces.presenters.gradio_presenter import GradioPresenter
from main import setup_dependencies


def main():
    """Main entry point for the web interface."""
    # Set up dependencies
    deps = setup_dependencies()
    controller = deps["controller"]
    
    # Create and launch Gradio interface
    presenter = GradioPresenter(controller)
    presenter.launch_interface()


if __name__ == "__main__":
    print("Khởi động Network Packet Analyzer cho Network Engineer...")
    print("Công cụ hỗ trợ:")
    print("- Debug vấn đề kết nối mạng (thiết bị không ping được đến nhau)")
    print("- Phát hiện và phân tích 20+ loại tấn công mạng")
    print("- Phân tích theo mô hình OSI và đề xuất giải pháp")
    print("- Trực quan hóa luồng mạng và phát hiện bất thường")
    
    # Create required directories
    os.makedirs("data", exist_ok=True)
    os.makedirs("visualizations", exist_ok=True)
    
    # Run the interface
    main() 