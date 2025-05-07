#!/usr/bin/env python3
"""
Web Interface - Launch the web-based interface for Network Packet Analyzer.
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
    # Create required directories
    os.makedirs("data", exist_ok=True)
    os.makedirs("visualizations", exist_ok=True)
    
    # Run the interface
    main() 