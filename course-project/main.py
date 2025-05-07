#!/usr/bin/env python3
"""
Network Packet Analyzer - Main application entry point.

This application analyzes pcap files to detect network attacks such as
ARP spoofing, SYN floods, ICMP floods, and other suspicious activities.
"""
import argparse
import os
import time


from src.infrastructure.repositories.file_packet_repository import FilePacketRepository
from src.infrastructure.repositories.memory_flow_repository import MemoryFlowRepository
from src.infrastructure.repositories.memory_attack_repository import MemoryAttackRepository

from src.interfaces.gateways.smolagent_gateway import SmolagentGateway

from src.interfaces.presenters.cli_presenter import CLIPresenter
from src.interfaces.presenters.visualization_presenter import MatplotlibVisualizationStrategy

from src.use_cases.analyze_packet_use_case import AnalyzePacketUseCase
from src.use_cases.detect_attack_use_case import DetectAttackUseCase
from src.use_cases.visualize_flow_use_case import VisualizeFlowUseCase

from src.interfaces.controllers.packet_analyzer_controller import PacketAnalyzerController


def setup_dependencies():
    """Set up and wire dependencies."""
    # Create repositories
    packet_repository = FilePacketRepository("data/packets")
    flow_repository = MemoryFlowRepository()
    attack_repository = MemoryAttackRepository()
    
    # Create visualization strategy
    visualization_strategy = MatplotlibVisualizationStrategy("visualizations")
    
    # Create gateways
    smolagent_gateway = None
    try:
        smolagent_gateway = SmolagentGateway()
        print("SmolagentGateway initialized successfully.")
    except Exception as e:
        print(f"Warning: Could not initialize SmolagentGateway: {e}")
        print("The application will run without AI-assisted analysis.")
    
    # Create use cases
    analyze_packet_use_case = AnalyzePacketUseCase(packet_repository, flow_repository)
    detect_attack_use_case = DetectAttackUseCase(
        packet_repository, flow_repository, attack_repository)
    visualize_flow_use_case = VisualizeFlowUseCase(
        flow_repository, attack_repository, visualization_strategy)
    
    # Create presenter
    cli_presenter = CLIPresenter()
    
    # Create controller
    controller = PacketAnalyzerController(
        analyze_packet_use_case, detect_attack_use_case, visualize_flow_use_case)
    
    return {
        "packet_repository": packet_repository,
        "flow_repository": flow_repository,
        "attack_repository": attack_repository,
        "analyze_packet_use_case": analyze_packet_use_case,
        "detect_attack_use_case": detect_attack_use_case,
        "visualize_flow_use_case": visualize_flow_use_case,
        "cli_presenter": cli_presenter,
        "controller": controller,
        "smolagent_gateway": smolagent_gateway
    }


def analyze_pcap_file(controller, presenter, pcap_file):
    """Analyze a pcap file and present results."""
    start_time = time.time()
    print(f"Analyzing pcap file: {pcap_file}")
    
    # Analyze the pcap file
    results = controller.analyze_pcap_file(pcap_file)
    
    # Present results
    presenter.present_analysis_results(results)
    
    elapsed_time = time.time() - start_time
    print(f"\nAnalysis completed in {elapsed_time:.2f} seconds.")


def monitor_realtime(controller, presenter, duration_minutes):
    """Monitor traffic in real-time for attacks."""
    # Run real-time monitoring
    results = controller.detect_attacks_realtime(duration_minutes)
    
    # Present monitoring results
    presenter.present_realtime_monitoring(results)


def list_available_pcap_files():
    """List available pcap files in the data directory."""
    data_dirs = ["data", "data/tcp", "data/arp", "data/icmp"]
    pcap_files = []
    
    for data_dir in data_dirs:
        if os.path.exists(data_dir):
            for file in os.listdir(data_dir):
                if file.endswith(".pcap") or file.endswith(".pcapng"):
                    pcap_files.append(os.path.join(data_dir, file))
    
    return pcap_files


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Network Packet Analyzer - Detect attacks in pcap files")
    
    # Create a subparser for different commands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a pcap file")
    analyze_parser.add_argument("pcap_file", help="Path to the pcap file to analyze")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List available pcap files")
    
    # Monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Monitor traffic in real-time")
    monitor_parser.add_argument("--duration", type=int, default=5,
                              help="Duration in minutes to monitor (default: 5)")
    
    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Show traffic statistics")
    stats_parser.add_argument("--hours", type=int, default=1,
                             help="Timeframe in hours (default: 1)")
    
    # Attacks command
    attacks_parser = subparsers.add_parser("attacks", help="Show detected attacks")
    attacks_parser.add_argument("--hours", type=int, default=24,
                              help="Timeframe in hours (default: 24)")
    
    return parser.parse_args()


def main():
    """Main entry point of the application."""
    args = parse_args()
    
    # Set up dependencies
    deps = setup_dependencies()
    controller = deps["controller"]
    presenter = deps["cli_presenter"]
    
    # Handle different commands
    if args.command == "analyze":
        pcap_file = args.pcap_file
        if not os.path.exists(pcap_file):
            print(f"Error: File not found: {pcap_file}")
            return
        analyze_pcap_file(controller, presenter, pcap_file)
    
    elif args.command == "list":
        pcap_files = list_available_pcap_files()
        if pcap_files:
            print("\nAvailable pcap files:")
            for i, file in enumerate(pcap_files, 1):
                print(f"  {i}. {file}")
            print("\nTo analyze a file, run: python main.py analyze <file_path>")
        else:
            print("\nNo pcap files found in the data directory.")
            print("Place pcap files in the 'data' directory or its subdirectories.")
    
    elif args.command == "monitor":
        monitor_realtime(controller, presenter, args.duration)
    
    elif args.command == "stats":
        stats = controller.get_flow_statistics()
        presenter.present_flow_statistics(stats)
    
    elif args.command == "attacks":
        attacks = controller.get_attack_details(args.hours)
        presenter.present_attack_details(attacks)
    
    else:
        # No command specified, print help
        pcap_files = list_available_pcap_files()
        print("\nNetwork Packet Analyzer")
        print("======================")
        print("\nCommands:")
        print("  analyze <file>   Analyze a pcap file for attacks")
        print("  list             List available pcap files")
        print("  monitor          Monitor traffic in real-time")
        print("  stats            Show traffic statistics")
        print("  attacks          Show detected attacks")
        
        if pcap_files:
            print("\nAvailable pcap files:")
            for i, file in enumerate(pcap_files, 1):
                print(f"  {i}. {file}")
            print("\nTo analyze a file, run: python main.py analyze <file_path>")
        else:
            print("\nNo pcap files found. Place pcap files in the 'data' directory.")


if __name__ == "__main__":
    main() 