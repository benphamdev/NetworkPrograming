"""
CLI Presenter - Formats and presents analysis results on command line.
"""
from typing import Dict, Any, List, Optional
import json
from datetime import datetime
import textwrap
from colorama import Fore, Style, init


class CLIPresenter:
    """Command-line interface presenter for packet analysis results."""
    
    def __init__(self):
        """Initialize the CLI presenter."""
        # Initialize colorama for cross-platform colored output
        init()
    
    def present_analysis_results(self, results: Dict[str, Any]) -> None:
        """
        Present analysis results on command line.
        
        Args:
            results: Analysis results dictionary
        """
        self._print_header("PACKET ANALYSIS RESULTS")
        
        # Print flow statistics
        self._print_section("Flow Statistics")
        if "flow_statistics" in results:
            flow_stats = results["flow_statistics"]
            for key, value in flow_stats.items():
                self._print_key_value(key, value)
        else:
            print("  No flow statistics available.")
        
        # Print attack information
        self._print_section("Attack Detection")
        if "attacks" in results and results["attacks"]:
            self._print_key_value("Attack Count", results["attack_count"])
            for i, attack in enumerate(results["attacks"]):
                self._print_attack(attack, i+1)
        else:
            print(f"  {Fore.GREEN}No attacks detected.{Style.RESET_ALL}")
        
        # Print visualization information if available
        if "visualizations" in results:
            self._print_section("Visualizations")
            viz = results["visualizations"]
            for viz_name, viz_path in viz.items():
                if viz_path:
                    print(f"  {viz_name}: {viz_path}")
    
    def present_attack_details(self, attacks: List[Dict[str, Any]]) -> None:
        """
        Present detailed attack information.
        
        Args:
            attacks: List of attack dictionaries
        """
        if not attacks:
            print(f"\n{Fore.GREEN}No attacks detected in the specified timeframe.{Style.RESET_ALL}")
            return
        
        self._print_header(f"ATTACK DETAILS ({len(attacks)} attacks)")
        
        for i, attack in enumerate(attacks):
            self._print_attack(attack, i+1)
    
    def present_flow_statistics(self, stats: Dict[str, Any]) -> None:
        """
        Present flow statistics.
        
        Args:
            stats: Flow statistics dictionary
        """
        self._print_header("FLOW STATISTICS")
        
        for key, value in stats.items():
            self._print_key_value(key, value)
    
    def present_traffic_visualizations(self, visualization_paths: Dict[str, str]) -> None:
        """
        Present information about generated traffic visualizations.
        
        Args:
            visualization_paths: Dictionary mapping visualization names to file paths
        """
        self._print_header("TRAFFIC VISUALIZATIONS")
        
        for viz_name, path in visualization_paths.items():
            if path:
                print(f"  {viz_name}: {path}")
    
    def present_realtime_monitoring(self, monitoring_results: Dict[str, Any]) -> None:
        """
        Present results from real-time monitoring.
        
        Args:
            monitoring_results: Dictionary with monitoring results
        """
        start_time = datetime.fromisoformat(monitoring_results["start_time"])
        end_time = datetime.fromisoformat(monitoring_results["end_time"])
        
        self._print_header("REAL-TIME MONITORING RESULTS")
        
        print(f"  Monitoring period: {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        attack_count = monitoring_results["attack_count"]
        if attack_count > 0:
            print(f"\n  {Fore.RED}⚠️ Detected {attack_count} potential attacks!{Style.RESET_ALL}")
            for i, attack in enumerate(monitoring_results["attacks"]):
                self._print_attack(attack, i+1)
        else:
            print(f"\n  {Fore.GREEN}✅ No attacks detected during the monitoring period.{Style.RESET_ALL}")
    
    def _print_header(self, header_text: str) -> None:
        """Print a section header."""
        width = 80
        print("\n" + "=" * width)
        print(f"{Fore.CYAN}{header_text.center(width)}{Style.RESET_ALL}")
        print("=" * width + "\n")
    
    def _print_section(self, section_name: str) -> None:
        """Print a section name."""
        print(f"\n{Fore.YELLOW}{section_name}:{Style.RESET_ALL}")
    
    def _print_key_value(self, key: str, value: Any) -> None:
        """Print a key-value pair."""
        formatted_key = key.replace('_', ' ').title()
        print(f"  {formatted_key}: {value}")
    
    def _print_attack(self, attack: Dict[str, Any], index: int) -> None:
        """Print details of an attack."""
        attack_type = attack.get("attack_type", "Unknown")
        confidence = attack.get("confidence", 0)
        severity = attack.get("severity", 0)
        description = attack.get("description", "No description available")
        
        # Determine color based on severity
        if severity >= 7:
            color = Fore.RED
        elif severity >= 4:
            color = Fore.YELLOW
        else:
            color = Fore.GREEN
        
        print(f"\n  {color}Attack #{index}: {attack_type}{Style.RESET_ALL}")
        print(f"    Description: {description}")
        print(f"    Confidence: {confidence:.2f}")
        print(f"    Severity: {severity}/10")
        
        # Print source IPs if available
        if "source_ips" in attack and attack["source_ips"]:
            source_ips = attack["source_ips"]
            if len(source_ips) <= 5:
                print(f"    Source IPs: {', '.join(source_ips)}")
            else:
                print(f"    Source IPs: {', '.join(source_ips[:5])} (and {len(source_ips)-5} more)")
        
        # Print target IPs if available
        if "target_ips" in attack and attack["target_ips"]:
            target_ips = attack["target_ips"]
            print(f"    Target IPs: {', '.join(target_ips)}")
        
        # Print timestamp if available
        if "timestamp" in attack:
            timestamp = attack["timestamp"]
            print(f"    Timestamp: {timestamp}")
        
        # Print additional metadata for specific attack types
        if attack_type == "SYN_FLOOD" and "syn_count" in attack:
            print(f"    SYN Packets: {attack['syn_count']}")
            if "syn_ack_count" in attack:
                print(f"    SYN-ACK Packets: {attack['syn_ack_count']}")
        
        elif attack_type == "PORT_SCAN" and "scanned_ports" in attack:
            scanned_ports = attack.get("scanned_ports", [])
            if len(scanned_ports) <= 10:
                print(f"    Scanned Ports: {', '.join(map(str, scanned_ports))}")
            else:
                print(f"    Scanned Ports: {', '.join(map(str, scanned_ports[:10]))} (and {len(scanned_ports)-10} more)")
                print(f"    Total Ports Scanned: {len(scanned_ports)}")
        
        elif attack_type == "ARP_SPOOFING" and "spoofed_mac" in attack:
            print(f"    Spoofed MAC: {attack['spoofed_mac']}")
            if "real_mac" in attack and attack["real_mac"]:
                print(f"    Real MAC: {attack['real_mac']}")
            
        elif attack_type == "ICMP_FLOOD" and "packet_rate" in attack:
            print(f"    Packet Rate: {attack['packet_rate']:.2f} packets/second")
            if "icmp_echo_requests" in attack:
                print(f"    Echo Requests: {attack['icmp_echo_requests']}") 