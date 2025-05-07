"""
Packet Analyzer Controller - Handles user interactions for packet analysis.
"""
from typing import Dict, Any, List, Tuple
from datetime import datetime, timedelta

from src.use_cases.analyze_packet_use_case import AnalyzePacketUseCase
from src.use_cases.detect_attack_use_case import DetectAttackUseCase
from src.use_cases.visualize_flow_use_case import VisualizeFlowUseCase


class PacketAnalyzerController:
    """Controller for packet analysis operations."""
    
    def __init__(
        self,
        analyze_packet_use_case: AnalyzePacketUseCase,
        detect_attack_use_case: DetectAttackUseCase,
        visualize_flow_use_case: VisualizeFlowUseCase
    ):
        """Initialize with required use cases."""
        self.analyze_packet_use_case = analyze_packet_use_case
        self.detect_attack_use_case = detect_attack_use_case
        self.visualize_flow_use_case = visualize_flow_use_case
    
    def analyze_pcap_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze a pcap file and return analysis results."""
        # Analyze packets and get flow statistics
        packet_results, flow_stats = self.analyze_packet_use_case.analyze_pcap_file(file_path)
        
        # Detect attacks
        attacks = self.detect_attack_use_case.detect_all_attacks()
        
        # Create visualizations
        flow_graph = self.visualize_flow_use_case.visualize_tcp_flows()
        protocol_dist = self.visualize_flow_use_case.visualize_protocol_distribution()
        
        # Return comprehensive results
        return {
            "flow_statistics": flow_stats,
            "attack_count": len(attacks),
            "attacks": [attack.to_dict() for attack in attacks],
            "visualizations": {
                "flow_graph": flow_graph,
                "protocol_distribution": protocol_dist
            }
        }
    
    def get_attack_details(self, timeframe_hours: int = 24) -> List[Dict[str, Any]]:
        """Get details of detected attacks."""
        timeframe = timedelta(hours=timeframe_hours)
        attacks = self.detect_attack_use_case.detect_all_attacks(timeframe)
        
        return [attack.to_dict() for attack in attacks]
    
    def get_flow_statistics(self, timeframe_hours: int = 1) -> Dict[str, Any]:
        """Get flow statistics."""
        # Use the analyze_packet_use_case to get flow statistics
        return self.analyze_packet_use_case.get_flow_statistics()
    
    def visualize_traffic(self, protocol: str = None, timeframe_hours: int = 1) -> Dict[str, str]:
        """Generate traffic visualizations."""
        timeframe = timedelta(hours=timeframe_hours)
        
        # Create various visualizations
        flow_graph = self.visualize_flow_use_case.visualize_tcp_flows(timeframe)
        packet_rate = self.visualize_flow_use_case.visualize_packet_rate(protocol, timeframe)
        protocol_dist = self.visualize_flow_use_case.visualize_protocol_distribution(timeframe)
        
        if protocol == "TCP":
            flow_states = self.visualize_flow_use_case.visualize_flow_states("TCP", timeframe)
        else:
            flow_states = None
        
        return {
            "flow_graph": flow_graph,
            "packet_rate": packet_rate,
            "protocol_distribution": protocol_dist,
            "flow_states": flow_states
        }
    
    def detect_attacks_realtime(self, duration_minutes: int = 5) -> Dict[str, Any]:
        """Monitor traffic for attacks in real-time for a specified duration."""
        timeframe = timedelta(minutes=duration_minutes)
        start_time = datetime.now()
        end_time = start_time + timeframe
        
        print(f"Monitoring traffic for attacks from {start_time.strftime('%H:%M:%S')} to {end_time.strftime('%H:%M:%S')}...")
        
        # In a real implementation, this would actively monitor traffic
        # For now, we'll just analyze the most recent timeframe
        attacks = self.detect_attack_use_case.detect_all_attacks(timeframe)
        
        if attacks:
            print(f"⚠️ Detected {len(attacks)} potential attacks!")
            for attack in attacks:
                print(f"- {attack.description} (Confidence: {attack.confidence:.2f}, Severity: {attack.severity}/10)")
        else:
            print("✅ No attacks detected during the monitoring period.")
        
        return {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "attack_count": len(attacks),
            "attacks": [attack.to_dict() for attack in attacks]
        } 