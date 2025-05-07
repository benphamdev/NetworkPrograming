"""
Analyze Packet Use Case - Analyzes packets to extract information and detect patterns.
"""
from typing import Dict, Any, List, Tuple

from src.domain.packet import Packet, TCPPacket, ICMPPacket, ARPPacket
from src.domain.entities.flow import TCPFlow, FlowState, ICMPFlow
from src.domain.repositories.packet_repository import PacketRepository
from src.domain.repositories.flow_repository import FlowRepository


class AnalyzePacketUseCase:
    """Use case for analyzing network packets."""
    
    def __init__(self, packet_repository: PacketRepository, flow_repository: FlowRepository):
        """Initialize with required repositories."""
        self.packet_repository = packet_repository
        self.flow_repository = flow_repository
        self.flow_cache = {}  # flow_id -> Flow
    
    def analyze_tcp_packet(self, packet: TCPPacket) -> Dict[str, Any]:
        """Analyze a TCP packet and extract information."""
        result = {
            "is_syn": packet.is_syn(),
            "is_syn_ack": packet.is_syn_ack(),
            "is_rst": packet.is_rst(),
            "is_fin": packet.is_fin(),
            "has_payload": len(packet.payload) > 0,
            "seq_number": packet.seq_number,
            "ack_number": packet.ack_number,
            "window_size": packet.window_size
        }
        
        # Get or create flow
        flow_id = f"{packet.src_ip}:{packet.src_port}-{packet.dst_ip}:{packet.dst_port}-TCP"
        reverse_flow_id = f"{packet.dst_ip}:{packet.dst_port}-{packet.src_ip}:{packet.src_port}-TCP"
        
        flow = self.flow_cache.get(flow_id)
        reverse_flow = self.flow_cache.get(reverse_flow_id)
        
        if flow is None and reverse_flow is None:
            # New flow
            flow = TCPFlow(
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol="TCP",
                start_time=packet.timestamp,
                state=FlowState.UNKNOWN,
                packet_count=1,
                byte_count=packet.length
            )
            self.flow_cache[flow_id] = flow
        elif flow is not None:
            # Existing flow
            flow.packet_count += 1
            flow.byte_count += packet.length
            flow.end_time = packet.timestamp
        elif reverse_flow is not None:
            # Existing flow (reverse direction)
            reverse_flow.packet_count += 1
            reverse_flow.byte_count += packet.length
            reverse_flow.end_time = packet.timestamp
            flow = reverse_flow
        
        # Update flow state based on flags
        if flow is not None and isinstance(flow, TCPFlow):
            if packet.is_syn():
                flow.syn_count += 1
                if flow.state == FlowState.UNKNOWN:
                    flow.state = FlowState.INCOMPLETE
            
            if packet.is_fin():
                flow.fin_count += 1
                if flow.fin_count >= 2:
                    flow.state = FlowState.CLOSED
                    flow.graceful_close = True
            
            if packet.is_rst():
                flow.rst_count += 1
                flow.state = FlowState.RESET
            
            # Check for handshake completion
            if packet.is_syn_ack() and flow.syn_count > 0:
                flow.handshake_completed = True
                flow.state = FlowState.ESTABLISHED
            
            if packet.retransmission:
                flow.retransmissions += 1
        
        result["flow"] = flow
        
        return result
    
    def analyze_icmp_packet(self, packet: ICMPPacket) -> Dict[str, Any]:
        """Analyze an ICMP packet and extract information."""
        result = {
            "icmp_type": packet.icmp_type,
            "icmp_code": packet.icmp_code,
            "is_echo_request": packet.is_echo_request(),
            "is_echo_reply": packet.is_echo_reply(),
            "has_payload": len(packet.payload) > 0
        }
        
        # Get or create flow - For ICMP we use a simpler flow ID
        flow_id = f"{packet.src_ip}-{packet.dst_ip}-ICMP"
        reverse_flow_id = f"{packet.dst_ip}-{packet.src_ip}-ICMP"
        
        flow = self.flow_cache.get(flow_id)
        reverse_flow = self.flow_cache.get(reverse_flow_id)
        
        if flow is None and reverse_flow is None:
            # New flow
            flow = ICMPFlow(
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=0,  # ICMP doesn't use ports
                dst_port=0,
                protocol="ICMP",
                start_time=packet.timestamp,
                packet_count=1,
                byte_count=packet.length
            )
            self.flow_cache[flow_id] = flow
        elif flow is not None:
            # Existing flow
            flow.packet_count += 1
            flow.byte_count += packet.length
            flow.end_time = packet.timestamp
        elif reverse_flow is not None:
            # Existing flow (reverse direction)
            reverse_flow.packet_count += 1
            reverse_flow.byte_count += packet.length
            reverse_flow.end_time = packet.timestamp
            flow = reverse_flow
        
        # Update flow state based on ICMP type
        if flow is not None and isinstance(flow, ICMPFlow):
            if packet.is_echo_request():
                flow.echo_requests += 1
            if packet.is_echo_reply():
                flow.echo_replies += 1
        
        result["flow"] = flow
        
        return result
    
    def analyze_arp_packet(self, packet: ARPPacket) -> Dict[str, Any]:
        """Analyze an ARP packet and extract information."""
        return {
            "is_request": packet.is_request(),
            "is_reply": packet.is_reply(),
            "src_mac": packet.src_mac,
            "dst_mac": packet.dst_mac,
            "target_ip": packet.target_ip,
            "sender_ip": packet.sender_ip
        }
    
    def get_flow_statistics(self) -> Dict[str, Any]:
        """Get statistics about all flows."""
        total_flows = len(self.flow_cache)
        established_count = sum(1 for flow in self.flow_cache.values() 
                              if flow.state == FlowState.ESTABLISHED)
        reset_count = sum(1 for flow in self.flow_cache.values() 
                         if flow.state == FlowState.RESET)
        closed_count = sum(1 for flow in self.flow_cache.values() 
                          if flow.state == FlowState.CLOSED)
        incomplete_count = sum(1 for flow in self.flow_cache.values() 
                             if flow.state == FlowState.INCOMPLETE)
        
        return {
            "total_flows": total_flows,
            "established_count": established_count,
            "reset_count": reset_count,
            "closed_count": closed_count,
            "incomplete_count": incomplete_count
        }
    
    def persist_flows(self) -> None:
        """Save all flows to the repository."""
        for flow in self.flow_cache.values():
            self.flow_repository.save_flow(flow)
    
    def analyze_packet(self, packet: Packet) -> Dict[str, Any]:
        """Analyze a packet based on its type."""
        if isinstance(packet, TCPPacket):
            return self.analyze_tcp_packet(packet)
        elif isinstance(packet, ICMPPacket):
            return self.analyze_icmp_packet(packet)
        elif isinstance(packet, ARPPacket):
            return self.analyze_arp_packet(packet)
        else:
            return {"protocol": packet.protocol}
    
    def analyze_pcap_file(self, file_path: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Analyze all packets in a pcap file."""
        packets = self.packet_repository.load_pcap_file(file_path)
        results = []
        
        for packet in packets:
            self.packet_repository.save_packet(packet)
            result = self.analyze_packet(packet)
            results.append(result)
        
        # Persist flows after analysis
        self.persist_flows()
        
        # Return both individual packet analysis and flow statistics
        return results, self.get_flow_statistics()