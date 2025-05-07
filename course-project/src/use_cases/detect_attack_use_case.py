"""
Detect Attack Use Case - Analyzes traffic patterns to detect potential attacks.
"""
from datetime import datetime, timedelta
from typing import Dict, Any, List
from collections import Counter, defaultdict

# Fix the import path
from src.domain.packet import TCPPacket, ICMPPacket, ARPPacket
from src.domain.entities.flow import TCPFlow, FlowState
from src.domain.entities.attack import (
    Attack, AttackType, SynFloodAttack, ArpSpoofingAttack, 
    PortScanAttack, IcmpFloodAttack, RstAttack
)
from src.domain.repositories.packet_repository import PacketRepository
from src.domain.repositories.flow_repository import FlowRepository
from src.domain.repositories.attack_repository import AttackRepository


class DetectAttackUseCase:
    """Use case for detecting network attacks."""
    
    def __init__(
        self, 
        packet_repository: PacketRepository, 
        flow_repository: FlowRepository,
        attack_repository: AttackRepository,
        thresholds: Dict[str, Any] = None
    ):
        """Initialize with required repositories and thresholds."""
        self.packet_repository = packet_repository
        self.flow_repository = flow_repository
        self.attack_repository = attack_repository
        
        # Default thresholds
        self.thresholds = {
            "syn_flood_rate": 100,  # SYNs per second
            "syn_flood_count": 500,  # Total SYNs
            "port_scan_threshold": 15,  # Unique ports
            "icmp_flood_rate": 50,  # ICMP packets per second
            "rst_attack_threshold": 10,  # RSTs without prior connection
            "arp_spoofing_min_packets": 5  # Minimum ARP packets to consider spoofing
        }
        
        # Override with provided thresholds
        if thresholds:
            self.thresholds.update(thresholds)
    
    def detect_syn_flood(self, timeframe: timedelta = timedelta(minutes=5)) -> List[SynFloodAttack]:
        """
        Detect SYN flood attacks within a specific timeframe.
        
        A SYN flood is characterized by:
        1. High rate of SYN packets
        2. Low rate of SYN-ACK responses
        3. Often from spoofed source IPs
        """
        end_time = datetime.now()
        start_time = end_time - timeframe
        
        # Get TCP packets in the timeframe
        tcp_packets = [
            p for p in self.packet_repository.get_packets_in_timeframe(start_time, end_time)
            if isinstance(p, TCPPacket)
        ]
        
        # Group by destination IP and port
        targets = defaultdict(list)
        for packet in tcp_packets:
            if packet.is_syn():
                key = (packet.dst_ip, packet.dst_port)
                targets[key].append(packet)
        
        attacks = []
        for (target_ip, target_port), syn_packets in targets.items():
            # Check if the number of SYN packets exceeds threshold
            if len(syn_packets) < self.thresholds["syn_flood_count"]:
                continue
            
            # Calculate rate
            time_span = (max(p.timestamp for p in syn_packets) - 
                         min(p.timestamp for p in syn_packets)).total_seconds()
            if time_span < 1:  # Avoid division by zero
                time_span = 1
                
            syn_rate = len(syn_packets) / time_span
            
            # Check if the rate exceeds threshold
            if syn_rate < self.thresholds["syn_flood_rate"]:
                continue
            
            # Count source IPs
            source_ips = set(p.src_ip for p in syn_packets)
            source_ports = set(p.src_port for p in syn_packets)
            
            # Looks like a SYN flood
            attack = SynFloodAttack(
                timestamp=min(p.timestamp for p in syn_packets),
                attack_type=AttackType.SYN_FLOOD,
                source_ips=list(source_ips),
                target_ips=[target_ip],
                severity=min(10, int(syn_rate / self.thresholds["syn_flood_rate"] * 5)),
                confidence=min(1.0, len(syn_packets) / self.thresholds["syn_flood_count"]),
                description=f"SYN flood detected: {len(syn_packets)} SYN packets at {syn_rate:.2f}/sec to {target_ip}:{target_port}",
                packet_count=len(syn_packets),
                syn_count=len(syn_packets),
                syn_ack_count=sum(1 for p in tcp_packets if p.is_syn_ack() and p.src_ip == target_ip),
                unique_source_ports=len(source_ports)
            )
            
            attacks.append(attack)
            self.attack_repository.save_attack(attack)
        
        return attacks
    
    def detect_port_scan(self, timeframe: timedelta = timedelta(minutes=5)) -> List[PortScanAttack]:
        """
        Detect port scanning attacks within a specific timeframe.
        
        A port scan is characterized by:
        1. Multiple connection attempts to different ports on the same host
        2. Often with TCP SYN packets that don't complete the handshake
        """
        end_time = datetime.now()
        start_time = end_time - timeframe
        
        # Get TCP packets in the timeframe
        tcp_packets = [
            p for p in self.packet_repository.get_packets_in_timeframe(start_time, end_time)
            if isinstance(p, TCPPacket)
        ]
        
        # Group by source IP and destination IP
        scans = defaultdict(lambda: defaultdict(list))
        for packet in tcp_packets:
            if packet.is_syn():
                scans[packet.src_ip][packet.dst_ip].append(packet.dst_port)
        
        attacks = []
        for src_ip, targets in scans.items():
            for dst_ip, ports in targets.items():
                # Check if number of unique ports exceeds threshold
                unique_ports = set(ports)
                if len(unique_ports) < self.thresholds["port_scan_threshold"]:
                    continue
                
                # Get relevant packets for this scan
                scan_packets = [
                    p for p in tcp_packets 
                    if p.src_ip == src_ip and p.dst_ip == dst_ip and p.is_syn()
                ]
                
                attack = PortScanAttack(
                    timestamp=min(p.timestamp for p in scan_packets),
                    attack_type=AttackType.PORT_SCAN,
                    source_ips=[src_ip],
                    target_ips=[dst_ip],
                    severity=min(10, int(len(unique_ports) / self.thresholds["port_scan_threshold"] * 5)),
                    confidence=min(1.0, len(unique_ports) / self.thresholds["port_scan_threshold"]),
                    description=f"Port scan detected: {len(unique_ports)} ports scanned on {dst_ip} from {src_ip}",
                    packet_count=len(scan_packets),
                    scanned_ports=list(unique_ports),
                    scan_type="SYN"
                )
                
                attacks.append(attack)
                self.attack_repository.save_attack(attack)
        
        return attacks
    
    def detect_icmp_flood(self, timeframe: timedelta = timedelta(minutes=5)) -> List[IcmpFloodAttack]:
        """
        Detect ICMP flood attacks within a specific timeframe.
        
        An ICMP flood is characterized by:
        1. High rate of ICMP echo request packets
        2. Often from multiple source IPs
        """
        end_time = datetime.now()
        start_time = end_time - timeframe
        
        # Get ICMP packets in the timeframe
        icmp_packets = [
            p for p in self.packet_repository.get_packets_in_timeframe(start_time, end_time)
            if isinstance(p, ICMPPacket)
        ]
        
        # Group by destination IP
        targets = defaultdict(list)
        for packet in icmp_packets:
            if packet.is_echo_request():
                targets[packet.dst_ip].append(packet)
        
        attacks = []
        for target_ip, echo_packets in targets.items():
            # Check for flood conditions
            if len(echo_packets) < self.thresholds["icmp_flood_rate"] * 5:  # At least 5 seconds worth
                continue
            
            # Calculate rate
            time_span = (max(p.timestamp for p in echo_packets) - 
                         min(p.timestamp for p in echo_packets)).total_seconds()
            if time_span < 1:
                time_span = 1
                
            packet_rate = len(echo_packets) / time_span
            
            # Check if rate exceeds threshold
            if packet_rate < self.thresholds["icmp_flood_rate"]:
                continue
            
            # Count source IPs
            source_ips = set(p.src_ip for p in echo_packets)
            
            # Looks like an ICMP flood
            attack = IcmpFloodAttack(
                timestamp=min(p.timestamp for p in echo_packets),
                attack_type=AttackType.ICMP_FLOOD,
                source_ips=list(source_ips),
                target_ips=[target_ip],
                severity=min(10, int(packet_rate / self.thresholds["icmp_flood_rate"] * 5)),
                confidence=min(1.0, packet_rate / self.thresholds["icmp_flood_rate"]),
                description=f"ICMP flood detected: {len(echo_packets)} packets at {packet_rate:.2f}/sec to {target_ip}",
                packet_count=len(echo_packets),
                icmp_echo_requests=len(echo_packets),
                icmp_echo_replies=sum(1 for p in icmp_packets if p.is_echo_reply() and p.src_ip == target_ip),
                packet_rate=packet_rate
            )
            
            attacks.append(attack)
            self.attack_repository.save_attack(attack)
        
        return attacks
    
    def detect_arp_spoofing(self, timeframe: timedelta = timedelta(minutes=10)) -> List[ArpSpoofingAttack]:
        """
        Detect ARP spoofing attacks within a specific timeframe.
        
        ARP spoofing is characterized by:
        1. ARP responses that change MAC addresses
        2. Unsolicited ARP replies
        """
        end_time = datetime.now()
        start_time = end_time - timeframe
        
        # Get ARP packets in the timeframe
        arp_packets = [
            p for p in self.packet_repository.get_packets_in_timeframe(start_time, end_time)
            if isinstance(p, ARPPacket)
        ]
        
        # Track IP to MAC mappings
        ip_to_mac = defaultdict(list)
        for packet in arp_packets:
            if packet.is_reply():
                ip_to_mac[packet.sender_ip].append(packet.src_mac)
        
        attacks = []
        for ip, mac_list in ip_to_mac.items():
            # Check for IP with multiple MACs
            unique_macs = set(mac_list)
            if len(unique_macs) <= 1:
                continue
            
            # Get the most frequent MAC (likely legitimate)
            mac_counter = Counter(mac_list)
            real_mac, _ = mac_counter.most_common(1)[0]
            
            # Check for other MACs with significant occurrences
            suspicious_macs = [
                (mac, count) for mac, count in mac_counter.items()
                if mac != real_mac and count >= self.thresholds["arp_spoofing_min_packets"]
            ]
            
            if not suspicious_macs:
                continue
            
            for spoofed_mac, count in suspicious_macs:
                # Get the specific packets for this spoofed MAC
                spoof_packets = [
                    p for p in arp_packets
                    if p.is_reply() and p.sender_ip == ip and p.src_mac == spoofed_mac
                ]
                
                # Create an attack entry
                attack = ArpSpoofingAttack(
                    timestamp=min(p.timestamp for p in spoof_packets),
                    attack_type=AttackType.ARP_SPOOFING,
                    source_ips=[p.src_ip for p in spoof_packets if p.src_ip != ip],
                    target_ips=[ip],
                    severity=7,  # ARP spoofing is always severe
                    confidence=min(1.0, count / (mac_counter[real_mac] or 1)),
                    description=f"ARP spoofing detected: {spoofed_mac} pretending to be {ip} (real MAC: {real_mac})",
                    packet_count=count,
                    spoofed_mac=spoofed_mac,
                    real_mac=real_mac,
                    poisoned_hosts=len(set(p.dst_ip for p in spoof_packets if p.dst_ip != ip))
                )
                
                attacks.append(attack)
                self.attack_repository.save_attack(attack)
        
        return attacks
    
    def detect_rst_attack(self, timeframe: timedelta = timedelta(minutes=5)) -> List[RstAttack]:
        """
        Detect RST attacks within a specific timeframe.
        
        An RST attack is characterized by:
        1. Abnormal number of RST packets
        2. Often targeted at specific connections
        """
        end_time = datetime.now()
        start_time = end_time - timeframe
        
        # Get flows in the timeframe
        all_flows = self.flow_repository.get_flows_in_timeframe(start_time, end_time)
        tcp_flows = [f for f in all_flows if isinstance(f, TCPFlow)]
        
        # Group flows by target
        reset_targets = defaultdict(list)
        for flow in tcp_flows:
            if flow.state == FlowState.RESET and flow.rst_count > 0:
                reset_targets[flow.dst_ip].append(flow)
        
        attacks = []
        for target_ip, reset_flows in reset_targets.items():
            # Check if the number of reset flows exceeds threshold
            if len(reset_flows) < self.thresholds["rst_attack_threshold"]:
                continue
            
            # Group by source IP to identify attacker
            by_source = defaultdict(list)
            for flow in reset_flows:
                by_source[flow.src_ip].append(flow)
            
            # For each potential attacker
            for src_ip, flows in by_source.items():
                if len(flows) < self.thresholds["rst_attack_threshold"]:
                    continue
                
                # Get total RST packets
                total_rsts = sum(f.rst_count for f in flows)
                
                attack = RstAttack(
                    timestamp=min(f.start_time for f in flows),
                    attack_type=AttackType.RST_ATTACK,
                    source_ips=[src_ip],
                    target_ips=[target_ip],
                    severity=min(10, int(len(flows) / self.thresholds["rst_attack_threshold"] * 5)),
                    confidence=min(1.0, len(flows) / self.thresholds["rst_attack_threshold"]),
                    description=f"RST attack detected: {len(flows)} connections reset from {src_ip} to {target_ip}",
                    packet_count=sum(f.packet_count for f in flows),
                    rst_count=total_rsts,
                    interrupted_connections=len(flows)
                )
                
                attacks.append(attack)
                self.attack_repository.save_attack(attack)
        
        return attacks
    
    def detect_all_attacks(self, timeframe: timedelta = timedelta(minutes=10)) -> List[Attack]:
        """Detect all types of attacks within a specific timeframe."""
        attacks = []
        
        # Run all detection methods
        attacks.extend(self.detect_syn_flood(timeframe))
        attacks.extend(self.detect_port_scan(timeframe))
        attacks.extend(self.detect_icmp_flood(timeframe))
        attacks.extend(self.detect_arp_spoofing(timeframe))
        attacks.extend(self.detect_rst_attack(timeframe))
        
        return attacks