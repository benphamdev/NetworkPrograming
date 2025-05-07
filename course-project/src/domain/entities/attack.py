"""
Attack entity module - Core domain entity representing network attacks.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Any, List, Optional
from src.utils.logger import log_function_call


class AttackType(Enum):
    """Enum for different types of network attacks."""
    SYN_FLOOD = "syn_flood"
    ARP_SPOOFING = "arp_spoofing"
    ARP_FLOODING = "arp_flooding"
    ICMP_FLOOD = "icmp_flood"
    PORT_SCAN = "port_scan"
    TCP_HIJACKING = "tcp_hijacking"
    RST_ATTACK = "rst_attack"
    UNKNOWN = "unknown"


@dataclass
class Attack:
    """Base Attack class representing a generic network attack."""
    timestamp: datetime
    attack_type: AttackType
    source_ips: List[str]
    target_ips: List[str]
    severity: int  # 1-10 scale
    confidence: float  # 0.0-1.0 scale
    description: str = ""
    packet_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @log_function_call
    def to_dict(self) -> Dict[str, Any]:
        """Convert attack to dictionary representation."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "attack_type": self.attack_type.value,
            "source_ips": self.source_ips,
            "target_ips": self.target_ips,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "packet_count": self.packet_count,
            "metadata": self.metadata
        }


@dataclass
class SynFloodAttack(Attack):
    """SYN Flood attack with specific details."""
    syn_count: int = 0
    syn_ack_count: int = 0
    unique_source_ports: int = 0
    
    @log_function_call
    def to_dict(self) -> Dict[str, Any]:
        """Convert SYN flood attack to dictionary representation."""
        base_dict = super().to_dict()
        syn_flood_dict = {
            "syn_count": self.syn_count,
            "syn_ack_count": self.syn_ack_count,
            "unique_source_ports": self.unique_source_ports
        }
        return {**base_dict, **syn_flood_dict}


@dataclass
class ArpSpoofingAttack(Attack):
    """ARP Spoofing attack with specific details."""
    spoofed_mac: str = ""
    real_mac: Optional[str] = None
    poisoned_hosts: int = 0
    
    @log_function_call
    def to_dict(self) -> Dict[str, Any]:
        """Convert ARP spoofing attack to dictionary representation."""
        base_dict = super().to_dict()
        arp_spoofing_dict = {
            "spoofed_mac": self.spoofed_mac,
            "real_mac": self.real_mac,
            "poisoned_hosts": self.poisoned_hosts
        }
        return {**base_dict, **arp_spoofing_dict}


@dataclass
class PortScanAttack(Attack):
    """Port Scan attack with specific details."""
    scanned_ports: List[int] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    scan_type: str = "SYN"  # SYN, FIN, XMAS, etc.
    
    @log_function_call
    def to_dict(self) -> Dict[str, Any]:
        """Convert port scan attack to dictionary representation."""
        base_dict = super().to_dict()
        port_scan_dict = {
            "scanned_ports": self.scanned_ports,
            "open_ports": self.open_ports,
            "scan_type": self.scan_type,
            "port_count": len(self.scanned_ports)
        }
        return {**base_dict, **port_scan_dict}


@dataclass
class IcmpFloodAttack(Attack):
    """ICMP Flood attack with specific details."""
    icmp_echo_requests: int = 0
    icmp_echo_replies: int = 0
    packet_rate: float = 0.0  # packets per second
    
    @log_function_call
    def to_dict(self) -> Dict[str, Any]:
        """Convert ICMP flood attack to dictionary representation."""
        base_dict = super().to_dict()
        icmp_flood_dict = {
            "icmp_echo_requests": self.icmp_echo_requests,
            "icmp_echo_replies": self.icmp_echo_replies,
            "packet_rate": self.packet_rate
        }
        return {**base_dict, **icmp_flood_dict}


@dataclass
class RstAttack(Attack):
    """RST Attack with specific details."""
    rst_count: int = 0
    interrupted_connections: int = 0
    
    @log_function_call
    def to_dict(self) -> Dict[str, Any]:
        """Convert RST attack to dictionary representation."""
        base_dict = super().to_dict()
        rst_dict = {
            "rst_count": self.rst_count,
            "interrupted_connections": self.interrupted_connections
        }
        return {**base_dict, **rst_dict}


@dataclass
class ArpFloodingAttack(Attack):
    """ARP Flooding attack with specific details."""
    packets_per_second: float = 0.0
    request_count: int = 0
    reply_count: int = 0
    unique_sources: int = 0  # For distributed attacks
    is_distributed: bool = False
    
    @log_function_call
    def to_dict(self) -> Dict[str, Any]:
        """Convert ARP flooding attack to dictionary representation."""
        base_dict = super().to_dict()
        arp_flooding_dict = {
            "packets_per_second": self.packets_per_second,
            "request_count": self.request_count,
            "reply_count": self.reply_count,
            "unique_sources": self.unique_sources,
            "is_distributed": self.is_distributed
        }
        return {**base_dict, **arp_flooding_dict}