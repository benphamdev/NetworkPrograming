"""
Packet entity module - Core domain entity representing a network packet.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any
from src.utils.logger import log_function_call


@dataclass
class Packet:
    """Base Packet class representing a generic network packet."""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    id: int = field(default=0)
    ttl: int = field(default=0)
    flags: str = field(default="")
    raw_data: bytes = field(default=b"", repr=False)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @log_function_call
    def to_dict(self) -> Dict[str, Any]:
        """Convert packet to dictionary representation."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "length": self.length,
            "id": self.id,
            "ttl": self.ttl,
            "flags": self.flags,
            "metadata": self.metadata
        }


@dataclass
class TCPPacket(Packet):
    """TCP Packet with TCP-specific fields."""
    src_port: int = 0
    dst_port: int = 0
    seq_number: int = 0
    ack_number: int = 0
    window_size: int = 0
    tcp_flags: str = ""
    payload: bytes = field(default=b"", repr=False)
    retransmission: bool = False
    
    @log_function_call
    def has_flag(self, flag: str) -> bool:
        """Check if packet has specific TCP flag."""
        return flag in self.tcp_flags
    
    @log_function_call
    def is_syn(self) -> bool:
        """Check if packet is SYN."""
        return "S" in self.tcp_flags and "A" not in self.tcp_flags
    
    @log_function_call
    def is_syn_ack(self) -> bool:
        """Check if packet is SYN-ACK."""
        return "S" in self.tcp_flags and "A" in self.tcp_flags
    
    @log_function_call
    def is_rst(self) -> bool:
        """Check if packet is RST."""
        return "R" in self.tcp_flags
    
    @log_function_call
    def is_fin(self) -> bool:
        """Check if packet is FIN."""
        return "F" in self.tcp_flags
    
    @log_function_call
    def to_dict(self) -> Dict[str, Any]:
        """Convert packet to dictionary representation."""
        base_dict = super().to_dict()
        tcp_dict = {
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "seq_number": self.seq_number,
            "ack_number": self.ack_number,
            "window_size": self.window_size,
            "tcp_flags": self.tcp_flags,
            "retransmission": self.retransmission,
            "has_payload": len(self.payload) > 0
        }
        return {**base_dict, **tcp_dict}


@dataclass
class ARPPacket(Packet):
    """ARP Packet with ARP-specific fields."""
    op_code: int = 0  # 1=request, 2=reply
    src_mac: str = ""
    dst_mac: str = ""
    target_ip: str = ""
    sender_ip: str = ""
    
    @log_function_call
    def is_request(self) -> bool:
        """Check if ARP packet is a request."""
        return self.op_code == 1
    
    @log_function_call
    def is_reply(self) -> bool:
        """Check if ARP packet is a reply."""
        return self.op_code == 2
    
    @log_function_call
    def to_dict(self) -> Dict[str, Any]:
        """Convert packet to dictionary representation."""
        base_dict = super().to_dict()
        arp_dict = {
            "op_code": self.op_code,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "target_ip": self.target_ip,
            "sender_ip": self.sender_ip,
            "is_request": self.is_request(),
            "is_reply": self.is_reply()
        }
        return {**base_dict, **arp_dict}


@dataclass
class ICMPPacket(Packet):
    """ICMP Packet with ICMP-specific fields."""
    icmp_type: int = 0
    icmp_code: int = 0
    icmp_seq: int = 0
    payload: bytes = field(default=b"", repr=False)
    
    @log_function_call
    def is_echo_request(self) -> bool:
        """Check if ICMP packet is echo request (ping)."""
        return self.icmp_type == 8 and self.icmp_code == 0
    
    @log_function_call
    def is_echo_reply(self) -> bool:
        """Check if ICMP packet is echo reply (ping response)."""
        return self.icmp_type == 0 and self.icmp_code == 0
    
    @log_function_call
    def to_dict(self) -> Dict[str, Any]:
        """Convert packet to dictionary representation."""
        base_dict = super().to_dict()
        icmp_dict = {
            "icmp_type": self.icmp_type,
            "icmp_code": self.icmp_code,
            "icmp_seq": self.icmp_seq,
            "is_echo_request": self.is_echo_request(),
            "is_echo_reply": self.is_echo_reply(),
            "has_payload": len(self.payload) > 0
        }
        return {**base_dict, **icmp_dict}