"""
Flow entity module - Core domain entity representing network flows.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional



class FlowState(Enum):
    """Enum for different states of network flows."""
    ESTABLISHED = "established"
    RESET = "reset"
    CLOSED = "closed"
    INCOMPLETE = "incomplete"
    UNKNOWN = "unknown"


@dataclass
class Flow:
    """Base Flow class representing a generic network flow between endpoints."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: datetime
    end_time: Optional[datetime] = None
    state: FlowState = FlowState.UNKNOWN
    packet_count: int = 0
    byte_count: int = 0
    retransmissions: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    # @log_function_call
    def to_dict(self) -> Dict[str, Any]:
        """Convert flow to dictionary representation."""
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "state": self.state.value,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "retransmissions": self.retransmissions,
            "metadata": self.metadata
        }

    @property
    # @log_function_call
    def duration(self) -> float:
        """Return flow duration in seconds."""
        if self.end_time is None:
            return 0.0
        return (self.end_time - self.start_time).total_seconds()

    @property
    # @log_function_call
    def flow_id(self) -> str:
        """Generate a unique ID for this flow."""
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}"


@dataclass
class TCPFlow(Flow):
    """TCP Flow with TCP-specific fields."""
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    window_scaling: bool = False
    mss: int = 0
    handshake_completed: bool = False
    graceful_close: bool = False

    # @log_function_call
    def to_dict(self) -> Dict[str, Any]:
        """Convert TCP flow to dictionary representation."""
        base_dict = super().to_dict()
        tcp_dict = {
            "syn_count": self.syn_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "window_scaling": self.window_scaling,
            "mss": self.mss,
            "handshake_completed": self.handshake_completed,
            "graceful_close": self.graceful_close
        }
        return {**base_dict, **tcp_dict}


@dataclass
class HTTPFlow(TCPFlow):
    """HTTP Flow with HTTP-specific fields."""
    http_method: str = ""
    url: str = ""
    status_code: int = 0
    content_type: str = ""
    host: str = ""
    user_agent: str = ""

    # @log_function_call
    def to_dict(self) -> Dict[str, Any]:
        """Convert HTTP flow to dictionary representation."""
        base_dict = super().to_dict()
        http_dict = {
            "http_method": self.http_method,
            "url": self.url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "host": self.host,
            "user_agent": self.user_agent
        }
        return {**base_dict, **http_dict}


@dataclass
class UDPFlow(Flow):
    """UDP Flow with UDP-specific fields."""
    dns_query: bool = False
    dns_response: bool = False

    # @log_function_call
    def to_dict(self) -> Dict[str, Any]:
        """Convert UDP flow to dictionary representation."""
        base_dict = super().to_dict()
        udp_dict = {
            "dns_query": self.dns_query,
            "dns_response": self.dns_response
        }
        return {**base_dict, **udp_dict}


@dataclass
class ICMPFlow(Flow):
    """ICMP Flow with ICMP-specific fields."""
    echo_requests: int = 0
    echo_replies: int = 0

    # @log_function_call
    def to_dict(self) -> Dict[str, Any]:
        """Convert ICMP flow to dictionary representation."""
        base_dict = super().to_dict()
        icmp_dict = {
            "echo_requests": self.echo_requests,
            "echo_replies": self.echo_replies
        }
        return {**base_dict, **icmp_dict}
