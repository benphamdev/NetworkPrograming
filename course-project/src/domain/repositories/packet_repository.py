"""
Packet repository interface - Defines interaction with packet storage.
"""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional, Dict, Any

from src.domain.packet import Packet
from src.utils.logger import log_function_call


class PacketRepository(ABC):
    """Interface for packet repositories."""
    
    @abstractmethod
    @log_function_call
    def save_packet(self, packet: Packet) -> None:
        """Save a packet to the repository."""
        pass
    
    @abstractmethod
    @log_function_call
    def get_packet_by_id(self, packet_id: int) -> Optional[Packet]:
        """Get a packet by its ID."""
        pass
    
    @abstractmethod
    @log_function_call
    def get_packets_by_protocol(self, protocol: str) -> List[Packet]:
        """Get all packets of a specific protocol."""
        pass
    
    @abstractmethod
    @log_function_call
    def get_packets_by_ip(self, ip_address: str, is_source: bool = True) -> List[Packet]:
        """Get all packets with a specific IP address."""
        pass
    
    @abstractmethod
    @log_function_call
    def get_packets_in_timeframe(self, start_time: datetime, end_time: datetime) -> List[Packet]:
        """Get all packets within a specific timeframe."""
        pass
    
    @abstractmethod
    @log_function_call
    def get_all_packets(self) -> List[Packet]:
        """Get all packets without timeframe constraint."""
        pass
    
    @abstractmethod
    @log_function_call
    def query_packets(self, query: Dict[str, Any]) -> List[Packet]:
        """Query packets based on various criteria."""
        pass
    
    @abstractmethod
    @log_function_call
    def count_packets(self, query: Dict[str, Any]) -> int:
        """Count packets matching specific criteria."""
        pass
    
    @abstractmethod
    @log_function_call
    def delete_packet(self, packet_id: int) -> bool:
        """Delete a packet by its ID."""
        pass
    
    @abstractmethod
    @log_function_call
    def clear_all(self) -> None:
        """Clear all packets in the repository."""
        pass
    
    @abstractmethod
    @log_function_call
    def load_pcap_file(self, file_path: str) -> List[Packet]:
        """Load packets from a pcap file."""
        pass