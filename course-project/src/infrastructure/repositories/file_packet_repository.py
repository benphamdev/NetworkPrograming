"""
File Packet Repository - Implementation of PacketRepository for file storage.
"""
from datetime import datetime
from typing import Dict, Any, List, Optional
import os
import pickle
from collections import defaultdict

from src.domain.packet import Packet, TCPPacket, ICMPPacket
from src.domain.repositories.packet_repository import PacketRepository
from src.interfaces.gateways.scapy_packet_gateway import ScapyPacketGateway


class FilePacketRepository(PacketRepository):
    """Repository for storing packets in files."""
    
    def __init__(self, storage_dir: str = "packet_storage"):
        """
        Initialize the file packet repository.
        
        Args:
            storage_dir: Directory to store packet data
        """
        self.storage_dir = storage_dir
        self.scapy_gateway = ScapyPacketGateway()
        self.packets = []  # In-memory cache
        self.packet_index = defaultdict(list)  # Index for faster lookups
        self.next_id = 1
        
        # Create storage directory if it doesn't exist
        os.makedirs(storage_dir, exist_ok=True)
    
    def save_packet(self, packet: Packet) -> None:
        """
        Save a packet to the repository.
        
        Args:
            packet: Packet entity to save
        """
        # Assign an ID if not already set
        if not hasattr(packet, 'id') or packet.id == 0:
            packet.id = self.next_id
            self.next_id += 1
        
        # Add to in-memory cache
        self.packets.append(packet)
        
        # Update indices
        self.packet_index['protocol'].append((packet.protocol, packet))
        self.packet_index['src_ip'].append((packet.src_ip, packet))
        self.packet_index['dst_ip'].append((packet.dst_ip, packet))
        
        # Save to file periodically (every 1000 packets)
        if len(self.packets) % 1000 == 0:
            self._persist_to_file()
    
    def get_packet_by_id(self, packet_id: int) -> Optional[Packet]:
        """
        Get a packet by its ID.
        
        Args:
            packet_id: ID of the packet to retrieve
            
        Returns:
            Packet entity or None if not found
        """
        for packet in self.packets:
            if hasattr(packet, 'id') and packet.id == packet_id:
                return packet
        return None
    
    def get_packets_by_protocol(self, protocol: str) -> List[Packet]:
        """
        Get all packets of a specific protocol.
        
        Args:
            protocol: Protocol name (e.g., "TCP", "ICMP")
            
        Returns:
            List of matching Packet entities
        """
        return [p for _, p in self.packet_index['protocol'] if _.upper() == protocol.upper()]
    
    def get_packets_by_ip(self, ip_address: str, is_source: bool = True) -> List[Packet]:
        """
        Get all packets with a specific IP address.
        
        Args:
            ip_address: IP address to match
            is_source: If True, match source IP; if False, match destination IP
            
        Returns:
            List of matching Packet entities
        """
        key = 'src_ip' if is_source else 'dst_ip'
        return [p for _, p in self.packet_index[key] if _ == ip_address]
    
    def get_packets_in_timeframe(self, start_time: datetime, end_time: datetime) -> List[Packet]:
        """
        Get all packets within a specific timeframe.
        
        Args:
            start_time: Start of timeframe
            end_time: End of timeframe
            
        Returns:
            List of matching Packet entities
        """
        return [p for p in self.packets if start_time <= p.timestamp <= end_time]
    
    def query_packets(self, query: Dict[str, Any]) -> List[Packet]:
        """
        Query packets based on various criteria.
        
        Args:
            query: Dictionary of query parameters
            
        Returns:
            List of matching Packet entities
        """
        result = self.packets
        
        # Filter by protocol if specified
        if 'protocol' in query:
            protocol = query['protocol']
            result = [p for p in result if p.protocol.upper() == protocol.upper()]
        
        # Filter by source IP if specified
        if 'src_ip' in query:
            src_ip = query['src_ip']
            result = [p for p in result if p.src_ip == src_ip]
        
        # Filter by destination IP if specified
        if 'dst_ip' in query:
            dst_ip = query['dst_ip']
            result = [p for p in result if p.dst_ip == dst_ip]
        
        # Filter by timeframe if specified
        if 'start_time' in query and 'end_time' in query:
            start_time = query['start_time']
            end_time = query['end_time']
            result = [p for p in result if start_time <= p.timestamp <= end_time]
        
        # Filter by specific fields for packet subtypes
        if 'tcp_flags' in query:
            flags = query['tcp_flags']
            result = [p for p in result if isinstance(p, TCPPacket) and all(f in p.tcp_flags for f in flags)]
        
        if 'icmp_type' in query:
            icmp_type = query['icmp_type']
            result = [p for p in result if isinstance(p, ICMPPacket) and p.icmp_type == icmp_type]
        
        return result
    
    def count_packets(self, query: Dict[str, Any]) -> int:
        """
        Count packets matching specific criteria.
        
        Args:
            query: Dictionary of query parameters
            
        Returns:
            Count of matching packets
        """
        return len(self.query_packets(query))
    
    def delete_packet(self, packet_id: int) -> bool:
        """
        Delete a packet by its ID.
        
        Args:
            packet_id: ID of the packet to delete
            
        Returns:
            True if packet was deleted, False otherwise
        """
        packet = self.get_packet_by_id(packet_id)
        if packet:
            self.packets = [p for p in self.packets if p.id != packet_id]
            
            # Update indices
            for key in self.packet_index:
                self.packet_index[key] = [(k, p) for k, p in self.packet_index[key] if p.id != packet_id]
            
            return True
        return False
    
    def clear_all(self) -> None:
        """Clear all packets in the repository."""
        self.packets = []
        self.packet_index = defaultdict(list)
        self.next_id = 1
    
    def load_pcap_file(self, file_path: str) -> List[Packet]:
        """
        Load packets from a pcap file.
        
        Args:
            file_path: Path to the pcap file
            
        Returns:
            List of Packet entities loaded from the file
        """
        packets = self.scapy_gateway.read_pcap_file(file_path)
        
        # Save packets to repository
        for packet in packets:
            self.save_packet(packet)
        
        return packets
    
    def _persist_to_file(self) -> None:
        """Persist packets to file."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(self.storage_dir, f"packets_{timestamp}.pkl")
        
        with open(output_file, 'wb') as f:
            pickle.dump(self.packets, f)
    
    def _load_from_file(self, file_path: str) -> None:
        """
        Load packets from a persisted file.
        
        Args:
            file_path: Path to the persisted packet file
        """
        with open(file_path, 'rb') as f:
            loaded_packets = pickle.load(f)
        
        # Add loaded packets to repository
        for packet in loaded_packets:
            self.save_packet(packet)