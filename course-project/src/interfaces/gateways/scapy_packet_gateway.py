"""
Scapy Packet Gateway - Reads and parses pcap files using Scapy library.
"""
from datetime import datetime
from typing import List, Optional
from scapy.all import rdpcap, Packet as ScapyPacket
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP

from src.domain.packet import Packet, TCPPacket, ICMPPacket, ARPPacket


class ScapyPacketGateway:
    """Gateway for reading packets using Scapy library."""
    
    def read_pcap_file(self, file_path: str) -> List[Packet]:
        """Read a pcap file and return a list of Packet entities."""
        try:
            # Read the pcap file using Scapy
            scapy_packets = rdpcap(file_path)
            
            # Convert Scapy packets to domain entities
            packets = []
            for idx, pkt in enumerate(scapy_packets):
                domain_packet = self._convert_to_domain_packet(pkt, idx)
                if domain_packet:
                    packets.append(domain_packet)
            
            return packets
        except Exception as e:
            print(f"Error reading pcap file: {e}")
            return []
    
    def _convert_to_domain_packet(self, scapy_pkt: ScapyPacket, idx: int) -> Optional[Packet]:
        """Convert a Scapy packet to a domain packet entity."""
        # Check if packet has IP layer
        if IP in scapy_pkt:
            src_ip = scapy_pkt[IP].src
            dst_ip = scapy_pkt[IP].dst
            protocol = self._get_protocol_name(scapy_pkt[IP].proto)
            length = len(scapy_pkt)
            timestamp = datetime.fromtimestamp(float(scapy_pkt.time))
            packet_id = scapy_pkt[IP].id
            ttl = scapy_pkt[IP].ttl
            
            # Create the appropriate packet type based on protocol
            if TCP in scapy_pkt:
                tcp = scapy_pkt[TCP]
                tcp_flags = self._parse_tcp_flags(tcp.flags)
                
                # Check for retransmission (basic heuristic)
                retransmission = False  # This would need packet tracking logic
                
                return TCPPacket(
                    timestamp=timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    length=length,
                    id=packet_id,
                    ttl=ttl,
                    flags=tcp_flags,
                    raw_data=bytes(scapy_pkt),
                    src_port=tcp.sport,
                    dst_port=tcp.dport,
                    seq_number=tcp.seq,
                    ack_number=tcp.ack,
                    window_size=tcp.window,
                    tcp_flags=tcp_flags,
                    payload=bytes(tcp.payload),
                    retransmission=retransmission
                )
            
            elif ICMP in scapy_pkt:
                icmp = scapy_pkt[ICMP]
                return ICMPPacket(
                    timestamp=timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    length=length,
                    id=packet_id,
                    ttl=ttl,
                    raw_data=bytes(scapy_pkt),
                    icmp_type=icmp.type,
                    icmp_code=icmp.code,
                    icmp_seq=getattr(icmp, 'seq', 0),
                    payload=bytes(icmp.payload)
                )
            
            elif UDP in scapy_pkt:
                udp = scapy_pkt[UDP]
                return Packet(
                    timestamp=timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    length=length,
                    id=packet_id,
                    ttl=ttl,
                    raw_data=bytes(scapy_pkt),
                    metadata={
                        "src_port": udp.sport,
                        "dst_port": udp.dport,
                        "length": udp.len
                    }
                )
            
            else:
                return Packet(
                    timestamp=timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    length=length,
                    id=packet_id,
                    ttl=ttl,
                    raw_data=bytes(scapy_pkt)
                )
        
        # Check for ARP packets
        elif ARP in scapy_pkt:
            arp = scapy_pkt[ARP]
            timestamp = datetime.fromtimestamp(float(scapy_pkt.time))
            
            # Get src and dst MAC addresses
            src_mac = arp.hwsrc
            dst_mac = arp.hwdst
            
            return ARPPacket(
                timestamp=timestamp,
                src_ip=arp.psrc,
                dst_ip=arp.pdst,
                protocol="ARP",
                length=len(scapy_pkt),
                raw_data=bytes(scapy_pkt),
                op_code=arp.op,
                src_mac=src_mac,
                dst_mac=dst_mac,
                target_ip=arp.pdst,
                sender_ip=arp.psrc
            )
        
        # Unhandled packet type
        else:
            # Basic fallback for other packet types
            try:
                timestamp = datetime.fromtimestamp(float(scapy_pkt.time))
                return Packet(
                    timestamp=timestamp,
                    src_ip="0.0.0.0",
                    dst_ip="0.0.0.0",
                    protocol="UNKNOWN",
                    length=len(scapy_pkt),
                    raw_data=bytes(scapy_pkt)
                )
            except:
                # If we can't even create a basic packet, skip it
                return None
    
    def _get_protocol_name(self, proto_num: int) -> str:
        """Convert IP protocol number to name."""
        protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            2: "IGMP",
            89: "OSPF"
        }
        return protocol_map.get(proto_num, f"PROTO_{proto_num}")
    
    def _parse_tcp_flags(self, flags: int) -> str:
        """Parse TCP flags to string representation."""
        flag_map = {
            0x01: "F",  # FIN
            0x02: "S",  # SYN
            0x04: "R",  # RST
            0x08: "P",  # PSH
            0x10: "A",  # ACK
            0x20: "U",  # URG
            0x40: "E",  # ECE
            0x80: "C"   # CWR
        }
        
        result = ""
        for bit, char in flag_map.items():
            if flags & bit:
                result += char
        
        return result