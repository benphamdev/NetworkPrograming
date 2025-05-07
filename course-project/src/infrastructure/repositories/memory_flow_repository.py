"""
Memory Flow Repository - Implementation of FlowRepository for in-memory storage.
"""
from datetime import datetime
from typing import Dict, Any, List, Optional
from collections import defaultdict

from src.domain.entities.flow import Flow, FlowState
from src.domain.repositories.flow_repository import FlowRepository


class MemoryFlowRepository(FlowRepository):
    """Repository for storing flows in memory."""
    
    def __init__(self):
        """Initialize the memory flow repository."""
        self.flows = {}  # flow_id -> Flow
        self.flow_index = defaultdict(list)  # Index for faster lookups
    
    def save_flow(self, flow: Flow) -> None:
        """
        Save a flow to the repository.
        
        Args:
            flow: Flow entity to save
        """
        # Use the flow_id property as the key
        flow_id = flow.flow_id
        
        # Add or update the flow
        self.flows[flow_id] = flow
        
        # Update indices
        self.flow_index['protocol'].append((flow.protocol, flow))
        self.flow_index['src_ip'].append((flow.src_ip, flow))
        self.flow_index['dst_ip'].append((flow.dst_ip, flow))
        
        if hasattr(flow, 'state'):
            self.flow_index['state'].append((flow.state, flow))
    
    def get_flow_by_id(self, flow_id: str) -> Optional[Flow]:
        """
        Get a flow by its ID.
        
        Args:
            flow_id: ID of the flow to retrieve
            
        Returns:
            Flow entity or None if not found
        """
        return self.flows.get(flow_id)
    
    def get_flows_by_protocol(self, protocol: str) -> List[Flow]:
        """
        Get all flows of a specific protocol.
        
        Args:
            protocol: Protocol name (e.g., "TCP", "ICMP")
            
        Returns:
            List of matching Flow entities
        """
        return [f for proto, f in self.flow_index['protocol'] if proto.upper() == protocol.upper()]
    
    def get_flows_by_ip(self, ip_address: str, is_source: bool = True) -> List[Flow]:
        """
        Get all flows with a specific IP address.
        
        Args:
            ip_address: IP address to match
            is_source: If True, match source IP; if False, match destination IP
            
        Returns:
            List of matching Flow entities
        """
        key = 'src_ip' if is_source else 'dst_ip'
        return [f for ip, f in self.flow_index[key] if ip == ip_address]
    
    def get_flows_by_state(self, state: FlowState) -> List[Flow]:
        """
        Get all flows with a specific state.
        
        Args:
            state: Flow state to match
            
        Returns:
            List of matching Flow entities
        """
        return [f for s, f in self.flow_index['state'] if s == state]
    
    def get_flows_in_timeframe(self, start_time: datetime, end_time: datetime) -> List[Flow]:
        """
        Get all flows within a specific timeframe.
        
        Args:
            start_time: Start of timeframe
            end_time: End of timeframe
            
        Returns:
            List of matching Flow entities
        """
        # A flow is in the timeframe if:
        # 1. It started during the timeframe, or
        # 2. It ended during the timeframe, or
        # 3. It started before the timeframe and is still active (no end_time)
        result = []
        for flow in self.flows.values():
            # Flow started during timeframe
            if start_time <= flow.start_time <= end_time:
                result.append(flow)
                continue
                
            # Flow ended during timeframe
            if flow.end_time and start_time <= flow.end_time <= end_time:
                result.append(flow)
                continue
                
            # Flow started before timeframe and is still active or ended after timeframe
            if flow.start_time <= start_time and (not flow.end_time or flow.end_time >= start_time):
                result.append(flow)
                continue
                
        return result
    
    def query_flows(self, query: Dict[str, Any]) -> List[Flow]:
        """
        Query flows based on various criteria.
        
        Args:
            query: Dictionary of query parameters
            
        Returns:
            List of matching Flow entities
        """
        result = list(self.flows.values())
        
        # Filter by protocol if specified
        if 'protocol' in query:
            protocol = query['protocol']
            result = [f for f in result if f.protocol.upper() == protocol.upper()]
        
        # Filter by source IP if specified
        if 'src_ip' in query:
            src_ip = query['src_ip']
            result = [f for f in result if f.src_ip == src_ip]
        
        # Filter by destination IP if specified
        if 'dst_ip' in query:
            dst_ip = query['dst_ip']
            result = [f for f in result if f.dst_ip == dst_ip]
        
        # Filter by state if specified
        if 'state' in query:
            state = query['state']
            if isinstance(state, str):
                result = [f for f in result if hasattr(f, 'state') and f.state.value == state]
            else:
                result = [f for f in result if hasattr(f, 'state') and f.state == state]
        
        # Filter by minimum packet count if specified
        if 'min_packet_count' in query:
            min_packet_count = query['min_packet_count']
            result = [f for f in result if f.packet_count >= min_packet_count]
        
        # Filter by time window if specified
        if 'time_window' in query:
            window_start = query.get('time_window_start', datetime.min)
            window_end = query.get('time_window_end', datetime.max)
            
            filtered_result = []
            for flow in result:
                # Flow started during timeframe
                if window_start <= flow.start_time <= window_end:
                    filtered_result.append(flow)
                    continue
                    
                # Flow ended during timeframe
                if flow.end_time and window_start <= flow.end_time <= window_end:
                    filtered_result.append(flow)
                    continue
                    
                # Flow started before timeframe and is still active or ended after timeframe
                if flow.start_time <= window_start and (not flow.end_time or flow.end_time >= window_start):
                    filtered_result.append(flow)
                    continue
            
            result = filtered_result
        
        return result
    
    def count_flows(self, query: Dict[str, Any]) -> int:
        """
        Count flows matching specific criteria.
        
        Args:
            query: Dictionary of query parameters
            
        Returns:
            Count of matching flows
        """
        return len(self.query_flows(query))
    
    def delete_flow(self, flow_id: str) -> bool:
        """
        Delete a flow by its ID.
        
        Args:
            flow_id: ID of the flow to delete
            
        Returns:
            True if flow was deleted, False otherwise
        """
        if flow_id in self.flows:
            flow = self.flows[flow_id]
            del self.flows[flow_id]
            
            # Update indices
            for key in self.flow_index:
                if key == 'state':
                    self.flow_index[key] = [(s, f) for s, f in self.flow_index[key] if f.flow_id != flow_id]
                else:
                    self.flow_index[key] = [(k, f) for k, f in self.flow_index[key] if f.flow_id != flow_id]
            
            return True
        return False
    
    def clear_all(self) -> None:
        """Clear all flows in the repository."""
        self.flows = {}
        self.flow_index = defaultdict(list) 