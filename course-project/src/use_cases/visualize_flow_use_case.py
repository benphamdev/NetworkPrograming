"""
Visualize Flow Use Case - Creates visualizations for network flows and traffic patterns.
"""
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from abc import ABC, abstractmethod

from src.domain.entities.flow import Flow, TCPFlow, FlowState
from src.domain.entities.attack import Attack, AttackType
from src.domain.repositories.flow_repository import FlowRepository
from src.domain.repositories.attack_repository import AttackRepository


class VisualizationStrategy(ABC):
    """Base abstract class for visualization strategies."""
    
    @abstractmethod
    def create_flow_graph(self, flows: List[Flow], title: str) -> str:
        """Create a graph visualization of network flows."""
        pass
    
    @abstractmethod
    def create_time_series(self, data: List[Tuple[datetime, float]], title: str, y_label: str) -> str:
        """Create a time series visualization."""
        pass
    
    @abstractmethod
    def create_attack_visualization(self, attacks: List[Attack], title: str) -> str:
        """Create a visualization of detected attacks."""
        pass
    
    @abstractmethod
    def create_protocol_distribution(self, counts: Dict[str, int], title: str) -> str:
        """Create a visualization of protocol distribution."""
        pass


class VisualizeFlowUseCase:
    """Use case for visualizing network flows and traffic patterns."""
    
    def __init__(self, flow_repository: FlowRepository, attack_repository: AttackRepository, 
                 visualization_strategy: VisualizationStrategy):
        """Initialize with required repositories and visualization strategy."""
        self.flow_repository = flow_repository
        self.attack_repository = attack_repository
        self.visualization_strategy = visualization_strategy
    
    def visualize_tcp_flows(self, timeframe: timedelta = timedelta(hours=1)) -> str:
        """Create a graph visualization of TCP flows."""
        end_time = datetime.now()
        start_time = end_time - timeframe
        
        # Get flows in the timeframe
        flows = self.flow_repository.get_flows_in_timeframe(start_time, end_time)
        tcp_flows = [f for f in flows if isinstance(f, TCPFlow)]
        
        # Create visualization
        return self.visualization_strategy.create_flow_graph(
            tcp_flows,
            f"TCP Flow Graph: {start_time.strftime('%H:%M:%S')} - {end_time.strftime('%H:%M:%S')}"
        )
    
    def visualize_packet_rate(self, protocol: Optional[str] = None, 
                             timeframe: timedelta = timedelta(hours=1), 
                             interval: timedelta = timedelta(minutes=1)) -> str:
        """Create a time series visualization of packet rate."""
        end_time = datetime.now()
        start_time = end_time - timeframe
        
        # Get flows in the timeframe
        flows = self.flow_repository.get_flows_in_timeframe(start_time, end_time)
        
        # Filter by protocol if specified
        if protocol:
            flows = [f for f in flows if f.protocol.upper() == protocol.upper()]
        
        # Create time buckets
        buckets = []
        current_time = start_time
        
        while current_time < end_time:
            bucket_end = min(current_time + interval, end_time)
            packets_in_interval = sum(
                f.packet_count for f in flows 
                if (f.start_time <= bucket_end and 
                   (f.end_time is None or f.end_time >= current_time))
            )
            
            # Calculate packets per second
            seconds = interval.total_seconds()
            packet_rate = packets_in_interval / seconds if seconds > 0 else 0
            
            buckets.append((current_time, packet_rate))
            current_time = bucket_end
        
        # Create visualization
        protocol_label = f"{protocol} " if protocol else ""
        return self.visualization_strategy.create_time_series(
            buckets,
            f"{protocol_label}Packet Rate: {start_time.strftime('%H:%M:%S')} - {end_time.strftime('%H:%M:%S')}",
            "Packets/second"
        )
    
    def visualize_attacks(self, attack_type: Optional[AttackType] = None,
                         timeframe: timedelta = timedelta(hours=24)) -> str:
        """Create a visualization of detected attacks."""
        end_time = datetime.now()
        start_time = end_time - timeframe
        
        # Get attacks in the timeframe
        attacks = self.attack_repository.get_attacks_in_timeframe(start_time, end_time)
        
        # Filter by attack type if specified
        if attack_type:
            attacks = [a for a in attacks if a.attack_type == attack_type]
        
        # Sort by timestamp
        attacks.sort(key=lambda a: a.timestamp)
        
        # Create visualization
        attack_type_label = f"{attack_type.value} " if attack_type else ""
        return self.visualization_strategy.create_attack_visualization(
            attacks,
            f"{attack_type_label}Attacks: {start_time.strftime('%Y-%m-%d %H:%M')} - {end_time.strftime('%Y-%m-%d %H:%M')}"
        )
    
    def visualize_protocol_distribution(self, timeframe: timedelta = timedelta(hours=1)) -> str:
        """Create a visualization of protocol distribution."""
        end_time = datetime.now()
        start_time = end_time - timeframe
        
        # Get flows in the timeframe
        flows = self.flow_repository.get_flows_in_timeframe(start_time, end_time)
        
        # Count by protocol
        protocol_counts = {}
        for flow in flows:
            protocol = flow.protocol.upper()
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        
        # Create visualization
        return self.visualization_strategy.create_protocol_distribution(
            protocol_counts,
            f"Protocol Distribution: {start_time.strftime('%H:%M:%S')} - {end_time.strftime('%H:%M:%S')}"
        )
    
    def visualize_flow_states(self, protocol: str = "TCP", timeframe: timedelta = timedelta(hours=1)) -> str:
        """Create a visualization of flow states."""
        end_time = datetime.now()
        start_time = end_time - timeframe
        
        # Get flows in the timeframe
        flows = self.flow_repository.get_flows_in_timeframe(start_time, end_time)
        flows = [f for f in flows if f.protocol.upper() == protocol.upper()]
        
        # Count by state
        state_counts = {}
        for flow in flows:
            state = flow.state.value
            state_counts[state] = state_counts.get(state, 0) + 1
        
        # Create visualization
        return self.visualization_strategy.create_protocol_distribution(
            state_counts,
            f"{protocol} Flow States: {start_time.strftime('%H:%M:%S')} - {end_time.strftime('%H:%M:%S')}"
        ) 