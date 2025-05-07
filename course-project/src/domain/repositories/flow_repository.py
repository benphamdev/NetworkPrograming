"""
Flow repository interface - Defines interaction with flow storage.
"""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional, Dict, Any

from src.domain.entities.flow import Flow, FlowState
from src.utils.logger import log_function_call


class FlowRepository(ABC):
    """Interface for flow repositories."""
    
    @abstractmethod
    @log_function_call
    def save_flow(self, flow: Flow) -> None:
        """Save a flow to the repository."""
        pass
    
    @abstractmethod
    @log_function_call
    def get_flow_by_id(self, flow_id: str) -> Optional[Flow]:
        """Get a flow by its ID."""
        pass
    
    @abstractmethod
    @log_function_call
    def get_flows_by_protocol(self, protocol: str) -> List[Flow]:
        """Get all flows of a specific protocol."""
        pass
    
    @abstractmethod
    @log_function_call
    def get_flows_by_ip(self, ip_address: str, is_source: bool = True) -> List[Flow]:
        """Get all flows with a specific IP address."""
        pass
    
    @abstractmethod
    @log_function_call
    def get_flows_by_state(self, state: FlowState) -> List[Flow]:
        """Get all flows with a specific state."""
        pass
    
    @abstractmethod
    @log_function_call
    def get_flows_in_timeframe(self, start_time: datetime, end_time: datetime) -> List[Flow]:
        """Get all flows within a specific timeframe."""
        pass
    
    @abstractmethod
    @log_function_call
    def query_flows(self, query: Dict[str, Any]) -> List[Flow]:
        """Query flows based on various criteria."""
        pass
    
    @abstractmethod
    @log_function_call
    def count_flows(self, query: Dict[str, Any]) -> int:
        """Count flows matching specific criteria."""
        pass
    
    @abstractmethod
    @log_function_call
    def delete_flow(self, flow_id: str) -> bool:
        """Delete a flow by its ID."""
        pass
    
    @abstractmethod
    @log_function_call
    def clear_all(self) -> None:
        """Clear all flows in the repository."""
        pass