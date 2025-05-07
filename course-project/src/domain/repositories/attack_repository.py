"""
Attack repository interface - Defines interaction with attack storage.
"""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional, Dict, Any

from src.domain.entities.attack import Attack, AttackType
from src.utils.logger import log_function_call


class AttackRepository(ABC):
    """Interface for attack repositories."""
    
    @abstractmethod
    @log_function_call
    def save_attack(self, attack: Attack) -> None:
        """Save an attack to the repository."""
        pass
    
    @abstractmethod
    @log_function_call
    def get_attack_by_id(self, attack_id: int) -> Optional[Attack]:
        """Get an attack by its ID."""
        pass
    
    @abstractmethod
    @log_function_call
    def get_attacks_by_type(self, attack_type: AttackType) -> List[Attack]:
        """Get all attacks of a specific type."""
        pass
    
    @abstractmethod
    @log_function_call
    def get_attacks_by_ip(self, ip_address: str, is_source: bool = True) -> List[Attack]:
        """Get all attacks involving a specific IP address."""
        pass
    
    @abstractmethod
    @log_function_call
    def get_attacks_in_timeframe(self, start_time: datetime, end_time: datetime) -> List[Attack]:
        """Get all attacks within a specific timeframe."""
        pass
    
    @abstractmethod
    @log_function_call
    def query_attacks(self, query: Dict[str, Any]) -> List[Attack]:
        """Query attacks based on various criteria."""
        pass
    
    @abstractmethod
    @log_function_call
    def count_attacks(self, query: Dict[str, Any]) -> int:
        """Count attacks matching specific criteria."""
        pass
    
    @abstractmethod
    @log_function_call
    def delete_attack(self, attack_id: int) -> bool:
        """Delete an attack by its ID."""
        pass
    
    @abstractmethod
    @log_function_call
    def clear_all(self) -> None:
        """Clear all attacks in the repository."""
        pass