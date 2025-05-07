"""
Memory Attack Repository - Implementation of AttackRepository for in-memory storage.
"""
from datetime import datetime
from typing import Dict, Any, List, Optional
from collections import defaultdict

from src.domain.entities.attack import Attack, AttackType
from src.domain.repositories.attack_repository import AttackRepository


class MemoryAttackRepository(AttackRepository):
    """Repository for storing attacks in memory."""
    
    def __init__(self):
        """Initialize the memory attack repository."""
        self.attacks = []  # In-memory storage
        self.attack_index = defaultdict(list)  # Index for faster lookups
        self.next_id = 1
    
    def save_attack(self, attack: Attack) -> None:
        """
        Save an attack to the repository.
        
        Args:
            attack: Attack entity to save
        """
        # Assign an ID if not already set
        if not hasattr(attack, 'id'):
            setattr(attack, 'id', self.next_id)
            self.next_id += 1
        
        # Add to in-memory storage
        self.attacks.append(attack)
        
        # Update indices
        attack_type = attack.attack_type
        self.attack_index['type'].append((attack_type, attack))
        
        for src_ip in attack.source_ips:
            self.attack_index['src_ip'].append((src_ip, attack))
        
        for target_ip in attack.target_ips:
            self.attack_index['target_ip'].append((target_ip, attack))
    
    def get_attack_by_id(self, attack_id: int) -> Optional[Attack]:
        """
        Get an attack by its ID.
        
        Args:
            attack_id: ID of the attack to retrieve
            
        Returns:
            Attack entity or None if not found
        """
        for attack in self.attacks:
            if hasattr(attack, 'id') and attack.id == attack_id:
                return attack
        return None
    
    def get_attacks_by_type(self, attack_type: AttackType) -> List[Attack]:
        """
        Get all attacks of a specific type.
        
        Args:
            attack_type: Type of attack to retrieve
            
        Returns:
            List of matching Attack entities
        """
        return [a for t, a in self.attack_index['type'] if t == attack_type]
    
    def get_attacks_by_ip(self, ip_address: str, is_source: bool = True) -> List[Attack]:
        """
        Get all attacks involving a specific IP address.
        
        Args:
            ip_address: IP address to match
            is_source: If True, match source IP; if False, match target IP
            
        Returns:
            List of matching Attack entities
        """
        key = 'src_ip' if is_source else 'target_ip'
        return [a for ip, a in self.attack_index[key] if ip == ip_address]
    
    def get_attacks_in_timeframe(self, start_time: datetime, end_time: datetime) -> List[Attack]:
        """
        Get all attacks within a specific timeframe.
        
        Args:
            start_time: Start of timeframe
            end_time: End of timeframe
            
        Returns:
            List of matching Attack entities
        """
        return [a for a in self.attacks if start_time <= a.timestamp <= end_time]
    
    def query_attacks(self, query: Dict[str, Any]) -> List[Attack]:
        """
        Query attacks based on various criteria.
        
        Args:
            query: Dictionary of query parameters
            
        Returns:
            List of matching Attack entities
        """
        result = self.attacks
        
        # Filter by attack type if specified
        if 'attack_type' in query:
            attack_type = query['attack_type']
            if isinstance(attack_type, str):
                result = [a for a in result if a.attack_type.value == attack_type]
            else:
                result = [a for a in result if a.attack_type == attack_type]
        
        # Filter by source IP if specified
        if 'source_ip' in query:
            source_ip = query['source_ip']
            result = [a for a in result if source_ip in a.source_ips]
        
        # Filter by target IP if specified
        if 'target_ip' in query:
            target_ip = query['target_ip']
            result = [a for a in result if target_ip in a.target_ips]
        
        # Filter by minimum severity if specified
        if 'min_severity' in query:
            min_severity = query['min_severity']
            result = [a for a in result if a.severity >= min_severity]
        
        # Filter by minimum confidence if specified
        if 'min_confidence' in query:
            min_confidence = query['min_confidence']
            result = [a for a in result if a.confidence >= min_confidence]
        
        # Filter by timeframe if specified
        if 'start_time' in query and 'end_time' in query:
            start_time = query['start_time']
            end_time = query['end_time']
            result = [a for a in result if start_time <= a.timestamp <= end_time]
        
        return result
    
    def count_attacks(self, query: Dict[str, Any]) -> int:
        """
        Count attacks matching specific criteria.
        
        Args:
            query: Dictionary of query parameters
            
        Returns:
            Count of matching attacks
        """
        return len(self.query_attacks(query))
    
    def delete_attack(self, attack_id: int) -> bool:
        """
        Delete an attack by its ID.
        
        Args:
            attack_id: ID of the attack to delete
            
        Returns:
            True if attack was deleted, False otherwise
        """
        attack = self.get_attack_by_id(attack_id)
        if attack:
            self.attacks = [a for a in self.attacks if a.id != attack_id]
            
            # Update indices
            for key in self.attack_index:
                if key == 'type':
                    self.attack_index[key] = [(t, a) for t, a in self.attack_index[key] if a.id != attack_id]
                else:
                    self.attack_index[key] = [(k, a) for k, a in self.attack_index[key] if a.id != attack_id]
            
            return True
        return False
    
    def clear_all(self) -> None:
        """Clear all attacks in the repository."""
        self.attacks = []
        self.attack_index = defaultdict(list)
        self.next_id = 1 