"""
ResponseExtractor - Helper class for extracting structured information from AI responses.
"""
from typing import List, Optional
import re

class ResponseExtractor:
    """Helper class to extract structured information from AI text responses."""
    
    def extract_attack_detection(self, response: str) -> bool:
        """
        Extract attack detection from text response.
        
        Args:
            response: Raw text response from AI.
            
        Returns:
            Boolean indicating whether an attack was detected.
        """
        response_lower = response.lower()
        
        # Look for positive indicators
        positive_indicators = [
            "attack detected", "attack is detected", "attack is occurring",
            "attack is likely", "attack is happening", "attack in progress",
            "malicious activity", "suspicious activity"
        ]
        
        # Look for negative indicators
        negative_indicators = [
            "no attack detected", "not an attack", "normal traffic",
            "benign traffic", "legitimate traffic", "false positive"
        ]
        
        # Check for positive indicators first
        for indicator in positive_indicators:
            if indicator in response_lower:
                return True
        
        # Then check for negative indicators
        for indicator in negative_indicators:
            if indicator in response_lower:
                return False
        
        # Default to False if uncertain
        return False
    
    def extract_attack_type(self, response: str) -> Optional[str]:
        """
        Extract attack type from text response.
        
        Args:
            response: Raw text response from AI.
            
        Returns:
            Standardized attack type string or None if not detected.
        """
        response_lower = response.lower()
        
        # Common attack types to look for
        attack_types = {
            "syn flood": "SYN_FLOOD",
            "arp spoof": "ARP_SPOOFING",
            "icmp flood": "ICMP_FLOOD",
            "port scan": "PORT_SCAN",
            "tcp hijack": "TCP_HIJACKING",
            "rst attack": "RST_ATTACK",
            "denial of service": "DOS",
            "ddos": "DDOS"
        }
        
        for key, value in attack_types.items():
            if key in response_lower:
                return value
        
        return None
    
    def extract_confidence(self, response: str) -> float:
        """
        Extract confidence score from text response.
        
        Args:
            response: Raw text response from AI.
            
        Returns:
            Confidence score between 0.0 and 1.0.
        """
        # Look for confidence score patterns
        confidence_patterns = [
            r'confidence[:\s]+(\d+\.?\d*)',
            r'confidence[:\s]+(\d+)%',
            r'confidence[:\s]+(high|medium|low)',
            r'confidence[:\s]+(high|medium|low)',
            r'confidence score[:\s]+(\d+\.?\d*)'
        ]
        
        for pattern in confidence_patterns:
            matches = re.search(pattern, response.lower())
            if matches:
                value = matches.group(1)
                if value.replace('.', '', 1).isdigit():
                    # Numeric confidence
                    confidence = float(value)
                    if confidence > 1 and confidence <= 100:  # Percentage
                        return confidence / 100
                    return min(1.0, max(0.0, confidence))  # Ensure 0-1 range
                else:
                    # Text-based confidence
                    if value == 'high':
                        return 0.9
                    elif value == 'medium':
                        return 0.6
                    elif value == 'low':
                        return 0.3
        
        # Default confidence
        return 0.5
    
    def extract_recommendations(self, response: str) -> List[str]:
        """
        Extract recommendations from text response.
        
        Args:
            response: Raw text response from AI.
            
        Returns:
            List of recommendation strings.
        """
        recommendations = []
        lines = response.split('\n')
        
        # Keywords that often indicate recommendations
        recommendation_indicators = [
            "recommend", "suggestion", "advice", "should", "could", "mitigate",
            "prevent", "block", "filter", "implement", "enable", "configure",
            "set up", "install"
        ]
        
        in_recommendation_section = False
        
        for line in lines:
            line = line.strip()
            
            # Check if we're in a recommendation section
            if "recommend" in line.lower() or "mitigat" in line.lower() or "action" in line.lower():
                in_recommendation_section = True
                if ":" in line:
                    recommendations.append(line.split(":", 1)[1].strip())
                continue
            
            # If we're in a recommendation section or the line has recommendation indicators
            if in_recommendation_section or any(indicator in line.lower() for indicator in recommendation_indicators):
                # Check if this is a bullet point or numbered item
                if line.startswith("-") or line.startswith("*") or re.match(r"^\d+\.", line):
                    recommendations.append(line.strip("- *").strip())
        
        return recommendations 