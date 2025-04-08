"""
Network AI Analyzer that uses AI providers to analyze network data.
"""
import os
import json
import pandas as pd
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

from ai_providers import AIProviderFactory, AIProvider

# Load environment variables from .env file
load_dotenv()


class NetworkAIAnalyzer:
    """
    Analyzer class that uses AI to analyze network security data.
    """
    
    def __init__(self, provider_type: str = None, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the NetworkAIAnalyzer.
        
        Args:
            provider_type: Type of AI provider to use ("groq", "openai")
                          If None, uses the first provider with a valid API key
            config: Additional configuration for the AI provider
        """
        if provider_type:
            self.ai_provider = AIProviderFactory.create_provider(provider_type, config)
        else:
            self.ai_provider = AIProviderFactory.get_default_provider()
        
        print(f"Initialized NetworkAIAnalyzer with {self.ai_provider.get_model_info()['provider']} provider")
    
    def analyze_logs(self, logs_df: pd.DataFrame, sample_size: int = 10) -> Dict[str, Any]:
        """
        Analyze network logs using AI and provide insights.
        
        Args:
            logs_df: DataFrame containing network logs
            sample_size: Number of log entries to sample for analysis
            
        Returns:
            Dictionary with analysis results
        """
        # Sample logs for analysis (to keep API usage reasonable)
        if len(logs_df) > sample_size:
            logs_sample = logs_df.sample(sample_size)
        else:
            logs_sample = logs_df
        
        # Convert sample to dict for the AI provider
        logs_dict = {
            "log_entries": logs_sample.to_dict(orient="records"),
            "total_entries": len(logs_df),
            "sampled_entries": len(logs_sample),
            "columns": list(logs_df.columns)
        }
        
        # Additional aggregated data to help with analysis
        if 'id.orig_h' in logs_df.columns:
            logs_dict["top_source_ips"] = logs_df['id.orig_h'].value_counts().head(5).to_dict()
            
        if 'id.resp_h' in logs_df.columns:
            logs_dict["top_dest_ips"] = logs_df['id.resp_h'].value_counts().head(5).to_dict()
            
        if 'id.resp_p' in logs_df.columns:
            logs_dict["top_dest_ports"] = logs_df['id.resp_p'].value_counts().head(5).to_dict()
        
        instructions = """
        Analyze these network security logs and provide:
        1. A summary of key patterns and potential security issues
        2. List of suspicious activities or anomalies
        3. Recommendations for further investigation
        4. Overall security risk assessment (Low, Medium, High)
        
        Focus on common attack patterns like port scanning, brute force attempts, and unusual connection patterns.
        """
        
        result = self.ai_provider.generate_structured_analysis(
            data=logs_dict,
            analysis_type="network_security",
            instructions=instructions
        )
        
        return result
    
    def explain_failure_reason(self, failure_reason: str) -> Dict[str, str]:
        """
        Provide a detailed explanation of a specific failure reason.
        
        Args:
            failure_reason: The failure reason to explain
            
        Returns:
            Dictionary with detailed explanation
        """
        prompt = f"""
        Explain this network security failure reason in detail:
        "{failure_reason}"
        
        Include:
        1. What caused this error?
        2. Is this a potential security concern? If so, why?
        3. How to fix or prevent this issue?
        """
        
        explanation = self.ai_provider.analyze_text(prompt, max_tokens=500, temperature=0.3)
        
        return {
            "failure_reason": failure_reason,
            "explanation": explanation
        }
    
    def identify_attack_patterns(self, logs_df: pd.DataFrame) -> Dict[str, Any]:
        """
        Identify potential attack patterns in network logs.
        
        Args:
            logs_df: DataFrame containing network logs
            
        Returns:
            Dictionary with attack pattern analysis
        """
        # Prepare summary statistics for analysis
        summary = {
            "total_events": len(logs_df),
            "time_range": {
                "start": logs_df['ts'].min() if 'ts' in logs_df.columns else None,
                "end": logs_df['ts'].max() if 'ts' in logs_df.columns else None
            }
        }
        
        if 'id.orig_h' in logs_df.columns:
            summary["unique_source_ips"] = logs_df['id.orig_h'].nunique()
            summary["top_source_ips"] = logs_df['id.orig_h'].value_counts().head(10).to_dict()
            
        if 'id.resp_h' in logs_df.columns:
            summary["unique_dest_ips"] = logs_df['id.resp_h'].nunique()
            summary["top_dest_ips"] = logs_df['id.resp_h'].value_counts().head(10).to_dict()
            
        if 'id.resp_p' in logs_df.columns:
            summary["unique_dest_ports"] = logs_df['id.resp_p'].nunique()
            summary["top_dest_ports"] = logs_df['id.resp_p'].value_counts().head(10).to_dict()
            
        if 'analyzer_name' in logs_df.columns:
            summary["protocol_breakdown"] = logs_df['analyzer_name'].value_counts().to_dict()
        
        instructions = """
        Based on the provided network traffic summary, identify potential attack patterns, suspicious activities, 
        and security concerns. Focus on:
        
        1. Signs of port scanning or reconnaissance
        2. Brute force attack attempts
        3. Unusual connection patterns
        4. Potentially malicious IP addresses
        5. Compromised systems or data exfiltration attempts
        
        Provide a threat assessment with severity ratings and confidence levels.
        """
        
        result = self.ai_provider.generate_structured_analysis(
            data=summary,
            analysis_type="attack_pattern_detection",
            instructions=instructions
        )
        
        return result
        

# Example usage
if __name__ == "__main__":
    # Create an analyzer that uses Groq by default
    analyzer = NetworkAIAnalyzer(provider_type="groq")
    
    # Test with sample data
    try:
        logs_df = pd.read_csv("../C-Network-Programming/Chap06/analyzer.csv")
        print(f"Loaded log file with {len(logs_df)} entries.")
        
        # Example 1: Analyze a sample of logs
        analysis = analyzer.analyze_logs(logs_df, sample_size=5)
        print("\n=== AI ANALYSIS ===")
        print(json.dumps(analysis, indent=2))
        
        # Example 2: Explain a failure reason
        if not logs_df.empty:
            sample_failure = logs_df['failure_reason'].iloc[0]
            explanation = analyzer.explain_failure_reason(sample_failure)
            print("\n=== FAILURE EXPLANATION ===")
            print(json.dumps(explanation, indent=2))
        
        # Example 3: Identify attack patterns
        patterns = analyzer.identify_attack_patterns(logs_df)
        print("\n=== ATTACK PATTERN ANALYSIS ===")
        print(json.dumps(patterns, indent=2))
        
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
