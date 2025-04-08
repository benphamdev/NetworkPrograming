import os

import openai
import pandas as pd
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure OpenAI API
openai.api_key = os.getenv('OPEN_AI_API_KEY')


class NetworkAIAnalyzer:
    """
    A class that uses OpenAI's API to analyze network security events
    and provide insights.
    """

    def __init__(self, model="gpt-3.5-turbo"):
        """
        Initialize the NetworkAIAnalyzer with the specified OpenAI model.
        
        Args:
            model (str): The OpenAI model to use. Default is "gpt-3.5-turbo".
        """
        self.model = model
        print(f"NetworkAIAnalyzer initialized with model: {model}")

    def analyze_logs(self, logs_df, sample_size=10):
        """
        Analyze network logs using OpenAI API and provide insights.
        
        Args:
            logs_df (pd.DataFrame): DataFrame containing network logs
            sample_size (int): Number of log entries to sample for analysis
            
        Returns:
            dict: Analysis results from OpenAI
        """
        # Sample logs for analysis (to keep API usage reasonable)
        if len(logs_df) > sample_size:
            logs_sample = logs_df.sample(sample_size)
        else:
            logs_sample = logs_df

        # Format logs for analysis
        logs_str = logs_sample.to_string()

        # Prepare the prompt for OpenAI
        prompt = f"""
        Analyze these network security logs and provide insights:
        1. Identify potential security threats or anomalies
        2. Suggest possible causes for the failure events
        3. Recommend actions to mitigate identified issues
        
        Network logs:
        {logs_str}
        
        Provide a detailed analysis in a structured format.
        """

        # Call OpenAI API
        try:
            response = openai.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a network security expert analyzing security logs."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.2  # Lower temperature for more focused response
            )

            # Extract and return analysis
            analysis = response.choices[0].message.content
            return {
                "status": "success",
                "analysis": analysis,
                "sample_size": len(logs_sample)
            }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }

    def explain_failure_reason(self, failure_reason):
        """
        Provide a detailed explanation of a specific failure reason.
        
        Args:
            failure_reason (str): The failure reason to explain
            
        Returns:
            dict: Explanation from OpenAI
        """
        prompt = f"""
        Explain this network security failure reason in detail:
        "{failure_reason}"
        
        Include:
        1. What caused this error?
        2. Is this a potential security concern? If so, why?
        3. How to fix or prevent this issue?
        """

        try:
            response = openai.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a network security expert explaining technical errors."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=500,
                temperature=0.3
            )

            explanation = response.choices[0].message.content
            return {
                "status": "success",
                "explanation": explanation
            }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }

    def identify_attack_patterns(self, logs_df):
        """
        Identify potential attack patterns in the logs.
        
        Args:
            logs_df (pd.DataFrame): DataFrame containing network logs
            
        Returns:
            dict: Attack pattern analysis from OpenAI
        """
        # Prepare summary statistics
        source_ips = logs_df['id.orig_h'].value_counts().head(10).to_dict()
        dest_ips = logs_df['id.resp_h'].value_counts().head(10).to_dict()
        dest_ports = logs_df['id.resp_p'].value_counts().head(10).to_dict()

        # Format data for OpenAI
        data_summary = f"""
        Top source IPs: {source_ips}
        Top destination IPs: {dest_ips}
        Top destination ports: {dest_ports}
        Total events: {len(logs_df)}
        Unique source IPs: {logs_df['id.orig_h'].nunique()}
        Unique destination IPs: {logs_df['id.resp_h'].nunique()}
        """

        prompt = f"""
        Based on this network traffic summary, identify potential attack patterns, suspicious activities, 
        or security concerns:
        
        {data_summary}
        
        Provide:
        1. Identified attack patterns or suspicious activities
        2. Threat assessment (severity and confidence)
        3. Recommendations for security team
        """

        try:
            response = openai.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system",
                     "content": "You are a cybersecurity threat analyst identifying attack patterns."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=800,
                temperature=0.2
            )

            analysis = response.choices[0].message.content
            return {
                "status": "success",
                "attack_analysis": analysis
            }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }


# Usage example
if __name__ == "__main__":
    # Create analyzer instance
    analyzer = NetworkAIAnalyzer()

    # Test with sample data (load your CSV file)
    try:
        logs_df = pd.read_csv("../C-Network-Programming/Chap06/analyzer.csv")
        print(f"Loaded log file with {len(logs_df)} entries.")

        # Analyze logs
        analysis_result = analyzer.analyze_logs(logs_df, sample_size=10)
        if analysis_result['status'] == 'success':
            print("\n=== AI ANALYSIS ===")
            print(analysis_result['analysis'])
        else:
            print(f"Error: {analysis_result['error']}")

        # Explain a specific failure reason
        if not logs_df.empty:
            sample_failure = logs_df['failure_reason'].iloc[0]
            explanation = analyzer.explain_failure_reason(sample_failure)
            if explanation['status'] == 'success':
                print("\n=== FAILURE EXPLANATION ===")
                print(explanation['explanation'])

        # Identify attack patterns
        pattern_analysis = analyzer.identify_attack_patterns(logs_df)
        if pattern_analysis['status'] == 'success':
            print("\n=== ATTACK PATTERN ANALYSIS ===")
            print(pattern_analysis['attack_analysis'])

    except Exception as e:
        print(f"Error loading or processing log file: {e}")
