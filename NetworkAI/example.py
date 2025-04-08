"""
Example usage of NetworkAIAnalyzer with Groq API.
"""
import pandas as pd
import json
from dotenv import load_dotenv
from network_ai_analyzer import NetworkAIAnalyzer
from ai_providers import AIProviderFactory

# Load environment variables from .env file
load_dotenv()

def main():
    """Run example analysis using Groq."""
    print("Network Security Analysis with Groq AI")
    print("=====================================")
    
    # Show available providers
    print("Checking available AI providers...")
    try:
        # Try to create a Groq provider
        groq_provider = AIProviderFactory.create_provider("groq")
        print("✓ Groq provider is available")
        print(f"  Model: {groq_provider.get_model_info()['model']}")
    except Exception as e:
        print(f"✗ Groq provider is not available: {e}")
    
    try:
        # Try to create an OpenAI provider
        openai_provider = AIProviderFactory.create_provider("openai")
        print("✓ OpenAI provider is available")
        print(f"  Model: {openai_provider.get_model_info()['model']}")
    except Exception as e:
        print(f"✗ OpenAI provider is not available: {e}")
    
    # Create the analyzer with Groq
    print("\nInitializing NetworkAIAnalyzer with Groq...")
    analyzer = NetworkAIAnalyzer(provider_type="groq")
    
    # Load sample data
    print("\nLoading network log data...")
    try:
        logs_df = pd.read_csv("../C-Network-Programming/Chap06/analyzer.csv")
        print(f"Loaded {len(logs_df)} log entries")
        
        # Sample the first few rows
        print("\nSample data:")
        print(logs_df.head(3))
        
        # Analyze the logs
        print("\nAnalyzing logs with Groq AI (sample size: 5)...")
        analysis = analyzer.analyze_logs(logs_df, sample_size=5)
        print("\n=== ANALYSIS RESULTS ===")
        print(json.dumps(analysis, indent=2))
        
        # Analyze a specific failure reason
        print("\nAnalyzing a specific failure reason...")
        sample_failure = logs_df['failure_reason'].iloc[0]
        print(f"Failure reason: {sample_failure[:100]}...")
        
        explanation = analyzer.explain_failure_reason(sample_failure)
        print("\n=== FAILURE EXPLANATION ===")
        print(json.dumps(explanation, indent=2))
        
        # Identify attack patterns
        print("\nIdentifying attack patterns...")
        patterns = analyzer.identify_attack_patterns(logs_df)
        print("\n=== ATTACK PATTERN ANALYSIS ===")
        print(json.dumps(patterns, indent=2))
        
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
