from dotenv import load_dotenv
from langchain_litellm import ChatLiteLLM
from langchain.agents import initialize_agent, AgentType
from langchain.tools import tool
import os
from rich import print
import pandas as pd
import matplotlib.pyplot as plt

load_dotenv()

api_key = os.environ["DEEPSEEK_API_KEY"]
api_key = os.getenv("OPENAI_API_KEY")

llm = ChatLiteLLM(
    model="deepseek/deepseek-chat",
    # model = "openai/gpt-4o-mini",
    api_key=api_key,
    api_base="https://api.deepseek.com/v1",
    temperature=0,
)

@tool
def dummy_network_tool(query: str) -> str:
    """A dummy network tool """
    return f"I received: {query}"

# Initialize the agent with handle_parsing_errors=True
agent = initialize_agent(
    tools=[dummy_network_tool],
    llm=llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
    verbose=True,
    handle_parsing_errors=True
)

# Run the agent with a sample query
query = """Plot chart to display network packet travel time from this computer to google.com, amazon.com 
            and facebook.com. Send at least 10 packets for each target. 
            Do NOT plot using average travel time, DO NOT use bar chart."""
response = agent.invoke(query)
print(response)

if __name__ == "__main__":
    # Create sample network data
    import numpy as np
    
    # Generate sample data
    n_samples = 100
    data = {
        'timestamp': pd.date_range(start='2024-01-01', periods=n_samples, freq='S'),
        'latency_ms': np.random.normal(100, 20, n_samples),
        'packet_size': np.random.randint(64, 1500, n_samples),
        'target': np.random.choice(['google.com', 'amazon.com', 'facebook.com'], n_samples)
    }
    
    df = pd.DataFrame(data)
    
    # Save sample data
    df.to_csv("network_data.csv", index=False)
    
    # Analysis
    print("=== Network Data Analysis ===")
    print(df.describe())
    
    # Plot latency distribution
    plt.figure(figsize=(10, 6))
    df.boxplot(column='latency_ms', by='target')
    plt.title("Latency Distribution by Target")
    plt.ylabel("Latency (ms)")
    plt.xticks(rotation=45)
    plt.savefig("latency_distribution.png")
    
    # Plot latency over time
    plt.figure(figsize=(12, 6))
    for target in df['target'].unique():
        target_data = df[df['target'] == target]
        plt.plot(target_data['timestamp'], target_data['latency_ms'], 
                label=target, marker='o', linestyle='-', alpha=0.6)
    
    plt.title("Network Latency Over Time")
    plt.xlabel("Timestamp")
    plt.ylabel("Latency (ms)")
    plt.legend()
    plt.grid(True)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("latency_time_series.png")
    
    plt.show()