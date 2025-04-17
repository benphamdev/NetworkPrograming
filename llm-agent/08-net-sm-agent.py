import os
import json
from dotenv import load_dotenv
from smolagents import CodeAgent, Tool, LiteLLMModel
from ai_providers.factory import AIProviderFactory

load_dotenv()
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
if not DEEPSEEK_API_KEY:
    raise ValueError("Set DEEPSEEK_API_KEY in your .env file")

# 1) Instantiate the DeepSeek LLM
llm_model = LiteLLMModel(
    model_id="deepseek/deepseek-chat",
    api_key=DEEPSEEK_API_KEY,
    messages=[
        {
            "role": "system",
            "content": (
                "You are a network security analyst assistant. "
                "Use the network_security tool when you need detailed analysis."
            )
        }
    ]
)

# 2) Define the network‐analysis tool wrapper
def network_analysis_tool(query: str) -> str:
    provider = AIProviderFactory.get_default_provider()
    result = provider.generate_structured_analysis(
        data={"query": query},
        analysis_type="security",
        instructions="Return JSON with sections: findings, risks, recommendations"
    )
    return json.dumps(result, indent=2)

tools = [
    Tool(
        name="network_security",
        description="Analyze network/security questions and return a JSON report",
        func=network_analysis_tool
    )
]

# 3) Create and run the CodeAgent
agent = CodeAgent(
    tools=tools,
    model=llm_model,
    verbosity_level=2
)

def main():
    question = """
    Our office subnet 10.0.1.0/24 is facing intermittent port scans.
    Use the network_security tool to list findings, risks, and recommendations.
    """
    response = agent.run(question)
    print(response)

if __name__ == "__main__":
    main()