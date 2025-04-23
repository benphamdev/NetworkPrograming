from smolagents import (
    CodeAgent,
    ToolCallingAgent,
    DuckDuckGoSearchTool,
    VisitWebpageTool,
    LiteLLMModel,
)
from phoenix.otel import register
from openinference.instrumentation.smolagents import SmolagentsInstrumentor

register()
SmolagentsInstrumentor().instrument()

from dotenv import load_dotenv
import os


load_dotenv()
apikey=os.getenv("DEEPSEEK_API_KEY") 
if not apikey:
    raise ValueError("Set DEEPSEEK_API_KEY in your .env file")

# model = HfApiModel(token=ACCESS_TOKEN, model_id="Qwen/Qwen2.5-Coder-32B-Instruct")

register()
SmolagentsInstrumentor().instrument()

model = LiteLLMModel(
    model_id="deepseek/deepseek-chat",
    api_key=apikey,
    messages=[
        {
            "role": "system",
            "content": "You are a helpful AI assistant capable of using tools to perform tasks. "
            "When given a query, analyze it and use available tools to gather information. "
            "Return JSON responses when possible.",
        }
    ],
    temperature=0.1,
    max_tokens=512,
    top_p=0.9,
    top_k=50,
    frequency_penalty=0.0,
    presence_penalty=0.0,
    stream=False,  # Disable streaming to avoid 'CustomStreamWrapper' issues
    n=1,
    logit_bias={},
    request_timeout=60,
)

search_agent = ToolCallingAgent(
    tools=[DuckDuckGoSearchTool(), VisitWebpageTool()],
    model=model,
    name="search_agent",
    description="This is an agent that can do web search.",
)

manager_agent = CodeAgent(
    tools=[],
    model=model,
    managed_agents=[search_agent],
)

manager_agent.run(
    "If the US keeps its 2024 growth rate, how many years will it take for the GDP to double?"
)


