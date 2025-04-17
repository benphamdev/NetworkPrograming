from smolagents import (
    CodeAgent,
    ToolCallingAgent,
    DuckDuckGoSearchTool,
    VisitWebpageTool,
    HfApiModel,
)

from dotenv import load_dotenv
import os
from rich import print

load_dotenv()
ACCESS_TOKEN = os.getenv("HUGGINGFACEHUB_API_TOKEN")
if not ACCESS_TOKEN:
    raise ValueError("Set HUGGINGFACEHUB_API_TOKEN in your .env file")


model = HfApiModel(token=ACCESS_TOKEN, model_id="Qwen/Qwen2.5-Coder-32B-Instruct")


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