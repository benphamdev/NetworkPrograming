import os
import time
from dotenv import load_dotenv

# Telemetry setup
from telemetry_setup import setup_telemetry, force_flush_traces

# Agent imports
from smolagents import (
    CodeAgent,
    ToolCallingAgent,
    DuckDuckGoSearchTool,
    VisitWebpageTool
)

from smolagents.models import LiteLLMModel
import logging

# Set up logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("llm-model")

# Telemetry-instrumented entrypoint
def main():
    # Initialize telemetry
    tracer_provider = setup_telemetry()

    # Load environment variables
    load_dotenv()

    # Get API key
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        raise ValueError("DEEPSEEK_API_KEY environment variable not set")

    # Set API key for litellm
    os.environ["DEEPSEEK_API_KEY"] = api_key
    
    # Reset any model configuration to ensure we're using Deepseek
    if "LITELLM_MODEL" in os.environ:
        logger.warning(f"Removing existing LITELLM_MODEL: {os.environ['LITELLM_MODEL']}")
        del os.environ["LITELLM_MODEL"]

    logger.info("Setting up LLM model with Deepseek...")

    # Configure litellm to use our model explicitly
    model_name = "deepseek/deepseek-chat"
    
    # Create a proper model instance for smolagents
    model = LiteLLMModel(
        model=model_name,
        model_kwargs={
            "api_key": api_key  # Pass API key directly
        }
    )

    logger.info(f"Using model: {model_name}")

    # Set up a web-searching agent
    search_agent = ToolCallingAgent(
        tools=[DuckDuckGoSearchTool(), VisitWebpageTool()],
        model=model,
        name="search_agent",
        description="This is an agent that can do web search.",
    )

    # Manager agent orchestrates the search agent
    manager_agent = CodeAgent(
        tools=[],
        model=model,
        managed_agents=[search_agent],
    )

    # Run the agent task
    manager_agent.run(
        "If the US keeps its 2024 growth rate, how many years will it take for the GDP to double?"
    )

    # Flush telemetry before exit
    force_flush_traces(tracer_provider)
    time.sleep(2)


if __name__ == "__main__":
    main()
