from smolagents import CodeAgent, HfApiModel
from dotenv import load_dotenv
import os

load_dotenv()

ACCESS_TOKEN = os.getenv("HUGGINGFACEHUB_API_TOKEN")

if not ACCESS_TOKEN:
    raise ValueError("Set HUGGINGFACEHUB_API_TOKEN in your .env file")

# First example: Calculating Fibonacci sequence
model_id = "Qwen/Qwen2.5-Coder-32B-Instruct"

# Create a model instance using Hugging Face API
model = HfApiModel(model_id=model_id, token=ACCESS_TOKEN) # You can choose to not pass any model_id to HfApiModel to use a default free model
# The model_id is the name of the model on Hugging Face Hub 
# You can optionally specify a provider like "together" or "sambanova"

# Create an agent with this model
agent = CodeAgent(tools=[], model=model, add_base_tools=True)

# Ask the agent to calculate the 118th Fibonacci number
agent.run(
    "Could you give me the 118th number in the Fibonacci sequence?",
)

# # Second example: Web scraping
# model = HfApiModel()  # Creates a default model
# # Create another agent that's allowed to use requests and BeautifulSoup
# agent = CodeAgent(tools=[], model=model, additional_authorized_imports=['requests', 'bs4'])
# # Ask the agent to scrape a webpage title
# agent.run("Could you get me the title of the page at url 'https://huggingface.co/blog'?")

