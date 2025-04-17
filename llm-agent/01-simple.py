from dotenv import load_dotenv
from litellm import completion
import os
from rich import print

load_dotenv()

api_key = os.environ["DEEPSEEK_API_KEY"]

def get_llm_response(message):
    response = completion(
        model="deepseek/deepseek-chat",
        api_key = api_key,
        messages=message,
        stream=False
    )
    return response

messages = [
    {
        "role":"system",
        "content":"You are a helpful AI assistance"
    },
    {
        "role":"user",
        "content":"When is my next meeting?"
    }
]

print(get_llm_response(messages))