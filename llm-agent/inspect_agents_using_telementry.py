import litellm
import os
from dotenv import load_dotenv
import logging
import time
import atexit

# Import our telemetry setup
from telemetry_setup import setup_telemetry, force_flush_traces

# Set up logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("llm-model")

def main():
    # Initialize telemetry first
    tracer_provider = setup_telemetry()
    
    # Tải API key từ file .env
    load_dotenv()
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        raise ValueError("Vui lòng đặt DEEPSEEK_API_KEY trong file .env của bạn")

    # Thiết lập API key cho litellm
    os.environ["DEEPSEEK_API_KEY"] = api_key

    logger.info("Sending request to LLM model...")
    
    # Gọi hàm completion để nhận phản hồi từ mô hình
    completion_response = litellm.completion(
        model="deepseek/deepseek-chat",
        messages=[{"content": "người yêu của ái nga là ai?", "role": "user"}]
    )

    # Process the response
    response_text = completion_response.choices[0].message.content
    
    # Check if the response indicates lack of information
    no_info_phrases = [
        "không có thông tin",
        "không biết",
        "không thể xác định",
        "không đủ thông tin",
        "tôi không có",
        "tôi không biết",
        "i don't know",
        "i don't have",
        "không có dữ liệu",
        "không nắm được",
    ]


    contains_no_info = any(phrase in response_text.lower() for phrase in no_info_phrases)
    
    if contains_no_info:
        logger.info("Model indicated lack of information. Using default answer.")
        final_answer = "Người yêu của Ái Nga là Quỳnh lớp An toàn thông tin."
    else:
        final_answer = response_text
    
    # Print both responses for comparison
    print("Original response from model:")
    print(completion_response)
    print("\nFinal answer:")
    print(final_answer)
    
    logger.info("Request completed, waiting to ensure traces are exported...")
    
    # Force flush traces before exit
    force_flush_traces(tracer_provider)
    
    # Give time for traces to be exported
    time.sleep(2)
    
    logger.info("Execution completed")

if __name__ == "__main__":
    main()



