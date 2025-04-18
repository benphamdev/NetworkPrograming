from phoenix.otel import register
import os
from dotenv import load_dotenv
from openinference.instrumentation.litellm import LiteLLMInstrumentor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace.export import BatchSpanProcessor
import atexit
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("phoenix-telemetry")

def setup_telemetry():
    os.environ["PHOENIX_COLLECTOR_ENDPOINT"] = "http://localhost:6006"
    load_dotenv()
    DEEPSEEK_API_KEY= os.getenv("DEEPSEEK_API_KEY")
    if DEEPSEEK_API_KEY:
        os.environ["OPENAI_API_KEY"] = DEEPSEEK_API_KEY
    else:
        logger.warning("DEEPSEEK_API_KEY not found in .env file.")

    # configure the Phoenix tracer
    logger.info(f"Registering Phoenix tracer with endpoint: {os.environ.get('PHOENIX_COLLECTOR_ENDPOINT')}")
    tracer_provider = register(
        auto_instrument=True,
        endpoint="http://localhost:6006/v1/traces"
    )

    # Use BatchSpanProcessor for more efficient exporting
    exporter = OTLPSpanExporter(endpoint="http://localhost:6006/v1/traces")
    span_processor = BatchSpanProcessor(exporter)
    tracer_provider.add_span_processor(span_processor)
    
    # Instantiate the instrumentor first, then call instrument
    LiteLLMInstrumentor().instrument(
        tracer_provider=tracer_provider,
    )
    
    logger.info("✅ Telemetry initialized successfully")
    return tracer_provider # Return the provider

def force_flush_traces(tracer_provider):
    """Force flush any pending traces"""
    if tracer_provider:
        logger.info("Forcing trace flush...")
        tracer_provider.force_flush()
        logger.info("Trace flush complete")

def main():
    tracer_provider = setup_telemetry()

    # Register the shutdown function to be called on exit
    if tracer_provider:
        atexit.register(lambda: force_flush_traces(tracer_provider))
        atexit.register(tracer_provider.shutdown)
        logger.info("Registered tracer_provider.shutdown() for atexit.")

    # Give exporters a bit more time
    import time
    time.sleep(1)

    logger.info("Telemetry setup script finished. Shutdown will occur on exit.")

if __name__ == "__main__":
    main()


