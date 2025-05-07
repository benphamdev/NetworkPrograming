import logging
import datetime
from functools import wraps

# Configure the base logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f"app_{datetime.datetime.now().strftime('%Y%m%d')}.log")
    ]
)

def get_logger(name):
    """Get a logger instance for the specified module name."""
    return logging.getLogger(name)

def log_function_call(func):
    """Decorator to log function calls with arguments and return values."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        func_name = func.__qualname__
        
        # Format the args and kwargs for logging, excluding large objects
        args_str = ', '.join([str(arg) if len(str(arg)) < 100 else f"{type(arg).__name__}(size={len(str(arg))})" for arg in args])
        kwargs_str = ', '.join([f"{k}={v}" if len(str(v)) < 100 else f"{k}={type(v).__name__}(size={len(str(v))})" for k, v in kwargs.items()])
        
        logger.info(f"Calling {func_name}({args_str}{', ' if args_str and kwargs_str else ''}{kwargs_str})")
        
        try:
            result = func(*args, **kwargs)
            
            # Log the result, but avoid logging large objects in detail
            result_str = str(result) if result is None or len(str(result)) < 100 else f"{type(result).__name__}(size={len(str(result))})"
            logger.info(f"{func_name} returned: {result_str}")
            
            return result
        except Exception as e:
            logger.error(f"{func_name} raised an exception: {type(e).__name__}: {str(e)}")
            raise
            
    return wrapper