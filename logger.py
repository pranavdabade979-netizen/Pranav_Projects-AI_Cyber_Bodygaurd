"""
Logging module for AI Cyber Bodyguard
Provides centralized logging for all components
"""
import logging
import os
from config import LOG_LEVEL, LOG_FILE

# Create logs directory if it doesn't exist
os.makedirs(os.path.dirname(LOG_FILE) or ".", exist_ok=True)

# Configure logging
logger = logging.getLogger("cyberbodyguard")
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

# File handler
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Formatter
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add handlers to logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

def get_logger(name):
    """Get a logger instance for the given name"""
    return logging.getLogger(f"cyberbodyguard.{name}")
