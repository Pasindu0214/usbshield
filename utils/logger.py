# utils/logger.py
import os
import logging
from logging.handlers import RotatingFileHandler

def setup_logger():
    """Set up and configure the logger"""
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Create logger
    logger = logging.getLogger('usbshield')
    logger.setLevel(logging.INFO)
    
    # Clear existing handlers if any
    if logger.handlers:
        logger.handlers.clear()
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Create file handler for rotating logs
    file_handler = RotatingFileHandler(
        os.path.join('logs', 'usbshield.log'),
        maxBytes=5*1024*1024,  # 5 MB
        backupCount=5
    )
    file_handler.setLevel(logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Add formatter to handlers
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger