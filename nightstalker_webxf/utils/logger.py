#!/usr/bin/env python3
"""
NightStalker Logger Module
Provides logging functionality for the NightStalker framework
"""

import logging
import os
import sys
from datetime import datetime
from pathlib import Path

class Logger:
    """Simple logger class for NightStalker framework"""
    
    def __init__(self, name="nightstalker", level=logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        # Prevent duplicate handlers
        if not self.logger.handlers:
            self._setup_handlers()
    
    def _setup_handlers(self):
        """Setup console and file handlers"""
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler (optional)
        log_dir = Path("data/logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = log_dir / f"nightstalker_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
    
    def info(self, message):
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message):
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message):
        """Log error message"""
        self.logger.error(message)
    
    def debug(self, message):
        """Log debug message"""
        self.logger.debug(message)
    
    def critical(self, message):
        """Log critical message"""
        self.logger.critical(message)

# Global logger instance
logger = Logger()

def get_logger(name=None):
    """Get a logger instance"""
    if name:
        return Logger(name)
    return logger 