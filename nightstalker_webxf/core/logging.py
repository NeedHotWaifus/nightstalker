#!/usr/bin/env python3
"""
Logging System for NightStalker WebXF
Unified logging with rotation, colored output, and structured logging
"""

import os
import sys
import logging
import logging.handlers
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
import json
import traceback

# ANSI color codes for colored output
class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colored output"""
    
    COLORS = {
        'DEBUG': Colors.CYAN,
        'INFO': Colors.GREEN,
        'WARNING': Colors.YELLOW,
        'ERROR': Colors.RED,
        'CRITICAL': Colors.PURPLE + Colors.BOLD
    }
    
    def format(self, record):
        # Add color to level name
        if hasattr(record, 'levelname'):
            color = self.COLORS.get(record.levelname, Colors.WHITE)
            record.levelname = f"{color}{record.levelname}{Colors.END}"
        
        # Add color to module name
        if hasattr(record, 'module'):
            record.module = f"{Colors.BLUE}{record.module}{Colors.END}"
        
        return super().format(record)

class StructuredFormatter(logging.Formatter):
    """Structured JSON formatter for machine-readable logs"""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'message': record.getMessage()
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                          'filename', 'module', 'lineno', 'funcName', 'created', 
                          'msecs', 'relativeCreated', 'thread', 'threadName', 
                          'processName', 'process', 'getMessage', 'exc_info', 
                          'exc_text', 'stack_info']:
                log_entry[key] = value
        
        return json.dumps(log_entry)

class LogManager:
    """Log manager for NightStalker WebXF"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize log manager"""
        self.config_path = config_path
        self.loggers: Dict[str, logging.Logger] = {}
        self._setup_root_logger()
    
    def _setup_root_logger(self) -> None:
        """Setup root logger configuration"""
        # Get configuration
        try:
            from .config import get_config
            config = get_config()
            log_config = config.get("logging", {})
        except ImportError:
            # Fallback configuration
            log_config = {
                "level": "INFO",
                "file": "logs/framework.log",
                "max_size": "10MB",
                "backup_count": 5,
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "console_output": True,
                "colored_output": True
            }
        
        # Create logs directory
        log_file = log_config.get("file", "logs/framework.log")
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, log_config.get("level", "INFO").upper()))
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=self._parse_size(log_config.get("max_size", "10MB")),
            backupCount=log_config.get("backup_count", 5)
        )
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler
        if log_config.get("console_output", True):
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            
            # Use colored formatter if enabled
            if log_config.get("colored_output", True) and sys.stdout.isatty():
                console_formatter = ColoredFormatter(log_config.get("format"))
            else:
                console_formatter = logging.Formatter(log_config.get("format"))
            
            console_handler.setFormatter(console_formatter)
            root_logger.addHandler(console_handler)
        
        # File formatter (always structured for better parsing)
        file_formatter = StructuredFormatter()
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string to bytes"""
        size_str = size_str.upper()
        if size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get or create a logger with the specified name"""
        if name not in self.loggers:
            self.loggers[name] = logging.getLogger(name)
        return self.loggers[name]
    
    def set_level(self, name: str, level: str) -> None:
        """Set log level for a specific logger"""
        logger = self.get_logger(name)
        logger.setLevel(getattr(logging, level.upper()))
    
    def add_file_handler(self, name: str, file_path: str, level: str = "DEBUG") -> None:
        """Add file handler to a specific logger"""
        logger = self.get_logger(name)
        
        # Create directory if it doesn't exist
        log_dir = os.path.dirname(file_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        file_handler = logging.FileHandler(file_path)
        file_handler.setLevel(getattr(logging, level.upper()))
        file_handler.setFormatter(StructuredFormatter())
        logger.addHandler(file_handler)
    
    def log_scan_start(self, scan_type: str, args: Any) -> None:
        """Log scan start event"""
        logger = self.get_logger("scanner")
        logger.info(f"Scan started", extra={
            'scan_type': scan_type,
            'args': str(args),
            'event': 'scan_start'
        })
    
    def log_scan_complete(self, scan_type: str, success: bool) -> None:
        """Log scan completion event"""
        logger = self.get_logger("scanner")
        status = "completed" if success else "failed"
        logger.info(f"Scan {status}", extra={
            'scan_type': scan_type,
            'success': success,
            'event': 'scan_complete'
        })
    
    def log_error(self, message: str, error: Exception) -> None:
        """Log error with full traceback"""
        logger = self.get_logger("error")
        logger.error(f"{message}: {str(error)}", extra={
            'error_type': type(error).__name__,
            'traceback': traceback.format_exc(),
            'event': 'error'
        })
    
    def log_tool_execution(self, tool_name: str, command: str, success: bool, output: str = "") -> None:
        """Log tool execution"""
        logger = self.get_logger("tools")
        status = "success" if success else "failed"
        logger.info(f"Tool execution {status}", extra={
            'tool_name': tool_name,
            'command': command,
            'success': success,
            'output': output[:1000] if output else "",  # Truncate long output
            'event': 'tool_execution'
        })
    
    def log_vulnerability(self, target: str, vuln_type: str, severity: str, details: Dict[str, Any]) -> None:
        """Log vulnerability discovery"""
        logger = self.get_logger("vulnerabilities")
        logger.warning(f"Vulnerability discovered", extra={
            'target': target,
            'vuln_type': vuln_type,
            'severity': severity,
            'details': details,
            'event': 'vulnerability_discovered'
        })
    
    def log_bruteforce_result(self, target: str, service: str, credentials: Dict[str, str]) -> None:
        """Log bruteforce results"""
        logger = self.get_logger("bruteforce")
        logger.info(f"Bruteforce successful", extra={
            'target': target,
            'service': service,
            'credentials': credentials,
            'event': 'bruteforce_success'
        })
    
    def log_recon_result(self, target: str, recon_type: str, results: Dict[str, Any]) -> None:
        """Log reconnaissance results"""
        logger = self.get_logger("recon")
        logger.info(f"Reconnaissance completed", extra={
            'target': target,
            'recon_type': recon_type,
            'results_count': len(results),
            'results': results,
            'event': 'recon_complete'
        })

# Global log manager instance
_log_manager = None

def setup_logging(config_path: Optional[str] = None) -> LogManager:
    """Setup logging system"""
    global _log_manager
    
    if _log_manager is None:
        _log_manager = LogManager(config_path)
    
    return _log_manager

def get_logger(name: str) -> logging.Logger:
    """Get logger instance"""
    if _log_manager is None:
        setup_logging()
    
    return _log_manager.get_logger(name)

def log_scan_start(scan_type: str, args: Any) -> None:
    """Log scan start event"""
    if _log_manager is None:
        setup_logging()
    
    _log_manager.log_scan_start(scan_type, args)

def log_scan_complete(scan_type: str, success: bool) -> None:
    """Log scan completion event"""
    if _log_manager is None:
        setup_logging()
    
    _log_manager.log_scan_complete(scan_type, success)

def log_error(message: str, error: Exception) -> None:
    """Log error with full traceback"""
    if _log_manager is None:
        setup_logging()
    
    _log_manager.log_error(message, error)

def log_tool_execution(tool_name: str, command: str, success: bool, output: str = "") -> None:
    """Log tool execution"""
    if _log_manager is None:
        setup_logging()
    
    _log_manager.log_tool_execution(tool_name, command, success, output)

def log_vulnerability(target: str, vuln_type: str, severity: str, details: Dict[str, Any]) -> None:
    """Log vulnerability discovery"""
    if _log_manager is None:
        setup_logging()
    
    _log_manager.log_vulnerability(target, vuln_type, severity, details)

def log_bruteforce_result(target: str, service: str, credentials: Dict[str, str]) -> None:
    """Log bruteforce results"""
    if _log_manager is None:
        setup_logging()
    
    _log_manager.log_bruteforce_result(target, service, credentials)

def log_recon_result(target: str, recon_type: str, results: Dict[str, Any]) -> None:
    """Log reconnaissance results"""
    if _log_manager is None:
        setup_logging()
    
    _log_manager.log_recon_result(target, recon_type, results)

def set_log_level(name: str, level: str) -> None:
    """Set log level for a specific logger"""
    if _log_manager is None:
        setup_logging()
    
    _log_manager.set_level(name, level)

def add_file_handler(name: str, file_path: str, level: str = "DEBUG") -> None:
    """Add file handler to a specific logger"""
    if _log_manager is None:
        setup_logging()
    
    _log_manager.add_file_handler(name, file_path, level) 