"""
Logging configuration for the Multi-Protocol IoT Router
Provides structured logging with different verbosity levels
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional


class BluetoothNoiseFilter(logging.Filter):
    """Filter out noisy Bluetooth D-Bus messages"""
    
    def filter(self, record):
        # Filter out specific noisy Bleak messages
        message = record.getMessage()
        
        # Filter D-Bus PropertiesChanged messages
        if 'PropertiesChanged' in message and ('RSSI' in message or 'TxPower' in message):
            return False
            
        # Filter D-Bus signal reception messages  
        if 'received D-Bus signal' in message and 'org.freedesktop.DBus.Properties' in message:
            return False
            
        # Filter verbose device property updates
        if record.name == 'bleak.backends.bluezdbus.manager' and 'RSSI' in message:
            return False
            
        return True


class ColoredFormatter(logging.Formatter):
    """Colored log formatter for console output"""
    
    # Color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'        # Reset
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{log_color}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)


def setup_logging(level: int = logging.INFO, log_file: Optional[str] = None):
    """
    Setup logging configuration
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional file path for logging to file
    """
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create formatter
    if log_file:
        # File logging format (no colors)
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    else:
        # Console logging format (with colors)
        formatter = ColoredFormatter(
            '%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s',
            datefmt='%H:%M:%S'
        )
    
    if log_file:
        # File handler with rotation
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    else:
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # Set specific logger levels
    if level >= logging.INFO:
        # Reduce noise from third-party libraries
        logging.getLogger('bleak').setLevel(logging.WARNING)
        logging.getLogger('asyncio').setLevel(logging.WARNING)
    
    # Always silence these noisy debug loggers even in debug mode
    logging.getLogger('bleak.backends.bluezdbus.manager').setLevel(logging.INFO)
    logging.getLogger('bleak.backends.bluezdbus.client').setLevel(logging.INFO)
    logging.getLogger('bleak.backends.bluezdbus.scanner').setLevel(logging.INFO)
    logging.getLogger('dbus_fast').setLevel(logging.WARNING)
    logging.getLogger('dbus_fast.signature').setLevel(logging.WARNING)
    
    # Apply noise filter to all handlers
    bluetooth_filter = BluetoothNoiseFilter()
    for handler in logger.handlers:
        handler.addFilter(bluetooth_filter)
    
    # Log the logging setup
    logger.info(f"Logging configured - Level: {logging.getLevelName(level)}")
    if log_file:
        logger.info(f"Logging to file: {log_file}")


class RouterLogger:
    """Router-specific logger with context"""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
    
    def debug(self, message: str, **kwargs):
        """Log debug message with context"""
        self._log(logging.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message with context"""
        self._log(logging.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message with context"""
        self._log(logging.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message with context"""
        self._log(logging.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message with context"""
        self._log(logging.CRITICAL, message, **kwargs)
    
    def _log(self, level: int, message: str, **kwargs):
        """Internal logging method with context"""
        if kwargs:
            context_parts = []
            for key, value in kwargs.items():
                context_parts.append(f"{key}={value}")
            context = " | ".join(context_parts)
            message = f"{message} | {context}"
        
        self.logger.log(level, message)


def get_logger(name: str) -> RouterLogger:
    """Get a router logger instance"""
    return RouterLogger(name)