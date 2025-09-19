"""Logging configuration and utilities.

This module provides centralized logging configuration with support for
structured logging, multiple output formats, and proper log management.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

import structlog
from rich.logging import RichHandler
from rich.console import Console

# Global logger registry
_loggers = {}
_configured = False


def setup_logging(level: str = "INFO", 
                 log_file: Optional[str] = None,
                 format_type: str = "structured",
                 max_size: str = "100MB",
                 backup_count: int = 5) -> None:
    """Set up logging configuration for the application.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        format_type: Log format type (structured, simple)
        max_size: Maximum log file size before rotation
        backup_count: Number of backup files to keep
    """
    global _configured
    
    if _configured:
        return
    
    # Configure structlog for structured logging
    if format_type == "structured":
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
    
    # Set up root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler with Rich formatting
    console = Console(stderr=True)
    console_handler = RichHandler(
        console=console,
        show_path=True,
        show_time=True,
        rich_tracebacks=True,
        tracebacks_show_locals=True
    )
    console_handler.setLevel(getattr(logging, level.upper()))
    
    if format_type == "simple":
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
    
    root_logger.addHandler(console_handler)
    
    # File handler with rotation if log file is specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert size string to bytes
        size_multipliers = {
            'KB': 1024,
            'MB': 1024 * 1024,
            'GB': 1024 * 1024 * 1024
        }
        
        max_bytes = 100 * 1024 * 1024  # Default 100MB
        for suffix, multiplier in size_multipliers.items():
            if max_size.upper().endswith(suffix):
                size_value = int(max_size[:-len(suffix)].strip())
                max_bytes = size_value * multiplier
                break
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(getattr(logging, level.upper()))
        
        if format_type == "structured":
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        else:
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
        
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
    
    # Suppress noisy third-party loggers
    logging.getLogger('playwright').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)
    
    _configured = True
    
    # Log setup completion
    logger = get_logger("logging")
    logger.info(f"Logging configured: level={level}, format={format_type}, file={log_file}")


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the specified name.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    global _loggers
    
    if name not in _loggers:
        if not _configured:
            # Set up basic logging if not configured yet
            setup_logging()
        
        _loggers[name] = logging.getLogger(name)
    
    return _loggers[name]


class LogContext:
    """Context manager for adding context to logs."""
    
    def __init__(self, logger: logging.Logger, **context):
        """Initialize log context.
        
        Args:
            logger: Logger instance
            **context: Context key-value pairs
        """
        self.logger = logger
        self.context = context
        self.bound_logger = None
    
    def __enter__(self):
        """Enter the context."""
        if hasattr(self.logger, 'bind'):  # structlog logger
            self.bound_logger = self.logger.bind(**self.context)
            return self.bound_logger
        else:
            # Standard logger - add context to each message
            return LoggerAdapter(self.logger, self.context)
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the context."""
        pass


class LoggerAdapter(logging.LoggerAdapter):
    """Logger adapter for adding context to standard loggers."""
    
    def process(self, msg, kwargs):
        """Process the log message with context."""
        context_str = ' '.join(f'{k}={v}' for k, v in self.extra.items())
        return f'[{context_str}] {msg}', kwargs
