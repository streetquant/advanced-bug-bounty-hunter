"""Enhanced logging configuration with correlation IDs and sensitive data redaction.

This module provides centralized logging configuration with support for
structured logging, correlation tracking, sensitive data protection,
and multiple output formats.
"""

import logging
import logging.handlers
import sys
import re
import json
import uuid
import contextvars
from pathlib import Path
from typing import Optional, Dict, Any, List, Pattern
from datetime import datetime

import structlog
from rich.logging import RichHandler
from rich.console import Console

# Global logger registry
_loggers = {}
_configured = False

# Context variable for correlation ID
correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    'correlation_id', default=''
)

# Context variable for agent ID
agent_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    'agent_id', default=''
)

# Context variable for scan ID
scan_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    'scan_id', default=''
)


class SensitiveDataRedactor:
    """Redacts sensitive information from log messages."""
    
    def __init__(self):
        # Patterns for sensitive data detection
        self.patterns: List[tuple[Pattern, str]] = [
            # Credit card numbers
            (re.compile(r'\b(?:\d{4}[\s-]?){3}\d{4}\b'), '[CREDIT_CARD]'),
            
            # Social Security Numbers (US format)
            (re.compile(r'\b\d{3}-?\d{2}-?\d{4}\b'), '[SSN]'),
            
            # Email addresses (partial redaction)
            (re.compile(r'\b([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b'), 
             lambda m: f'{m.group(1)[:2]}***@{m.group(2)}'),
            
            # Phone numbers
            (re.compile(r'\b(?:\+?1[-\s]?)?\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4}\b'), '[PHONE]'),
            
            # API Keys (various formats)
            (re.compile(r'\b[A-Za-z0-9]{32,}\b'), '[API_KEY]'),
            
            # JWT tokens
            (re.compile(r'\beyJ[A-Za-z0-9_/+\-=]+\.eyJ[A-Za-z0-9_/+\-=]+\.[A-Za-z0-9_/+\-=]*\b'), '[JWT_TOKEN]'),
            
            # Password fields in JSON/form data
            (re.compile(r'(["\']?password["\']?\s*[=:]\s*["\']?)([^"\',}\s]+)(["\']?)', re.IGNORECASE), 
             r'\1[PASSWORD]\3'),
            
            # Auth tokens in headers
            (re.compile(r'(authorization\s*:\s*(?:bearer\s+|basic\s+)?)([a-zA-Z0-9+/=]+)', re.IGNORECASE), 
             r'\1[AUTH_TOKEN]'),
            
            # Session IDs
            (re.compile(r'(sessionid\s*[=:]\s*["\']?)([a-zA-Z0-9]+)(["\']?)', re.IGNORECASE), 
             r'\1[SESSION_ID]\3'),
            
            # Database connection strings
            (re.compile(r'(://[^:]+:)([^@]+)(@)', re.IGNORECASE), r'\1[PASSWORD]\3'),
        ]
    
    def redact(self, message: str) -> str:
        """Redact sensitive information from a message.
        
        Args:
            message: Original log message
            
        Returns:
            Message with sensitive data redacted
        """
        redacted = message
        
        for pattern, replacement in self.patterns:
            if callable(replacement):
                redacted = pattern.sub(replacement, redacted)
            else:
                redacted = pattern.sub(replacement, redacted)
        
        return redacted


class CorrelationProcessor:
    """Processor to add correlation information to log records."""
    
    def __call__(self, logger, method_name, event_dict):
        """Add correlation information to event dictionary.
        
        Args:
            logger: Logger instance
            method_name: Log method name
            event_dict: Event dictionary
            
        Returns:
            Modified event dictionary
        """
        # Add correlation ID if available
        corr_id = correlation_id.get()
        if corr_id:
            event_dict['correlation_id'] = corr_id
        
        # Add agent ID if available
        agent = agent_id.get()
        if agent:
            event_dict['agent_id'] = agent
        
        # Add scan ID if available
        scan = scan_id.get()
        if scan:
            event_dict['scan_id'] = scan
        
        # Add timestamp in ISO format
        event_dict['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        
        return event_dict


class SensitiveDataProcessor:
    """Processor to redact sensitive data from log records."""
    
    def __init__(self):
        self.redactor = SensitiveDataRedactor()
    
    def __call__(self, logger, method_name, event_dict):
        """Redact sensitive data from event dictionary.
        
        Args:
            logger: Logger instance
            method_name: Log method name
            event_dict: Event dictionary
            
        Returns:
            Event dictionary with sensitive data redacted
        """
        # Redact the main event message
        if 'event' in event_dict:
            event_dict['event'] = self.redactor.redact(str(event_dict['event']))
        
        # Redact other string fields
        for key, value in event_dict.items():
            if isinstance(value, str):
                event_dict[key] = self.redactor.redact(value)
            elif isinstance(value, dict):
                event_dict[key] = self._redact_dict(value)
        
        return event_dict
    
    def _redact_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively redact sensitive data from dictionary.
        
        Args:
            data: Dictionary to process
            
        Returns:
            Dictionary with sensitive data redacted
        """
        redacted = {}
        for key, value in data.items():
            if isinstance(value, str):
                redacted[key] = self.redactor.redact(value)
            elif isinstance(value, dict):
                redacted[key] = self._redact_dict(value)
            else:
                redacted[key] = value
        return redacted


class SecurityAuditFormatter(logging.Formatter):
    """Custom formatter for security audit logs."""
    
    def __init__(self):
        super().__init__()
        self.redactor = SensitiveDataRedactor()
    
    def format(self, record):
        """Format log record with security considerations.
        
        Args:
            record: Log record to format
            
        Returns:
            Formatted log message
        """
        # Redact sensitive data from the message
        if hasattr(record, 'msg'):
            record.msg = self.redactor.redact(str(record.msg))
        
        # Add correlation information
        corr_id = correlation_id.get()
        if corr_id:
            record.correlation_id = corr_id
        
        agent = agent_id.get()
        if agent:
            record.agent_id = agent
        
        scan = scan_id.get()
        if scan:
            record.scan_id = scan
        
        # Format with correlation info
        format_string = (
            '%(asctime)s - %(name)s - %(levelname)s'
        )
        
        if hasattr(record, 'correlation_id'):
            format_string += ' - [%(correlation_id)s]'
        
        if hasattr(record, 'agent_id'):
            format_string += ' - [%(agent_id)s]'
        
        if hasattr(record, 'scan_id'):
            format_string += ' - [%(scan_id)s]'
        
        format_string += ' - %(message)s'
        
        formatter = logging.Formatter(format_string)
        return formatter.format(record)


def setup_logging(level: str = "INFO", 
                 log_file: Optional[str] = None,
                 format_type: str = "structured",
                 max_size: str = "100MB",
                 backup_count: int = 5,
                 enable_sensitive_data_redaction: bool = True) -> None:
    """Set up enhanced logging configuration for the application.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        format_type: Log format type (structured, simple, security)
        max_size: Maximum log file size before rotation
        backup_count: Number of backup files to keep
        enable_sensitive_data_redaction: Whether to enable sensitive data redaction
    """
    global _configured
    
    if _configured:
        return
    
    # Configure structlog for structured logging
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        CorrelationProcessor(),  # Add correlation information
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]
    
    # Add sensitive data redaction if enabled
    if enable_sensitive_data_redaction:
        processors.insert(-2, SensitiveDataProcessor())
    
    if format_type == "structured":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.processors.KeyValueRenderer())
    
    structlog.configure(
        processors=processors,
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
        tracebacks_show_locals=False  # Avoid showing locals for security
    )
    console_handler.setLevel(getattr(logging, level.upper()))
    
    # Use security formatter for console if requested
    if format_type == "security":
        console_handler.setFormatter(SecurityAuditFormatter())
    elif format_type == "simple":
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
        
        # Use appropriate formatter for file output
        if format_type == "security":
            file_handler.setFormatter(SecurityAuditFormatter())
        elif format_type == "structured":
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        else:
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
        
        if format_type != "security":
            file_handler.setFormatter(file_formatter)
        
        root_logger.addHandler(file_handler)
    
    # Suppress noisy third-party loggers
    logging.getLogger('playwright').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)
    logging.getLogger('aiohttp').setLevel(logging.WARNING)
    
    _configured = True
    
    # Log setup completion with correlation ID
    logger = get_logger("logging")
    with LogContext(correlation_id=generate_correlation_id()):
        logger.info(
            f"Enhanced logging configured: level={level}, format={format_type}, "
            f"file={log_file}, redaction={enable_sensitive_data_redaction}"
        )


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
        
        _loggers[name] = structlog.get_logger(name)
    
    return _loggers[name]


def generate_correlation_id() -> str:
    """Generate a new correlation ID.
    
    Returns:
        New correlation ID
    """
    return str(uuid.uuid4())[:8]


def set_correlation_id(corr_id: str) -> None:
    """Set the correlation ID for the current context.
    
    Args:
        corr_id: Correlation ID to set
    """
    correlation_id.set(corr_id)


def get_correlation_id() -> str:
    """Get the current correlation ID.
    
    Returns:
        Current correlation ID or empty string
    """
    return correlation_id.get()


def set_agent_id(agent: str) -> None:
    """Set the agent ID for the current context.
    
    Args:
        agent: Agent ID to set
    """
    agent_id.set(agent)


def get_agent_id() -> str:
    """Get the current agent ID.
    
    Returns:
        Current agent ID or empty string
    """
    return agent_id.get()


def set_scan_id(scan: str) -> None:
    """Set the scan ID for the current context.
    
    Args:
        scan: Scan ID to set
    """
    scan_id.set(scan)


def get_scan_id() -> str:
    """Get the current scan ID.
    
    Returns:
        Current scan ID or empty string
    """
    return scan_id.get()


class LogContext:
    """Context manager for adding context to logs with correlation tracking."""
    
    def __init__(self, correlation_id: Optional[str] = None, 
                 agent_id: Optional[str] = None,
                 scan_id: Optional[str] = None,
                 **extra_context):
        """Initialize log context.
        
        Args:
            correlation_id: Correlation ID for request tracking
            agent_id: Agent ID for agent-specific logging
            scan_id: Scan ID for scan-specific logging
            **extra_context: Additional context key-value pairs
        """
        self.correlation_id = correlation_id
        self.agent_id = agent_id
        self.scan_id = scan_id
        self.extra_context = extra_context
        
        # Store previous values to restore later
        self.prev_correlation_id = None
        self.prev_agent_id = None
        self.prev_scan_id = None
    
    def __enter__(self):
        """Enter the context."""
        # Store previous values
        self.prev_correlation_id = correlation_id.get()
        self.prev_agent_id = agent_id.get()
        self.prev_scan_id = scan_id.get()
        
        # Set new values
        if self.correlation_id:
            correlation_id.set(self.correlation_id)
        if self.agent_id:
            agent_id.set(self.agent_id)
        if self.scan_id:
            scan_id.set(self.scan_id)
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the context."""
        # Restore previous values
        if self.prev_correlation_id:
            correlation_id.set(self.prev_correlation_id)
        if self.prev_agent_id:
            agent_id.set(self.prev_agent_id)
        if self.prev_scan_id:
            scan_id.set(self.prev_scan_id)


class SecurityAuditLogger:
    """Specialized logger for security audit events."""
    
    def __init__(self, name: str):
        self.logger = get_logger(f"security.{name}")
    
    def log_vulnerability_found(self, vuln_data: Dict[str, Any]) -> None:
        """Log a vulnerability discovery.
        
        Args:
            vuln_data: Vulnerability information
        """
        with LogContext(correlation_id=generate_correlation_id()):
            self.logger.critical(
                "VULNERABILITY_FOUND",
                **vuln_data
            )
    
    def log_scope_violation(self, url: str, reason: str) -> None:
        """Log a scope violation.
        
        Args:
            url: URL that violated scope
            reason: Reason for violation
        """
        with LogContext(correlation_id=generate_correlation_id()):
            self.logger.warning(
                "SCOPE_VIOLATION",
                url=url,
                reason=reason
            )
    
    def log_authentication_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Log an authentication event.
        
        Args:
            event_type: Type of authentication event
            details: Event details
        """
        with LogContext(correlation_id=generate_correlation_id()):
            self.logger.info(
                f"AUTH_{event_type.upper()}",
                **details
            )
    
    def log_agent_action(self, action: str, agent_name: str, details: Dict[str, Any]) -> None:
        """Log an agent action.
        
        Args:
            action: Action performed
            agent_name: Name of the agent
            details: Action details
        """
        with LogContext(agent_id=agent_name, correlation_id=generate_correlation_id()):
            self.logger.info(
                f"AGENT_ACTION_{action.upper()}",
                **details
            )


# Convenience function for security audit logging
def get_security_logger(name: str) -> SecurityAuditLogger:
    """Get a security audit logger.
    
    Args:
        name: Logger name
        
    Returns:
        Security audit logger instance
    """
    return SecurityAuditLogger(name)
