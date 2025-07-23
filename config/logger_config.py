"""
Cyber-SOC Auto-Responder Logging Configuration

This module sets up structured logging with timestamped events for complete
audit trail and observability of all system actions.
"""

import logging
import logging.handlers
import structlog
import sys
from pathlib import Path
from typing import Any, Dict
from rich.console import Console
from rich.logging import RichHandler

def setup_logging(
    log_level: str = "INFO",
    log_file: Path = Path("./logs/cybersoc.log"),
    max_size: int = 10485760,  # 10MB
    backup_count: int = 5,
    enable_rich: bool = True
) -> None:
    """
    Set up structured logging for the Cyber-SOC Auto-Responder system.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file
        max_size: Maximum size of log file before rotation
        backup_count: Number of backup files to keep
        enable_rich: Whether to use Rich for colorized console output
    """
    
    # Ensure log directory exists
    log_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.JSONRenderer()
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level.upper())
        ),
        logger_factory=structlog.WriteLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear any existing handlers
    root_logger.handlers.clear()
    
    # Create file handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        filename=log_file,
        maxBytes=max_size,
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setLevel(getattr(logging, log_level.upper()))
    
    # Create console handler
    if enable_rich:
        console_handler = RichHandler(
            console=Console(stderr=True),
            show_time=True,
            show_path=True,
            markup=True,
            rich_tracebacks=True
        )
    else:
        console_handler = logging.StreamHandler(sys.stdout)
    
    console_handler.setLevel(getattr(logging, log_level.upper()))
    
    # Create formatters
    file_formatter = logging.Formatter(
        '%(asctime)s | %(levelname)8s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    if not enable_rich:
        console_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)8s | %(name)s | %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
    
    file_handler.setFormatter(file_formatter)
    
    # Add handlers to root logger
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # Set specific logger levels for third-party libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.INFO)
    logging.getLogger("splunklib").setLevel(logging.INFO)

def get_logger(name: str) -> structlog.BoundLogger:
    """
    Get a structured logger instance.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Configured structlog.BoundLogger instance
    """
    return structlog.get_logger(name)

def log_event(
    logger: structlog.BoundLogger,
    event_type: str,
    message: str,
    **kwargs: Any
) -> None:
    """
    Log a structured event with consistent formatting.
    
    Args:
        logger: The logger instance
        event_type: Type of event (alert_processed, host_isolated, etc.)
        message: Human-readable message
        **kwargs: Additional structured data
    """
    logger.info(
        message,
        event_type=event_type,
        **kwargs
    )

def log_alert_processing(
    logger: structlog.BoundLogger,
    alert_id: str,
    source: str,
    severity: str,
    action: str,
    duration_ms: int = None,
    **kwargs: Any
) -> None:
    """
    Log alert processing events with standardized fields.
    
    Args:
        logger: The logger instance
        alert_id: Unique alert identifier
        source: Source system (splunk, manual, etc.)
        severity: Alert severity level
        action: Action taken (triaged, escalated, isolated, etc.)
        duration_ms: Processing duration in milliseconds
        **kwargs: Additional context
    """
    log_data = {
        "alert_id": alert_id,
        "source": source,
        "severity": severity,
        "action": action,
        **kwargs
    }
    
    if duration_ms is not None:
        log_data["duration_ms"] = duration_ms
    
    log_event(
        logger,
        "alert_processing",
        f"Alert {alert_id} {action}",
        **log_data
    )

def log_integration_call(
    logger: structlog.BoundLogger,
    integration: str,
    endpoint: str,
    method: str,
    status_code: int = None,
    duration_ms: int = None,
    error: str = None
) -> None:
    """
    Log external integration API calls.
    
    Args:
        logger: The logger instance
        integration: Integration name (splunk, crowdstrike, thehive)
        endpoint: API endpoint called
        method: HTTP method
        status_code: Response status code
        duration_ms: Request duration in milliseconds
        error: Error message if request failed
    """
    log_data = {
        "integration": integration,
        "endpoint": endpoint,
        "method": method
    }
    
    if status_code is not None:
        log_data["status_code"] = status_code
    
    if duration_ms is not None:
        log_data["duration_ms"] = duration_ms
    
    if error:
        log_data["error"] = error
        logger.error(
            f"{integration} API call failed: {error}",
            event_type="integration_error",
            **log_data
        )
    else:
        logger.info(
            f"{integration} API call completed",
            event_type="integration_call",
            **log_data
        )

def log_security_event(
    logger: structlog.BoundLogger,
    event_type: str,
    description: str,
    host: str = None,
    user: str = None,
    indicators: list = None,
    **kwargs: Any
) -> None:
    """
    Log security-related events with standardized fields.
    
    Args:
        logger: The logger instance
        event_type: Security event type (malware_detected, host_isolated, etc.)
        description: Event description
        host: Affected hostname/IP
        user: Affected username
        indicators: List of IOCs or indicators
        **kwargs: Additional security context
    """
    log_data = {
        "event_type": event_type,
        "description": description,
        **kwargs
    }
    
    if host:
        log_data["host"] = host
    
    if user:
        log_data["user"] = user
    
    if indicators:
        log_data["indicators"] = indicators
    
    logger.warning(
        description,
        event_type="security_event",
        **log_data
    ) 