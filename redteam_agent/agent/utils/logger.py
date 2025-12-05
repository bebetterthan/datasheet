"""
Logger Module
=============

Centralized logging for the Red Team Agent.
"""

import logging
import sys
from typing import Optional
from datetime import datetime
from pathlib import Path


# Global logger cache
_loggers: dict = {}


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    format_string: Optional[str] = None
) -> None:
    """
    Setup global logging configuration.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        format_string: Custom format string
    """
    if format_string is None:
        format_string = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
        
    # Create formatter
    formatter = logging.Formatter(format_string)
    
    # Get root logger
    root_logger = logging.getLogger("redteam_agent")
    root_logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        # Create logs directory if needed
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        

def get_logger(name: str) -> logging.Logger:
    """
    Get or create a logger with the given name.
    
    Args:
        name: Logger name (usually module name)
        
    Returns:
        Logger instance
    """
    full_name = f"redteam_agent.{name}"
    
    if full_name not in _loggers:
        logger = logging.getLogger(full_name)
        
        # If no handlers set up yet, do basic setup
        if not logger.handlers and not logger.parent.handlers:
            setup_logging()
            
        _loggers[full_name] = logger
        
    return _loggers[full_name]


class TaskLogger:
    """
    Specialized logger for tracking task execution.
    
    Provides structured logging with task context.
    """
    
    def __init__(self, task_id: str, logger: Optional[logging.Logger] = None):
        """
        Initialize TaskLogger.
        
        Args:
            task_id: Unique task identifier
            logger: Optional base logger
        """
        self.task_id = task_id
        self.logger = logger or get_logger("TaskLogger")
        self._log_buffer: list = []
        
    def log(self, level: str, message: str, **kwargs) -> None:
        """
        Log a message with task context.
        
        Args:
            level: Log level
            message: Log message
            **kwargs: Additional context
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "task_id": self.task_id,
            "level": level,
            "message": message,
            **kwargs
        }
        
        self._log_buffer.append(entry)
        
        # Also log to standard logger
        log_func = getattr(self.logger, level.lower(), self.logger.info)
        log_func(f"[{self.task_id[:8]}] {message}")
        
    def debug(self, message: str, **kwargs) -> None:
        """Log debug message."""
        self.log("DEBUG", message, **kwargs)
        
    def info(self, message: str, **kwargs) -> None:
        """Log info message."""
        self.log("INFO", message, **kwargs)
        
    def warning(self, message: str, **kwargs) -> None:
        """Log warning message."""
        self.log("WARNING", message, **kwargs)
        
    def error(self, message: str, **kwargs) -> None:
        """Log error message."""
        self.log("ERROR", message, **kwargs)
        
    def critical(self, message: str, **kwargs) -> None:
        """Log critical message."""
        self.log("CRITICAL", message, **kwargs)
        
    def step(self, step_num: int, action: str, status: str = "started") -> None:
        """
        Log step execution.
        
        Args:
            step_num: Step number
            action: Action being performed
            status: Step status
        """
        self.info(f"Step {step_num}: {action} [{status}]", 
                  step=step_num, action=action, status=status)
        
    def finding(self, severity: str, finding_type: str, description: str) -> None:
        """
        Log a finding.
        
        Args:
            severity: Finding severity
            finding_type: Type of finding
            description: Finding description
        """
        self.info(f"Finding [{severity.upper()}]: {finding_type}",
                  severity=severity, type=finding_type, description=description)
        
    def get_log(self) -> list:
        """Get the log buffer."""
        return self._log_buffer.copy()
        
    def export(self, filepath: str) -> None:
        """
        Export log to file.
        
        Args:
            filepath: Path to save log
        """
        import json
        with open(filepath, "w") as f:
            json.dump(self._log_buffer, f, indent=2)
