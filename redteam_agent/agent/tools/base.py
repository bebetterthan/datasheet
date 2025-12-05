"""
Base Tool Module
================

Abstract base class for all tools.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from agent.utils.logger import get_logger


class ToolStatus(Enum):
    """Status of tool execution."""
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class ToolResult:
    """
    Result of tool execution.
    
    Attributes:
        status: Execution status
        output: Raw output from tool
        parsed: Parsed/structured output
        error: Error message if failed
        duration: Execution time in seconds
        metadata: Additional metadata
    """
    status: ToolStatus
    output: str
    parsed: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration: float = 0.0
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status": self.status.value,
            "output": self.output,
            "parsed": self.parsed,
            "error": self.error,
            "duration": self.duration,
            "metadata": self.metadata or {}
        }
        
    @property
    def success(self) -> bool:
        """Check if execution was successful."""
        return self.status == ToolStatus.SUCCESS


class BaseTool(ABC):
    """
    Abstract base class for all agent tools.
    
    All tools must inherit from this class and implement:
        - name: Tool identifier
        - description: What the tool does
        - execute(): Main execution method
        - parse_output(): Parse raw output into structured data
        
    Example:
        class NmapTool(BaseTool):
            name = "nmap"
            description = "Network port scanner"
            
            def execute(self, target: str, **kwargs) -> ToolResult:
                # Run nmap
                pass
    """
    
    # Tool metadata (override in subclass)
    name: str = "base"
    description: str = "Base tool class"
    category: str = "general"
    
    # Tool capabilities
    actions: List[str] = []
    
    # Execution settings
    timeout: int = 300  # Default 5 minute timeout
    requires_root: bool = False
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize tool.
        
        Args:
            config: Tool-specific configuration
        """
        self.config = config or {}
        self.logger = get_logger(f"Tool.{self.name}")
        self._enabled = True
        
    @abstractmethod
    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """
        Execute tool action.
        
        Args:
            action: Action to perform
            target: Target of the action
            params: Additional parameters
            
        Returns:
            ToolResult with execution results
        """
        pass
        
    @abstractmethod
    def parse_output(self, output: str) -> Dict[str, Any]:
        """
        Parse raw output into structured data.
        
        Args:
            output: Raw tool output
            
        Returns:
            Parsed data dictionary
        """
        pass
        
    def validate_params(
        self,
        action: str,
        params: Optional[Dict[str, Any]]
    ) -> bool:
        """
        Validate action parameters.
        
        Args:
            action: Action to validate
            params: Parameters to validate
            
        Returns:
            True if valid, raises ValueError otherwise
        """
        if action not in self.actions:
            raise ValueError(
                f"Action '{action}' not supported. "
                f"Available: {self.actions}"
            )
        return True
        
    def get_info(self) -> Dict[str, Any]:
        """Get tool information."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "actions": self.actions,
            "timeout": self.timeout,
            "requires_root": self.requires_root,
            "enabled": self._enabled
        }
        
    def enable(self) -> None:
        """Enable the tool."""
        self._enabled = True
        
    def disable(self) -> None:
        """Disable the tool."""
        self._enabled = False
        
    @property
    def is_enabled(self) -> bool:
        """Check if tool is enabled."""
        return self._enabled
        
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.name})>"
