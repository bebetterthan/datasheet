"""
Tool Registry Module
====================

Central registry for all available tools.
"""

from typing import Dict, Any, Optional, List, Type

from agent.tools.base import BaseTool, ToolResult
from agent.utils.logger import get_logger


class ToolRegistry:
    """
    Central registry for agent tools.
    
    Manages tool registration, lookup, and execution routing.
    
    Usage:
        registry = ToolRegistry()
        registry.register(NmapTool())
        result = registry.execute("nmap", "scan", "192.168.1.1")
    """
    
    def __init__(self):
        """Initialize registry."""
        self._tools: Dict[str, BaseTool] = {}
        self._categories: Dict[str, List[str]] = {}
        self.logger = get_logger("ToolRegistry")
        
    def register(self, tool: BaseTool) -> None:
        """
        Register a tool.
        
        Args:
            tool: Tool instance to register
        """
        if tool.name in self._tools:
            self.logger.warning(f"Tool '{tool.name}' already registered, replacing")
            
        self._tools[tool.name] = tool
        
        # Track by category
        category = tool.category
        if category not in self._categories:
            self._categories[category] = []
        if tool.name not in self._categories[category]:
            self._categories[category].append(tool.name)
            
        self.logger.info(f"Registered tool: {tool.name} ({category})")
        
    def unregister(self, name: str) -> None:
        """
        Unregister a tool.
        
        Args:
            name: Tool name to remove
        """
        if name in self._tools:
            tool = self._tools.pop(name)
            category = tool.category
            if category in self._categories:
                self._categories[category] = [
                    t for t in self._categories[category] if t != name
                ]
            self.logger.info(f"Unregistered tool: {name}")
            
    def get(self, name: str) -> Optional[BaseTool]:
        """
        Get a tool by name.
        
        Args:
            name: Tool name
            
        Returns:
            Tool instance or None
        """
        return self._tools.get(name)
        
    def execute(
        self,
        tool_name: str,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """
        Execute a tool action.
        
        Args:
            tool_name: Name of tool to execute
            action: Action to perform
            target: Target of action
            params: Additional parameters
            
        Returns:
            ToolResult from execution
        """
        tool = self.get(tool_name)
        
        if tool is None:
            self.logger.error(f"Tool not found: {tool_name}")
            return ToolResult(
                status=ToolStatus.ERROR,
                output="",
                error=f"Tool '{tool_name}' not found"
            )
            
        if not tool.is_enabled:
            self.logger.warning(f"Tool '{tool_name}' is disabled")
            return ToolResult(
                status=ToolStatus.SKIPPED,
                output="",
                error=f"Tool '{tool_name}' is disabled"
            )
            
        try:
            return tool.execute(action, target, params)
        except Exception as e:
            self.logger.error(f"Tool execution error: {e}")
            return ToolResult(
                status=ToolStatus.ERROR,
                output="",
                error=str(e)
            )
            
    def list_tools(self) -> List[Dict[str, Any]]:
        """List all registered tools."""
        return [tool.get_info() for tool in self._tools.values()]
        
    def list_by_category(self, category: str) -> List[str]:
        """List tools in a category."""
        return self._categories.get(category, [])
        
    def get_categories(self) -> List[str]:
        """Get all tool categories."""
        return list(self._categories.keys())
        
    def has_tool(self, name: str) -> bool:
        """Check if tool is registered."""
        return name in self._tools
        
    def get_actions(self, tool_name: str) -> List[str]:
        """Get available actions for a tool."""
        tool = self.get(tool_name)
        return tool.actions if tool else []
        
    def __len__(self) -> int:
        return len(self._tools)
        
    def __contains__(self, name: str) -> bool:
        return name in self._tools
        
    def __iter__(self):
        return iter(self._tools.values())


# Import ToolStatus for use in execute
from agent.tools.base import ToolStatus
