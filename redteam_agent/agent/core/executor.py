"""
Executor Module
===============

Safely executes security tools with proper validation and error handling.
"""

from typing import Dict, Any, Optional
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

from agent.utils.logger import get_logger


class Executor:
    """
    Tool execution module for the Red Team Agent.
    
    Responsible for:
    - Validating tool existence and parameters
    - Checking authorization via Gate Zero
    - Executing tools with timeout
    - Capturing output and errors
    - Handling failures gracefully
    
    Attributes:
        tools: Tool registry
        gate: Gate Zero security layer
    """
    
    def __init__(self, tools, gate, default_timeout: int = 60):
        """
        Initialize the Executor.
        
        Args:
            tools: ToolRegistry instance
            gate: GateZero instance
            default_timeout: Default execution timeout in seconds
        """
        self.tools = tools
        self.gate = gate
        self.default_timeout = default_timeout
        self.logger = get_logger("Executor")
        
    def execute(
        self,
        tool_name: str,
        action: str,
        params: Dict[str, Any],
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute a tool safely.
        
        Args:
            tool_name: Name of the tool to execute
            action: Action to perform
            params: Parameters for the tool
            timeout: Execution timeout (uses default if not specified)
            
        Returns:
            Execution result dictionary with:
            - success: bool
            - output: tool output (if successful)
            - findings: list of findings (if any)
            - error: error message (if failed)
            - duration: execution time in seconds
        """
        start_time = time.time()
        timeout = timeout or self.default_timeout
        
        self.logger.info(f"Executing {tool_name}.{action}")
        
        try:
            # Step 1: Validate tool exists
            tool = self.tools.get(tool_name)
            if tool is None:
                return self._error_result(
                    f"Tool '{tool_name}' not found",
                    start_time
                )
            
            # Step 2: Validate parameters
            validation_result = tool.validate_params(params)
            if not validation_result.get("valid", False):
                return self._error_result(
                    f"Invalid parameters: {validation_result.get('error', 'Unknown error')}",
                    start_time
                )
            
            # Step 3: Check authorization (if tool requires it)
            if tool.requires_auth:
                target = params.get("url") or params.get("target") or params.get("domain")
                if target and not self.gate.validate_target(target):
                    return self._error_result(
                        f"Target '{target}' not authorized",
                        start_time
                    )
            
            # Step 4: Execute with timeout
            result = self._execute_with_timeout(tool, action, params, timeout)
            
            # Step 5: Log action
            self.gate.log_action("tool_execution", {
                "tool": tool_name,
                "action": action,
                "params": params,
                "success": result.get("success", False),
                "duration": time.time() - start_time
            })
            
            return result
            
        except FuturesTimeoutError:
            return self._error_result(
                f"Execution timeout after {timeout}s",
                start_time,
                status="timeout"
            )
        except Exception as e:
            self.logger.error(f"Execution error: {e}")
            return self._error_result(str(e), start_time)
            
    def _execute_with_timeout(
        self,
        tool,
        action: str,
        params: Dict[str, Any],
        timeout: int
    ) -> Dict[str, Any]:
        """Execute tool with timeout protection."""
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(tool.execute, action, params)
            try:
                result = future.result(timeout=timeout)
                return {
                    "success": True,
                    "output": result.get("output"),
                    "findings": result.get("findings", []),
                    "raw": result.get("raw")
                }
            except FuturesTimeoutError:
                raise
            except Exception as e:
                return {
                    "success": False,
                    "error": str(e)
                }
                
    def _error_result(
        self,
        error: str,
        start_time: float,
        status: str = "error"
    ) -> Dict[str, Any]:
        """Create error result dictionary."""
        return {
            "success": False,
            "error": error,
            "status": status,
            "duration": time.time() - start_time
        }
        
    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific tool."""
        tool = self.tools.get(tool_name)
        if tool:
            return tool.get_schema()
        return None
        
    def list_available_tools(self) -> list:
        """List all available tools."""
        return self.tools.list_all()
