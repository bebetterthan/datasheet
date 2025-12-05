"""
Tools Package
=============

Security assessment tools for the Red Team Agent.

Tool Categories:
    - recon: Reconnaissance and information gathering
    - scanner: Vulnerability scanning
    - analyzer: Data analysis and processing
    - reporter: Report generation tools
"""

from agent.tools.base import BaseTool, ToolResult
from agent.tools.registry import ToolRegistry

__all__ = [
    "BaseTool",
    "ToolResult",
    "ToolRegistry"
]
