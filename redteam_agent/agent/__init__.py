"""
Red Team AI Agent Framework
===========================

A comprehensive AI-powered security assessment agent that combines
fine-tuned LLM capabilities with automated security tools.

Components:
- core: Agent engine (planner, executor, observer, memory)
- llm: LLM integration layer
- tools: Security assessment tools
- security: Gate Zero authorization layer
- utils: Helper utilities
"""

__version__ = "1.0.0"
__author__ = "Red Team AI"

from agent.core.agent import RedTeamAgent as Agent
from agent.core.agent import AgentConfig, AgentState

__all__ = [
    "Agent",
    "AgentConfig",
    "AgentState",
    "__version__"
]
