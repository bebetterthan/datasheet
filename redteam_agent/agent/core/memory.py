"""
Memory Module
=============

Manages context and state for the agent during task execution.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
from collections import OrderedDict
import json

from agent.utils.logger import get_logger


class Memory:
    """
    Memory module for the Red Team Agent.
    
    Manages both short-term (per-task) and long-term (persistent) memory.
    Handles context window management for efficient LLM usage.
    
    Attributes:
        max_context_tokens: Maximum tokens to include in context
        summarize_threshold: Token count at which to summarize
        
    Memory Types:
        - Short-term: Current task, plan, steps, findings
        - Long-term: Previous scan results, known vulnerabilities (optional)
    """
    
    def __init__(
        self,
        max_context_tokens: int = 8000,
        summarize_threshold: int = 6000
    ):
        """
        Initialize Memory.
        
        Args:
            max_context_tokens: Maximum tokens in context window
            summarize_threshold: Threshold for automatic summarization
        """
        self.max_context_tokens = max_context_tokens
        self.summarize_threshold = summarize_threshold
        self.logger = get_logger("Memory")
        
        # Short-term memory (per task)
        self._short_term: OrderedDict = OrderedDict()
        
        # Long-term memory (persistent across tasks)
        self._long_term: Dict[str, Any] = {}
        
        # Metadata
        self._created_at = datetime.now()
        self._last_accessed = datetime.now()
        
    def add(self, key: str, value: Any, long_term: bool = False) -> None:
        """
        Store information in memory.
        
        Args:
            key: Unique key for the information
            value: Value to store
            long_term: If True, store in long-term memory
        """
        self._last_accessed = datetime.now()
        
        if long_term:
            self._long_term[key] = {
                "value": value,
                "timestamp": datetime.now().isoformat()
            }
        else:
            self._short_term[key] = {
                "value": value,
                "timestamp": datetime.now().isoformat()
            }
            
        # Check if we need to summarize
        if self.get_token_count() > self.summarize_threshold:
            self._auto_summarize()
            
    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieve information from memory.
        
        Args:
            key: Key to retrieve
            default: Default value if key not found
            
        Returns:
            Stored value or default
        """
        self._last_accessed = datetime.now()
        
        # Check short-term first
        if key in self._short_term:
            return self._short_term[key]["value"]
            
        # Then long-term
        if key in self._long_term:
            return self._long_term[key]["value"]
            
        return default
        
    def get_context(self, max_tokens: Optional[int] = None) -> str:
        """
        Get full context string for LLM prompt.
        
        Args:
            max_tokens: Maximum tokens to include (uses default if not specified)
            
        Returns:
            Formatted context string
        """
        max_tokens = max_tokens or self.max_context_tokens
        
        context_parts = []
        
        # Add task info
        task = self.get("task")
        if task:
            context_parts.append(f"TASK: {task}")
            
        # Add plan summary
        plan = self.get("plan")
        if plan:
            steps = plan.get("steps", [])
            context_parts.append(f"PLAN: {len(steps)} steps")
            
        # Add completed steps (most recent first)
        steps_keys = [k for k in self._short_term.keys() if k.startswith("step_")]
        if steps_keys:
            context_parts.append("\nCOMPLETED STEPS:")
            for key in sorted(steps_keys, reverse=True)[:5]:  # Last 5 steps
                step_data = self._short_term[key]["value"]
                step = step_data.get("step", {})
                result = step_data.get("result", {})
                context_parts.append(
                    f"  - {step.get('tool', '?')}.{step.get('action', '?')}: "
                    f"{result.get('status', 'unknown')}"
                )
                
        # Add findings summary
        findings = self._collect_findings()
        if findings:
            context_parts.append(f"\nFINDINGS ({len(findings)}):")
            for f in findings[:10]:  # Top 10 findings
                context_parts.append(
                    f"  - [{f.get('severity', 'INFO')}] {f.get('type', 'Unknown')}"
                )
                
        context = "\n".join(context_parts)
        
        # Truncate if too long (rough estimation: 4 chars per token)
        max_chars = max_tokens * 4
        if len(context) > max_chars:
            context = context[:max_chars] + "\n... (truncated)"
            
        return context
        
    def _collect_findings(self) -> List[Dict[str, Any]]:
        """Collect all findings from memory."""
        findings = []
        
        for key, data in self._short_term.items():
            if key.startswith("step_"):
                step_data = data["value"]
                observation = step_data.get("observation", {})
                step_findings = observation.get("findings", [])
                findings.extend(step_findings)
                
        return findings
        
    def get_findings(self) -> List[Dict[str, Any]]:
        """Get all findings collected during the task."""
        return self._collect_findings()
        
    def summarize(self) -> str:
        """
        Create a summary of current memory state.
        
        Returns:
            Summary string
        """
        summary_parts = []
        
        # Task
        task = self.get("task")
        if task:
            summary_parts.append(f"Task: {task[:100]}")
            
        # Steps count
        steps_count = len([k for k in self._short_term.keys() if k.startswith("step_")])
        summary_parts.append(f"Steps executed: {steps_count}")
        
        # Findings count
        findings = self._collect_findings()
        summary_parts.append(f"Findings: {len(findings)}")
        
        # Severity breakdown
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if severity_counts:
            summary_parts.append(f"By severity: {severity_counts}")
            
        return " | ".join(summary_parts)
        
    def clear(self) -> None:
        """Clear short-term memory (for new task)."""
        self._short_term.clear()
        self.logger.debug("Short-term memory cleared")
        
    def clear_all(self) -> None:
        """Clear all memory including long-term."""
        self._short_term.clear()
        self._long_term.clear()
        self.logger.debug("All memory cleared")
        
    def export(self) -> Dict[str, Any]:
        """
        Export memory for persistence.
        
        Returns:
            Dictionary containing all memory data
        """
        return {
            "short_term": dict(self._short_term),
            "long_term": dict(self._long_term),
            "metadata": {
                "created_at": self._created_at.isoformat(),
                "last_accessed": self._last_accessed.isoformat(),
                "token_count": self.get_token_count()
            }
        }
        
    def import_data(self, data: Dict[str, Any]) -> None:
        """
        Import memory from saved data.
        
        Args:
            data: Previously exported memory data
        """
        if "short_term" in data:
            self._short_term = OrderedDict(data["short_term"])
        if "long_term" in data:
            self._long_term = data["long_term"]
            
    def get_token_count(self) -> int:
        """
        Estimate token count of current memory.
        
        Returns:
            Estimated token count
        """
        # Rough estimation: serialize and count chars, divide by 4
        try:
            serialized = json.dumps({
                "short": dict(self._short_term),
                "long": self._long_term
            }, default=str)
            return len(serialized) // 4
        except:
            return 0
            
    def _auto_summarize(self) -> None:
        """Automatically summarize old content to save space."""
        self.logger.debug("Auto-summarizing memory...")
        
        # Keep only the most recent steps
        steps_keys = sorted([k for k in self._short_term.keys() if k.startswith("step_")])
        if len(steps_keys) > 10:
            # Remove oldest steps, keep last 10
            for key in steps_keys[:-10]:
                del self._short_term[key]
                
        self.logger.debug(f"Memory summarized. New token count: {self.get_token_count()}")
        
    def __len__(self) -> int:
        """Return number of items in short-term memory."""
        return len(self._short_term)
        
    def __contains__(self, key: str) -> bool:
        """Check if key exists in memory."""
        return key in self._short_term or key in self._long_term
