"""
Planner Module
==============

Creates and manages execution plans for security assessment tasks.
Uses LLM to break down tasks into actionable steps.
"""

from typing import Optional, Dict, Any, List
from dataclasses import dataclass

from agent.utils.logger import get_logger


@dataclass
class PlanStep:
    """A single step in the execution plan."""
    id: int
    tool: str
    action: str
    params: Dict[str, Any]
    description: str
    depends_on: Optional[int] = None
    priority: int = 5
    estimated_duration: int = 30


class Planner:
    """
    Task planning module for the Red Team Agent.
    
    Responsible for:
    - Analyzing task requirements
    - Breaking down into subtasks
    - Selecting appropriate tools
    - Ordering steps logically
    - Dynamic replanning based on findings
    
    Attributes:
        llm: LLM provider for reasoning
        tools: Tool registry
        memory: Agent memory
    """
    
    def __init__(self, llm, tools, memory):
        """
        Initialize the Planner.
        
        Args:
            llm: LLM provider instance
            tools: ToolRegistry instance
            memory: Memory instance
        """
        self.llm = llm
        self.tools = tools
        self.memory = memory
        self.logger = get_logger("Planner")
        
    def create_plan(self, task: str) -> Dict[str, Any]:
        """
        Create an execution plan for a task.
        
        Args:
            task: Natural language task description
            
        Returns:
            Plan dictionary with steps
        """
        self.logger.info(f"Creating plan for: {task[:50]}...")
        
        # Get available tools schema
        tools_schema = self.tools.get_schemas()
        
        # Create planning prompt
        prompt = self._create_planning_prompt(task, tools_schema)
        
        # Get LLM response
        response = self.llm.generate(prompt)
        
        # Parse plan from response
        plan = self._parse_plan(response, task)
        
        self.logger.info(f"Created plan with {len(plan.get('steps', []))} steps")
        return plan
        
    def decide_next_step(
        self,
        task: str,
        findings: List[Dict[str, Any]],
        steps_completed: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Decide the next step based on current progress.
        
        This enables dynamic replanning - the agent can adjust
        its approach based on what it discovers.
        
        Args:
            task: Original task description
            findings: Findings discovered so far
            steps_completed: Steps already executed
            
        Returns:
            Next step to execute, or None if task is complete
        """
        # Check if we should complete
        if self._should_complete(task, findings, steps_completed):
            return {"action": "complete"}
            
        # Get context
        context = self.memory.get_context()
        tools_schema = self.tools.get_schemas()
        
        # Create decision prompt
        prompt = self._create_decision_prompt(
            task=task,
            findings=findings,
            steps_completed=steps_completed,
            tools_schema=tools_schema,
            context=context
        )
        
        # Get LLM decision
        response = self.llm.generate(prompt)
        
        # Parse next step
        next_step = self._parse_next_step(response)
        
        return next_step
        
    def _create_planning_prompt(self, task: str, tools_schema: str) -> str:
        """Create the initial planning prompt."""
        return f"""You are a security assessment planner. Create an execution plan for the following task.

TASK: {task}

AVAILABLE TOOLS:
{tools_schema}

Create a step-by-step plan. For each step, specify:
- tool: The tool to use
- action: The specific action
- params: Parameters for the tool
- description: What this step accomplishes

Output your plan in this format:
<plan>
<step id="1" tool="TOOL_NAME" action="ACTION_NAME">
<params>{{"param1": "value1"}}</params>
<description>What this step does</description>
</step>
...
</plan>

Important:
- Start with reconnaissance to understand the target
- Check security headers and configurations
- Analyze JavaScript and external resources
- Look for specific vulnerabilities mentioned in the task
- End with generating findings

Create the plan now:"""

    def _create_decision_prompt(
        self,
        task: str,
        findings: List[Dict[str, Any]],
        steps_completed: List[Dict[str, Any]],
        tools_schema: str,
        context: str
    ) -> str:
        """Create prompt for deciding next step."""
        completed_summary = self._summarize_completed_steps(steps_completed)
        findings_summary = self._summarize_findings(findings)
        
        return f"""You are a security assessment agent. Decide the next action.

ORIGINAL TASK: {task}

COMPLETED STEPS ({len(steps_completed)}):
{completed_summary}

FINDINGS SO FAR ({len(findings)}):
{findings_summary}

AVAILABLE TOOLS:
{tools_schema}

Based on the progress so far, decide:
1. What should be the next step? OR
2. Is the task complete?

If the task is complete, output:
<action>complete</action>

If there's a next step, output:
<tool_call>
<tool>TOOL_NAME</tool>
<action>ACTION_NAME</action>
<params>{{"param": "value"}}</params>
<reason>Why this step is needed</reason>
</tool_call>

Your decision:"""

    def _parse_plan(self, response: str, task: str) -> Dict[str, Any]:
        """Parse LLM response into structured plan."""
        import re
        
        plan = {
            "task": task,
            "steps": []
        }
        
        # Try to parse structured format
        step_pattern = r'<step\s+id="(\d+)"\s+tool="([^"]+)"\s+action="([^"]+)"[^>]*>.*?<params>(.*?)</params>.*?<description>(.*?)</description>.*?</step>'
        matches = re.findall(step_pattern, response, re.DOTALL)
        
        if matches:
            for match in matches:
                step_id, tool, action, params_str, description = match
                try:
                    import json
                    params = json.loads(params_str.strip())
                except:
                    params = {}
                    
                plan["steps"].append({
                    "id": int(step_id),
                    "tool": tool.strip(),
                    "action": action.strip(),
                    "params": params,
                    "description": description.strip()
                })
        else:
            # Fallback: Create default plan based on task
            plan = self._create_default_plan(task)
            
        return plan
        
    def _parse_next_step(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse next step from LLM response."""
        import re
        
        # Check for complete action
        if "<action>complete</action>" in response.lower():
            return {"action": "complete"}
            
        # Parse tool call
        tool_match = re.search(r'<tool>([^<]+)</tool>', response)
        action_match = re.search(r'<action>([^<]+)</action>', response)
        params_match = re.search(r'<params>([^<]+)</params>', response, re.DOTALL)
        reason_match = re.search(r'<reason>([^<]+)</reason>', response, re.DOTALL)
        
        if tool_match and action_match:
            params = {}
            if params_match:
                try:
                    import json
                    params = json.loads(params_match.group(1).strip())
                except:
                    pass
                    
            return {
                "tool": tool_match.group(1).strip(),
                "action": action_match.group(1).strip(),
                "params": params,
                "reason": reason_match.group(1).strip() if reason_match else ""
            }
            
        # Fallback: Try to extract from natural language
        return self._extract_step_from_text(response)
        
    def _extract_step_from_text(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract step info from natural language response."""
        # Get list of tools
        available_tools = self.tools.list_all()
        
        text_lower = text.lower()
        
        # Find mentioned tool
        for tool_name in available_tools:
            if tool_name.lower() in text_lower:
                return {
                    "tool": tool_name,
                    "action": "run",
                    "params": {},
                    "reason": "Extracted from response"
                }
                
        return None
        
    def _should_complete(
        self,
        task: str,
        findings: List[Dict[str, Any]],
        steps_completed: List[Dict[str, Any]]
    ) -> bool:
        """Determine if task should be marked complete."""
        # Complete if we have findings and executed several steps
        if len(findings) > 0 and len(steps_completed) >= 3:
            # Check if recent steps are failing
            recent_failures = sum(
                1 for s in steps_completed[-3:] 
                if s.get("status") in ["failed", "error"]
            )
            if recent_failures >= 2:
                return True
                
        # Complete if we've done many steps without new findings
        if len(steps_completed) >= 10:
            return True
            
        return False
        
    def _summarize_completed_steps(self, steps: List[Dict[str, Any]]) -> str:
        """Create summary of completed steps."""
        if not steps:
            return "None"
            
        lines = []
        for s in steps[-5:]:  # Last 5 steps
            status_icon = "✓" if s.get("status") == "success" else "✗"
            lines.append(f"{status_icon} {s.get('tool', '?')}.{s.get('action', '?')}")
            
        return "\n".join(lines)
        
    def _summarize_findings(self, findings: List[Dict[str, Any]]) -> str:
        """Create summary of findings."""
        if not findings:
            return "None yet"
            
        lines = []
        for f in findings[:10]:  # First 10 findings
            lines.append(f"- [{f.get('severity', 'INFO')}] {f.get('type', 'Unknown')}")
            
        return "\n".join(lines)
        
    def _create_default_plan(self, task: str) -> Dict[str, Any]:
        """Create default plan when parsing fails."""
        # Extract target from task
        import re
        url_match = re.search(r'https?://[^\s]+', task)
        target = url_match.group(0) if url_match else "target"
        
        return {
            "task": task,
            "steps": [
                {
                    "id": 1,
                    "tool": "http_probe",
                    "action": "check",
                    "params": {"url": target},
                    "description": "Check if target is accessible"
                },
                {
                    "id": 2,
                    "tool": "header_scanner",
                    "action": "scan",
                    "params": {"url": target},
                    "description": "Scan security headers"
                },
                {
                    "id": 3,
                    "tool": "js_scanner",
                    "action": "enumerate",
                    "params": {"url": target},
                    "description": "Enumerate JavaScript files"
                },
                {
                    "id": 4,
                    "tool": "js_analyzer",
                    "action": "analyze",
                    "params": {"url": target},
                    "description": "Analyze JavaScript for suspicious patterns"
                }
            ]
        }
