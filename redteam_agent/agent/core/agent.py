"""
Red Team AI Agent - Main Agent Class
=====================================

The core agent that orchestrates the entire security assessment workflow.
Implements the THINK -> ACTION -> OBSERVE loop with Gate Zero security.

Usage:
    agent = RedTeamAgent(config_path="configs/agent_config.yaml")
    result = agent.run("Scan example.com for Magecart vulnerabilities")
"""

import time
import uuid
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from pathlib import Path

from agent.core.planner import Planner
from agent.core.executor import Executor
from agent.core.observer import Observer
from agent.core.memory import Memory
from agent.llm.provider import LLMProvider
from agent.tools.registry import ToolRegistry
from agent.security.gate_zero import GateZero
from agent.utils.logger import get_logger
from agent.utils.config import load_config


class AgentState(Enum):
    """Agent execution states."""
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    OBSERVING = "observing"
    REPORTING = "reporting"
    COMPLETED = "completed"
    ERROR = "error"
    STOPPED = "stopped"


@dataclass
class AgentConfig:
    """Configuration for the Red Team Agent."""
    max_iterations: int = 10
    timeout: int = 3600
    model_path: Optional[str] = None
    api_url: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 4096
    enable_gate_zero: bool = True
    verbose: bool = False
    log_level: str = "INFO"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "max_iterations": self.max_iterations,
            "timeout": self.timeout,
            "model_path": self.model_path,
            "api_url": self.api_url,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "enable_gate_zero": self.enable_gate_zero,
            "verbose": self.verbose,
            "log_level": self.log_level
        }


@dataclass
class TaskResult:
    """Result of a completed task."""
    task_id: str
    task: str
    status: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    iterations: int
    findings: List[Dict[str, Any]] = field(default_factory=list)
    report: Optional[str] = None
    error: Optional[str] = None
    steps_executed: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class StepResult:
    """Result of a single execution step."""
    step_id: int
    tool: str
    action: str
    status: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    output: Optional[Dict[str, Any]] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None


class RedTeamAgent:
    """
    Main Red Team AI Agent class.
    
    This agent combines a fine-tuned LLM with security tools to perform
    automated security assessments. It follows a THINK -> ACTION -> OBSERVE
    loop until the task is completed or max iterations reached.
    
    Attributes:
        config: Agent configuration dictionary
        llm: LLM provider for reasoning
        tools: Registry of available security tools
        memory: Context and conversation memory
        gate: Gate Zero security authorization layer
        planner: Task planning module
        executor: Tool execution module
        observer: Result observation module
        
    Example:
        >>> agent = RedTeamAgent()
        >>> result = agent.run(
        ...     task="Scan https://example.com for XSS vulnerabilities",
        ...     engagement_id="ENG-2024-001"
        ... )
        >>> print(result.findings)
    """
    
    def __init__(
        self,
        config_path: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the Red Team Agent.
        
        Args:
            config_path: Path to YAML configuration file
            config: Configuration dictionary (overrides config_path)
        """
        self.logger = get_logger("RedTeamAgent")
        self.logger.info("Initializing Red Team AI Agent...")
        
        # Load configuration
        if config:
            self.config = config
        elif config_path:
            self.config = load_config(config_path)
        else:
            self.config = load_config()  # Load default config
            
        # Initialize components
        self._init_components()
        
        # Agent state
        self.state = AgentState.IDLE
        self.current_task_id: Optional[str] = None
        self._stop_requested = False
        
        self.logger.info("Red Team AI Agent initialized successfully")
        
    def _init_components(self) -> None:
        """Initialize all agent components."""
        agent_config = self.config.get("agent", {})
        
        # Initialize LLM provider
        llm_config = agent_config.get("llm", {})
        self.llm = LLMProvider(
            provider=llm_config.get("provider", "local"),
            model_path=llm_config.get("model_path"),
            api_url=llm_config.get("api_url"),
            max_tokens=llm_config.get("max_tokens", 4096),
            temperature=llm_config.get("temperature", 0.7)
        )
        
        # Initialize tool registry
        self.tools = ToolRegistry()
        self.tools.discover_tools()
        
        # Initialize memory
        memory_config = agent_config.get("memory", {})
        self.memory = Memory(
            max_context_tokens=memory_config.get("max_context_tokens", 8000),
            summarize_threshold=memory_config.get("summarize_threshold", 6000)
        )
        
        # Initialize Gate Zero security
        security_config = agent_config.get("security", {})
        self.gate = GateZero(
            require_authorization=security_config.get("require_authorization", True),
            engagement_file=security_config.get("engagement_file"),
            audit_log_path=security_config.get("audit_log_path", "./logs/audit/")
        )
        
        # Initialize core modules
        self.planner = Planner(llm=self.llm, tools=self.tools, memory=self.memory)
        self.executor = Executor(tools=self.tools, gate=self.gate)
        self.observer = Observer(llm=self.llm, memory=self.memory)
        
        # Settings
        self.max_iterations = agent_config.get("max_iterations", 20)
        self.task_timeout = agent_config.get("task_timeout", 600)
        self.verbose = agent_config.get("verbose", True)
        self.auto_report = agent_config.get("output", {}).get("auto_report", True)
        
    def run(
        self,
        task: str,
        engagement_id: Optional[str] = None,
        target: Optional[str] = None
    ) -> TaskResult:
        """
        Execute a security assessment task.
        
        This is the main entry point for running the agent. It will:
        1. Validate authorization via Gate Zero
        2. Create an execution plan
        3. Execute the THINK -> ACTION -> OBSERVE loop
        4. Generate a final report
        
        Args:
            task: Natural language description of the task
            engagement_id: Optional engagement/authorization ID
            target: Optional explicit target (extracted from task if not provided)
            
        Returns:
            TaskResult containing findings, report, and execution details
            
        Raises:
            AuthorizationError: If Gate Zero denies the request
            TimeoutError: If task exceeds timeout limit
        """
        task_id = str(uuid.uuid4())[:8]
        self.current_task_id = task_id
        start_time = datetime.now()
        
        self.logger.info(f"Starting task {task_id}: {task[:100]}...")
        self._print_banner(task)
        
        try:
            # Reset state
            self.state = AgentState.IDLE
            self.memory.clear()
            self._stop_requested = False
            findings = []
            steps_executed = []
            
            # Step 1: Gate Zero Authorization Check
            self.logger.info("Checking Gate Zero authorization...")
            if not self._check_authorization(task, engagement_id, target):
                raise PermissionError("Gate Zero denied the request")
            
            # Step 2: Planning
            self.state = AgentState.PLANNING
            self._print_status("PLANNING", "Creating execution plan...")
            
            plan = self.planner.create_plan(task)
            self.memory.add("plan", plan)
            
            if self.verbose:
                self._print_plan(plan)
            
            # Step 3: Execute THINK -> ACTION -> OBSERVE loop
            iteration = 0
            task_start = time.time()
            
            while iteration < self.max_iterations:
                # Check timeout
                if time.time() - task_start > self.task_timeout:
                    self.logger.warning("Task timeout reached")
                    break
                    
                # Check stop request
                if self._stop_requested:
                    self.logger.info("Stop requested by user")
                    self.state = AgentState.STOPPED
                    break
                
                iteration += 1
                self.logger.info(f"Iteration {iteration}/{self.max_iterations}")
                
                # THINK: Decide next action
                self.state = AgentState.PLANNING
                next_step = self.planner.decide_next_step(
                    task=task,
                    findings=findings,
                    steps_completed=steps_executed
                )
                
                if next_step is None or next_step.get("action") == "complete":
                    self.logger.info("Agent decided task is complete")
                    break
                
                # ACTION: Execute the step
                self.state = AgentState.EXECUTING
                self._print_status("EXECUTING", f"Step {iteration}: {next_step.get('tool', 'unknown')}")
                
                step_result = self._execute_step(next_step, iteration)
                steps_executed.append(step_result.__dict__)
                
                # OBSERVE: Analyze results
                self.state = AgentState.OBSERVING
                observation = self.observer.analyze(
                    step=next_step,
                    result=step_result,
                    context=self.memory.get_context()
                )
                
                # Extract findings
                if observation.get("findings"):
                    findings.extend(observation["findings"])
                    self._print_findings(observation["findings"])
                
                # Update memory
                self.memory.add(f"step_{iteration}", {
                    "step": next_step,
                    "result": step_result.__dict__,
                    "observation": observation
                })
                
                # Check if observer suggests completion
                if observation.get("task_complete"):
                    self.logger.info("Observer determined task is complete")
                    break
            
            # Step 4: Generate Report
            self.state = AgentState.REPORTING
            report = None
            if self.auto_report:
                self._print_status("REPORTING", "Generating final report...")
                report = self._generate_report(task, findings, steps_executed)
            
            # Complete
            self.state = AgentState.COMPLETED
            end_time = datetime.now()
            
            result = TaskResult(
                task_id=task_id,
                task=task,
                status="completed",
                start_time=start_time,
                end_time=end_time,
                duration_seconds=(end_time - start_time).total_seconds(),
                iterations=iteration,
                findings=findings,
                report=report,
                steps_executed=steps_executed
            )
            
            self._print_summary(result)
            self.gate.log_action("task_complete", {"task_id": task_id, "findings_count": len(findings)})
            
            return result
            
        except Exception as e:
            self.state = AgentState.ERROR
            self.logger.error(f"Task failed: {e}")
            
            end_time = datetime.now()
            return TaskResult(
                task_id=task_id,
                task=task,
                status="error",
                start_time=start_time,
                end_time=end_time,
                duration_seconds=(end_time - start_time).total_seconds(),
                iterations=0,
                error=str(e),
                steps_executed=[]
            )
        finally:
            self.current_task_id = None
            
    def _check_authorization(
        self,
        task: str,
        engagement_id: Optional[str],
        target: Optional[str]
    ) -> bool:
        """Check Gate Zero authorization."""
        # Extract target from task if not provided
        if not target:
            target = self._extract_target(task)
            
        return self.gate.full_check(
            engagement_id=engagement_id,
            target=target,
            action_type="scan"
        )
        
    def _extract_target(self, task: str) -> Optional[str]:
        """Extract target URL/domain from task description."""
        import re
        # Simple URL extraction
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        match = re.search(url_pattern, task)
        if match:
            return match.group(0)
        # Domain pattern
        domain_pattern = r'\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        match = re.search(domain_pattern, task)
        if match:
            return match.group(0)
        return None
        
    def _execute_step(self, step: Dict[str, Any], step_id: int) -> StepResult:
        """Execute a single step."""
        start_time = datetime.now()
        
        try:
            result = self.executor.execute(
                tool_name=step.get("tool"),
                action=step.get("action"),
                params=step.get("params", {})
            )
            
            end_time = datetime.now()
            
            return StepResult(
                step_id=step_id,
                tool=step.get("tool", "unknown"),
                action=step.get("action", "unknown"),
                status="success" if result.get("success") else "failed",
                start_time=start_time,
                end_time=end_time,
                duration_seconds=(end_time - start_time).total_seconds(),
                output=result.get("output"),
                findings=result.get("findings", []),
                error=result.get("error")
            )
            
        except Exception as e:
            end_time = datetime.now()
            return StepResult(
                step_id=step_id,
                tool=step.get("tool", "unknown"),
                action=step.get("action", "unknown"),
                status="error",
                start_time=start_time,
                end_time=end_time,
                duration_seconds=(end_time - start_time).total_seconds(),
                error=str(e)
            )
            
    def _generate_report(
        self,
        task: str,
        findings: List[Dict[str, Any]],
        steps: List[Dict[str, Any]]
    ) -> str:
        """Generate final report using LLM."""
        report_prompt = f"""Generate a security assessment report.

Task: {task}

Findings ({len(findings)} total):
{self._format_findings(findings)}

Steps Executed ({len(steps)} total):
{self._format_steps(steps)}

Generate a professional security report in Markdown format including:
1. Executive Summary
2. Scope
3. Findings (sorted by severity)
4. Recommendations
5. Conclusion
"""
        
        response = self.llm.generate(report_prompt)
        return response
        
    def _format_findings(self, findings: List[Dict[str, Any]]) -> str:
        """Format findings for report prompt."""
        if not findings:
            return "No findings"
        
        lines = []
        for i, f in enumerate(findings, 1):
            lines.append(f"{i}. [{f.get('severity', 'INFO')}] {f.get('type', 'Unknown')}")
            lines.append(f"   Description: {f.get('description', 'N/A')}")
            if f.get('evidence'):
                lines.append(f"   Evidence: {f.get('evidence')}")
        return "\n".join(lines)
        
    def _format_steps(self, steps: List[Dict[str, Any]]) -> str:
        """Format steps for report prompt."""
        lines = []
        for s in steps:
            status_icon = "✓" if s.get("status") == "success" else "✗"
            lines.append(f"{status_icon} {s.get('tool', 'unknown')}.{s.get('action', 'unknown')}")
        return "\n".join(lines)
        
    def stop(self) -> None:
        """Request agent to stop current task."""
        self._stop_requested = True
        self.logger.info("Stop requested")
        
    def get_state(self) -> Dict[str, Any]:
        """Get current agent state."""
        return {
            "state": self.state.value,
            "task_id": self.current_task_id,
            "memory_size": self.memory.get_token_count(),
            "tools_available": len(self.tools.list_all())
        }
        
    # ===== Pretty Print Methods =====
    
    def _print_banner(self, task: str) -> None:
        """Print task banner."""
        if not self.verbose:
            return
        print("\n" + "=" * 60)
        print("  🤖 RED TEAM AI AGENT")
        print("=" * 60)
        print(f"\n📋 Task: {task[:80]}{'...' if len(task) > 80 else ''}\n")
        
    def _print_status(self, stage: str, message: str) -> None:
        """Print status update."""
        if not self.verbose:
            return
        icons = {
            "PLANNING": "🧠",
            "EXECUTING": "⚡",
            "OBSERVING": "👁️",
            "REPORTING": "📝"
        }
        icon = icons.get(stage, "🔄")
        print(f"\n[{icon} {stage}] {message}")
        
    def _print_plan(self, plan: Dict[str, Any]) -> None:
        """Print execution plan."""
        if not self.verbose:
            return
        print("\n📋 Execution Plan:")
        for step in plan.get("steps", []):
            print(f"  Step {step.get('id', '?')}: {step.get('tool', '?')}.{step.get('action', '?')}")
            
    def _print_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Print new findings."""
        if not self.verbose or not findings:
            return
        severity_icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵"
        }
        for f in findings:
            icon = severity_icons.get(f.get("severity", "info").lower(), "⚪")
            print(f"  {icon} [{f.get('severity', 'INFO')}] {f.get('type', 'Finding')}: {f.get('description', '')[:60]}")
            
    def _print_summary(self, result: TaskResult) -> None:
        """Print task summary."""
        if not self.verbose:
            return
        print("\n" + "=" * 60)
        print("  ✅ TASK COMPLETED")
        print("=" * 60)
        print(f"\n📊 Summary:")
        print(f"   Duration: {result.duration_seconds:.1f}s")
        print(f"   Iterations: {result.iterations}")
        print(f"   Findings: {len(result.findings)}")
        
        # Count by severity
        severity_counts = {}
        for f in result.findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
        if severity_counts:
            print("   By Severity:")
            for sev, count in sorted(severity_counts.items()):
                print(f"     - {sev.capitalize()}: {count}")
        print()
