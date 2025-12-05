"""
Workflow Engine
===============

Defines and executes security assessment workflows.
"""

import asyncio
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import yaml
from pathlib import Path

from agent.utils.logger import get_logger


class WorkflowState(Enum):
    """Workflow execution states."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepState(Enum):
    """Step execution states."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class WorkflowStep:
    """Single step in a workflow."""
    id: str
    name: str
    tool: str
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)
    condition: Optional[str] = None
    on_failure: str = "continue"  # continue, stop, skip_dependents
    timeout: int = 300
    retries: int = 0
    state: StepState = StepState.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


@dataclass
class WorkflowDefinition:
    """Workflow definition."""
    id: str
    name: str
    description: str
    version: str = "1.0"
    author: str = "RedTeamAgent"
    steps: List[WorkflowStep] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    timeout: int = 3600
    parallel: bool = False
    max_parallel: int = 5


class WorkflowEngine:
    """
    Executes security assessment workflows.
    
    Supports:
    - Sequential and parallel execution
    - Step dependencies
    - Conditional execution
    - Variable substitution
    - Error handling strategies
    """
    
    def __init__(self, tool_registry=None, executor=None):
        self.logger = get_logger("WorkflowEngine")
        self.tool_registry = tool_registry
        self.executor = executor
        self.workflows: Dict[str, WorkflowDefinition] = {}
        self.running_workflows: Dict[str, Dict[str, Any]] = {}
        
        # Load built-in workflows
        self._load_builtin_workflows()
        
    def _load_builtin_workflows(self):
        """Load built-in workflow definitions."""
        # Quick Scan workflow
        self.workflows["quick_scan"] = WorkflowDefinition(
            id="quick_scan",
            name="Quick Security Scan",
            description="Fast security assessment covering basic checks",
            steps=[
                WorkflowStep(
                    id="probe",
                    name="HTTP Probe",
                    tool="http_client",
                    action="probe",
                    params={"url": "{target}"}
                ),
                WorkflowStep(
                    id="tech_detect",
                    name="Technology Detection",
                    tool="tech_detect",
                    action="detect",
                    params={"target": "{target}"},
                    depends_on=["probe"]
                ),
                WorkflowStep(
                    id="headers",
                    name="Security Headers",
                    tool="header_scanner",
                    action="scan",
                    params={"url": "{target}"},
                    depends_on=["probe"]
                ),
                WorkflowStep(
                    id="ssl",
                    name="SSL Analysis",
                    tool="ssl_scanner",
                    action="scan",
                    params={"target": "{target}"},
                    depends_on=["probe"]
                ),
            ],
            tags=["quick", "basic", "recon"]
        )
        
        # Full Scan workflow
        self.workflows["full_scan"] = WorkflowDefinition(
            id="full_scan",
            name="Full Security Assessment",
            description="Comprehensive security assessment",
            steps=[
                WorkflowStep(
                    id="probe",
                    name="HTTP Probe",
                    tool="http_client",
                    action="probe",
                    params={"url": "{target}"}
                ),
                WorkflowStep(
                    id="tech_detect",
                    name="Technology Detection",
                    tool="tech_detect",
                    action="detect",
                    params={"target": "{target}"},
                    depends_on=["probe"]
                ),
                WorkflowStep(
                    id="headers",
                    name="Security Headers",
                    tool="header_scanner",
                    action="scan",
                    params={"url": "{target}"},
                    depends_on=["probe"]
                ),
                WorkflowStep(
                    id="ssl",
                    name="SSL Analysis",
                    tool="ssl_scanner",
                    action="scan",
                    params={"target": "{target}"},
                    depends_on=["probe"]
                ),
                WorkflowStep(
                    id="csp",
                    name="CSP Analysis",
                    tool="csp_analyzer",
                    action="analyze",
                    params={"target": "{target}"},
                    depends_on=["headers"]
                ),
                WorkflowStep(
                    id="dirs",
                    name="Directory Discovery",
                    tool="gobuster",
                    action="dir",
                    params={"url": "{target}"},
                    depends_on=["probe"],
                    timeout=600
                ),
                WorkflowStep(
                    id="nuclei",
                    name="Vulnerability Scan",
                    tool="nuclei",
                    action="scan",
                    params={"target": "{target}"},
                    depends_on=["probe"],
                    timeout=900
                ),
            ],
            tags=["full", "comprehensive"],
            timeout=7200
        )
        
        # Magecart Detection workflow
        self.workflows["magecart_scan"] = WorkflowDefinition(
            id="magecart_scan",
            name="Magecart/Skimmer Detection",
            description="Specialized scan for payment card skimmers",
            steps=[
                WorkflowStep(
                    id="probe",
                    name="HTTP Probe",
                    tool="http_client",
                    action="probe",
                    params={"url": "{target}"}
                ),
                WorkflowStep(
                    id="tech_detect",
                    name="Technology Detection",
                    tool="tech_detect",
                    action="detect",
                    params={"target": "{target}"},
                    depends_on=["probe"]
                ),
                WorkflowStep(
                    id="headers",
                    name="Security Headers",
                    tool="header_scanner",
                    action="scan",
                    params={"url": "{target}"},
                    depends_on=["probe"]
                ),
                WorkflowStep(
                    id="csp",
                    name="CSP Analysis",
                    tool="csp_analyzer",
                    action="analyze",
                    params={"target": "{target}"},
                    depends_on=["headers"]
                ),
                WorkflowStep(
                    id="csp_bypass",
                    name="CSP Bypass Check",
                    tool="csp_analyzer",
                    action="check_bypass",
                    params={"target": "{target}"},
                    depends_on=["csp"]
                ),
                WorkflowStep(
                    id="js_enum",
                    name="JavaScript Enumeration",
                    tool="js_analyzer",
                    action="enumerate",
                    params={"target": "{target}"},
                    depends_on=["probe"]
                ),
                WorkflowStep(
                    id="skimmer_scan",
                    name="Skimmer Detection",
                    tool="skimmer_detect",
                    action="scan_page",
                    params={"target": "{target}"},
                    depends_on=["js_enum"]
                ),
                WorkflowStep(
                    id="checkout_analysis",
                    name="Checkout Page Analysis",
                    tool="skimmer_detect",
                    action="analyze_checkout",
                    params={"target": "{target}/checkout"},
                    depends_on=["skimmer_scan"],
                    condition="has_checkout_page"
                ),
                WorkflowStep(
                    id="js_analyze",
                    name="JavaScript Deep Analysis",
                    tool="js_analyzer",
                    action="detect_skimmer",
                    params={"target": "{target}"},
                    depends_on=["js_enum"],
                    condition="suspicious_scripts_found"
                ),
            ],
            tags=["magecart", "skimmer", "ecommerce", "payment"],
            timeout=3600
        )
        
        # E-commerce Security workflow
        self.workflows["ecommerce_scan"] = WorkflowDefinition(
            id="ecommerce_scan",
            name="E-commerce Security Assessment",
            description="Full security assessment for e-commerce sites",
            steps=[
                WorkflowStep(
                    id="probe",
                    name="HTTP Probe",
                    tool="http_client",
                    action="probe",
                    params={"url": "{target}"}
                ),
                WorkflowStep(
                    id="tech_detect",
                    name="CMS/Platform Detection",
                    tool="tech_detect",
                    action="identify_cms",
                    params={"target": "{target}"},
                    depends_on=["probe"]
                ),
                WorkflowStep(
                    id="headers",
                    name="Security Headers",
                    tool="header_scanner",
                    action="scan",
                    params={"url": "{target}"},
                    depends_on=["probe"]
                ),
                WorkflowStep(
                    id="ssl",
                    name="SSL/TLS Analysis",
                    tool="ssl_scanner",
                    action="full_scan",
                    params={"target": "{target}"},
                    depends_on=["probe"]
                ),
                WorkflowStep(
                    id="csp",
                    name="CSP Analysis",
                    tool="csp_analyzer",
                    action="analyze",
                    params={"target": "{target}"},
                    depends_on=["headers"]
                ),
                WorkflowStep(
                    id="payment_discovery",
                    name="Payment Page Discovery",
                    tool="gobuster",
                    action="dir",
                    params={
                        "url": "{target}",
                        "wordlist": "payment_paths.txt"
                    },
                    depends_on=["probe"],
                    timeout=300
                ),
                WorkflowStep(
                    id="js_enum",
                    name="JavaScript Enumeration",
                    tool="js_analyzer",
                    action="enumerate",
                    params={"target": "{target}"},
                    depends_on=["probe"]
                ),
                WorkflowStep(
                    id="skimmer_scan",
                    name="Skimmer Detection",
                    tool="skimmer_detect",
                    action="scan_page",
                    params={"target": "{target}"},
                    depends_on=["js_enum"]
                ),
                WorkflowStep(
                    id="nuclei_ecommerce",
                    name="E-commerce Vuln Scan",
                    tool="nuclei",
                    action="scan",
                    params={
                        "target": "{target}",
                        "tags": "ecommerce,magento,shopify,woocommerce"
                    },
                    depends_on=["tech_detect"],
                    timeout=900
                ),
            ],
            tags=["ecommerce", "payment", "magecart", "full"],
            timeout=7200
        )
        
        # Recon Only workflow
        self.workflows["recon_only"] = WorkflowDefinition(
            id="recon_only",
            name="Reconnaissance Only",
            description="Non-intrusive reconnaissance scan",
            steps=[
                WorkflowStep(
                    id="probe",
                    name="HTTP Probe",
                    tool="http_client",
                    action="probe",
                    params={"url": "{target}"}
                ),
                WorkflowStep(
                    id="dns",
                    name="DNS Lookup",
                    tool="dns",
                    action="lookup",
                    params={"domain": "{domain}"}
                ),
                WorkflowStep(
                    id="whois",
                    name="WHOIS Lookup",
                    tool="whois",
                    action="lookup",
                    params={"domain": "{domain}"}
                ),
                WorkflowStep(
                    id="tech_detect",
                    name="Technology Detection",
                    tool="tech_detect",
                    action="detect",
                    params={"target": "{target}"},
                    depends_on=["probe"]
                ),
                WorkflowStep(
                    id="headers",
                    name="Header Analysis",
                    tool="header_scanner",
                    action="scan",
                    params={"url": "{target}"},
                    depends_on=["probe"]
                ),
            ],
            tags=["recon", "passive", "non-intrusive"]
        )
        
    def load_workflow(self, path: str) -> WorkflowDefinition:
        """Load workflow from YAML file."""
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
            
        steps = [
            WorkflowStep(
                id=s["id"],
                name=s.get("name", s["id"]),
                tool=s["tool"],
                action=s["action"],
                params=s.get("params", {}),
                depends_on=s.get("depends_on", []),
                condition=s.get("condition"),
                on_failure=s.get("on_failure", "continue"),
                timeout=s.get("timeout", 300),
                retries=s.get("retries", 0)
            )
            for s in data.get("steps", [])
        ]
        
        workflow = WorkflowDefinition(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            version=data.get("version", "1.0"),
            author=data.get("author", "custom"),
            steps=steps,
            variables=data.get("variables", {}),
            tags=data.get("tags", []),
            timeout=data.get("timeout", 3600),
            parallel=data.get("parallel", False),
            max_parallel=data.get("max_parallel", 5)
        )
        
        self.workflows[workflow.id] = workflow
        return workflow
        
    def get_workflow(self, workflow_id: str) -> Optional[WorkflowDefinition]:
        """Get workflow by ID."""
        return self.workflows.get(workflow_id)
        
    def list_workflows(self) -> List[Dict[str, Any]]:
        """List all available workflows."""
        return [
            {
                "id": w.id,
                "name": w.name,
                "description": w.description,
                "steps": len(w.steps),
                "tags": w.tags
            }
            for w in self.workflows.values()
        ]
        
    async def execute(
        self,
        workflow_id: str,
        variables: Dict[str, Any],
        callbacks: Optional[Dict[str, Callable]] = None
    ) -> Dict[str, Any]:
        """
        Execute a workflow.
        
        Args:
            workflow_id: Workflow to execute
            variables: Variable substitutions (e.g., {target})
            callbacks: Optional callbacks for events
            
        Returns:
            Execution result with all step results
        """
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            raise ValueError(f"Workflow not found: {workflow_id}")
            
        self.logger.info(f"Starting workflow: {workflow.name}")
        
        execution_id = f"{workflow_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        result = {
            "execution_id": execution_id,
            "workflow_id": workflow_id,
            "workflow_name": workflow.name,
            "state": WorkflowState.RUNNING.value,
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "variables": variables,
            "steps": {},
            "findings": [],
            "errors": []
        }
        
        self.running_workflows[execution_id] = result
        
        try:
            # Execute steps
            completed_steps = set()
            
            while True:
                # Find ready steps (dependencies satisfied)
                ready_steps = [
                    step for step in workflow.steps
                    if step.id not in completed_steps
                    and all(dep in completed_steps for dep in step.depends_on)
                    and step.state == StepState.PENDING
                ]
                
                if not ready_steps:
                    # Check if all done or stuck
                    pending = [s for s in workflow.steps if s.state == StepState.PENDING]
                    if not pending:
                        break
                    else:
                        # Stuck - dependency failure
                        for s in pending:
                            s.state = StepState.SKIPPED
                            s.error = "Dependencies not met"
                        break
                        
                # Execute ready steps
                if workflow.parallel:
                    # Parallel execution
                    tasks = [
                        self._execute_step(step, variables, result)
                        for step in ready_steps[:workflow.max_parallel]
                    ]
                    await asyncio.gather(*tasks)
                else:
                    # Sequential execution
                    for step in ready_steps:
                        await self._execute_step(step, variables, result)
                        
                # Update completed
                for step in workflow.steps:
                    if step.state in [StepState.COMPLETED, StepState.FAILED, StepState.SKIPPED]:
                        completed_steps.add(step.id)
                        
                # Call progress callback
                if callbacks and "on_progress" in callbacks:
                    progress = len(completed_steps) / len(workflow.steps)
                    callbacks["on_progress"](progress, result)
                    
            # Determine final state
            failed_steps = [s for s in workflow.steps if s.state == StepState.FAILED]
            if failed_steps:
                result["state"] = WorkflowState.COMPLETED.value  # Completed with errors
            else:
                result["state"] = WorkflowState.COMPLETED.value
                
        except Exception as e:
            self.logger.error(f"Workflow execution error: {e}")
            result["state"] = WorkflowState.FAILED.value
            result["errors"].append(str(e))
            
        finally:
            result["end_time"] = datetime.now().isoformat()
            
            # Call completion callback
            if callbacks and "on_complete" in callbacks:
                callbacks["on_complete"](result)
                
        return result
        
    async def _execute_step(
        self,
        step: WorkflowStep,
        variables: Dict[str, Any],
        result: Dict[str, Any]
    ) -> None:
        """Execute a single workflow step."""
        step.state = StepState.RUNNING
        step.start_time = datetime.now()
        
        self.logger.info(f"Executing step: {step.name} ({step.tool}.{step.action})")
        
        try:
            # Substitute variables in params
            params = self._substitute_variables(step.params, variables)
            
            # Check condition
            if step.condition:
                if not self._evaluate_condition(step.condition, result):
                    step.state = StepState.SKIPPED
                    step.error = f"Condition not met: {step.condition}"
                    self.logger.info(f"Skipping step {step.name}: condition not met")
                    return
                    
            # Execute via executor or directly
            if self.executor:
                step_result = await self.executor.execute_tool(
                    step.tool,
                    step.action,
                    params,
                    timeout=step.timeout
                )
            else:
                # Simulated execution for testing
                step_result = {
                    "status": "success",
                    "output": f"Simulated output for {step.tool}.{step.action}",
                    "findings": []
                }
                await asyncio.sleep(0.1)  # Simulate work
                
            step.result = step_result
            step.state = StepState.COMPLETED
            
            # Extract findings
            if step_result.get("findings"):
                result["findings"].extend(step_result["findings"])
                
        except Exception as e:
            self.logger.error(f"Step {step.name} failed: {e}")
            step.state = StepState.FAILED
            step.error = str(e)
            result["errors"].append(f"Step {step.name}: {e}")
            
        finally:
            step.end_time = datetime.now()
            
            # Record step result
            result["steps"][step.id] = {
                "name": step.name,
                "tool": step.tool,
                "action": step.action,
                "state": step.state.value,
                "start_time": step.start_time.isoformat() if step.start_time else None,
                "end_time": step.end_time.isoformat() if step.end_time else None,
                "duration": (step.end_time - step.start_time).total_seconds() if step.start_time and step.end_time else None,
                "result": step.result,
                "error": step.error
            }
            
    def _substitute_variables(
        self,
        params: Dict[str, Any],
        variables: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Substitute {variable} placeholders in params."""
        result = {}
        
        for key, value in params.items():
            if isinstance(value, str):
                for var_name, var_value in variables.items():
                    value = value.replace(f"{{{var_name}}}", str(var_value))
                result[key] = value
            elif isinstance(value, dict):
                result[key] = self._substitute_variables(value, variables)
            else:
                result[key] = value
                
        return result
        
    def _evaluate_condition(
        self,
        condition: str,
        result: Dict[str, Any]
    ) -> bool:
        """Evaluate a condition based on current results."""
        # Simple condition evaluation
        # Format: "step_id.field == value" or "has_something"
        
        if condition.startswith("has_"):
            # Check for presence of something in findings
            key = condition[4:]  # Remove "has_"
            return any(
                key in str(f).lower()
                for f in result.get("findings", [])
            )
            
        if "." in condition:
            parts = condition.split(".")
            step_id = parts[0]
            
            step_result = result.get("steps", {}).get(step_id)
            if not step_result:
                return False
                
            # Navigate to field
            value = step_result
            for part in parts[1:]:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    return False
                    
            return bool(value)
            
        return True
        
    async def cancel(self, execution_id: str) -> bool:
        """Cancel a running workflow."""
        if execution_id in self.running_workflows:
            self.running_workflows[execution_id]["state"] = WorkflowState.CANCELLED.value
            return True
        return False
