"""
Workflow Loader Module
=====================
Loads and validates workflow definitions from YAML files.
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
import yaml

from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class WorkflowParameter:
    """Represents a workflow input parameter."""
    
    name: str
    type: str
    required: bool = False
    default: Any = None
    description: str = ""
    validation: Optional[str] = None
    allowed_values: List[Any] = field(default_factory=list)
    sensitive: bool = False
    
    def validate(self, value: Any) -> bool:
        """Validate a parameter value."""
        if value is None:
            if self.required:
                return False
            return True
        
        # Type validation
        type_map = {
            "string": str,
            "integer": int,
            "boolean": bool,
            "float": float,
            "object": dict,
            "array": list
        }
        expected_type = type_map.get(self.type)
        if expected_type and not isinstance(value, expected_type):
            return False
        
        # Allowed values validation
        if self.allowed_values and value not in self.allowed_values:
            return False
        
        # Regex validation
        if self.validation and isinstance(value, str):
            if not re.match(self.validation, value):
                return False
        
        return True


@dataclass
class WorkflowStepDef:
    """Represents a workflow step definition."""
    
    id: str
    name: str
    tool: str
    params: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    condition: Optional[str] = None
    depends_on: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    continue_on_failure: bool = False
    timeout: int = 300
    retries: int = 0
    substeps: List['WorkflowStepDef'] = field(default_factory=list)


@dataclass
class WorkflowPhaseDef:
    """Represents a workflow phase (group of steps)."""
    
    id: str
    name: str
    description: str = ""
    steps: List[WorkflowStepDef] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)
    condition: Optional[str] = None
    parallel: bool = False


@dataclass
class WorkflowDefinition:
    """Complete workflow definition."""
    
    name: str
    description: str
    version: str = "1.0.0"
    estimated_duration: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    parameters: Dict[str, WorkflowParameter] = field(default_factory=dict)
    variables: Dict[str, Any] = field(default_factory=dict)
    steps: List[WorkflowStepDef] = field(default_factory=list)
    phases: List[WorkflowPhaseDef] = field(default_factory=list)
    output: Dict[str, Any] = field(default_factory=dict)
    report: Dict[str, Any] = field(default_factory=dict)
    
    def validate_parameters(self, params: Dict[str, Any]) -> Dict[str, str]:
        """
        Validate input parameters against definitions.
        
        Returns:
            Dict of parameter names to error messages
        """
        errors = {}
        
        for name, param_def in self.parameters.items():
            value = params.get(name, param_def.default)
            
            if param_def.required and value is None:
                errors[name] = f"Required parameter '{name}' is missing"
                continue
            
            if value is not None and not param_def.validate(value):
                errors[name] = f"Invalid value for parameter '{name}'"
        
        return errors
    
    def get_execution_order(self) -> List[str]:
        """
        Get step IDs in execution order based on dependencies.
        
        Returns:
            Ordered list of step IDs
        """
        # Build dependency graph
        all_steps = {}
        for step in self.steps:
            all_steps[step.id] = step
        for phase in self.phases:
            for step in phase.steps:
                all_steps[step.id] = step
        
        # Topological sort
        visited = set()
        order = []
        
        def visit(step_id: str):
            if step_id in visited:
                return
            visited.add(step_id)
            
            step = all_steps.get(step_id)
            if step:
                for dep in step.depends_on:
                    visit(dep)
                order.append(step_id)
        
        for step_id in all_steps:
            visit(step_id)
        
        return order


class WorkflowLoader:
    """
    Loads and manages workflow definitions.
    
    Supports loading workflows from:
    - Individual YAML files
    - Workflow directories
    - Embedded configurations
    """
    
    def __init__(self, workflows_dir: Optional[str] = None):
        """
        Initialize workflow loader.
        
        Args:
            workflows_dir: Directory containing workflow YAML files
        """
        self.workflows_dir = Path(workflows_dir) if workflows_dir else None
        self.workflows: Dict[str, WorkflowDefinition] = {}
        
        # Load workflows if directory provided
        if self.workflows_dir and self.workflows_dir.exists():
            self.load_all_workflows()
    
    def load_all_workflows(self):
        """Load all workflows from workflows directory."""
        if not self.workflows_dir:
            logger.warning("No workflows directory configured")
            return
        
        for yaml_file in self.workflows_dir.glob("*.yaml"):
            try:
                workflow = self.load_workflow_file(yaml_file)
                self.workflows[workflow.name] = workflow
                logger.info(f"Loaded workflow: {workflow.name}")
            except Exception as e:
                logger.error(f"Failed to load {yaml_file}: {e}")
    
    def load_workflow_file(self, filepath: Path) -> WorkflowDefinition:
        """
        Load a workflow from a YAML file.
        
        Args:
            filepath: Path to YAML workflow file
            
        Returns:
            WorkflowDefinition object
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        return self._parse_workflow(data)
    
    def load_workflow_string(self, yaml_string: str) -> WorkflowDefinition:
        """
        Load a workflow from a YAML string.
        
        Args:
            yaml_string: YAML workflow definition
            
        Returns:
            WorkflowDefinition object
        """
        data = yaml.safe_load(yaml_string)
        return self._parse_workflow(data)
    
    def _parse_workflow(self, data: Dict[str, Any]) -> WorkflowDefinition:
        """Parse workflow from dict data."""
        # Parse parameters
        parameters = {}
        for name, param_data in data.get("parameters", {}).items():
            parameters[name] = self._parse_parameter(name, param_data)
        
        # Parse steps
        steps = []
        for step_data in data.get("steps", []):
            steps.append(self._parse_step(step_data))
        
        # Parse phases
        phases = []
        for phase_data in data.get("phases", []):
            phases.append(self._parse_phase(phase_data))
        
        return WorkflowDefinition(
            name=data.get("name", "unnamed"),
            description=data.get("description", ""),
            version=data.get("version", "1.0.0"),
            estimated_duration=data.get("estimated_duration", ""),
            metadata=data.get("metadata", {}),
            parameters=parameters,
            variables=data.get("variables", {}),
            steps=steps,
            phases=phases,
            output=data.get("output", {}),
            report=data.get("report", {})
        )
    
    def _parse_parameter(
        self, 
        name: str, 
        data: Dict[str, Any]
    ) -> WorkflowParameter:
        """Parse a workflow parameter."""
        return WorkflowParameter(
            name=name,
            type=data.get("type", "string"),
            required=data.get("required", False),
            default=data.get("default"),
            description=data.get("description", ""),
            validation=data.get("validation"),
            allowed_values=data.get("allowed_values", []),
            sensitive=data.get("sensitive", False)
        )
    
    def _parse_step(self, data: Dict[str, Any]) -> WorkflowStepDef:
        """Parse a workflow step."""
        substeps = []
        for substep_data in data.get("substeps", []):
            substeps.append(self._parse_step(substep_data))
        
        return WorkflowStepDef(
            id=data.get("id", ""),
            name=data.get("name", ""),
            tool=data.get("tool", ""),
            params=data.get("params", {}),
            description=data.get("description", ""),
            condition=data.get("condition"),
            depends_on=data.get("depends_on", []),
            outputs=data.get("outputs", []),
            continue_on_failure=data.get("continue_on_failure", False),
            timeout=data.get("timeout", 300),
            retries=data.get("retries", 0),
            substeps=substeps
        )
    
    def _parse_phase(self, data: Dict[str, Any]) -> WorkflowPhaseDef:
        """Parse a workflow phase."""
        steps = []
        for step_data in data.get("steps", []):
            steps.append(self._parse_step(step_data))
        
        return WorkflowPhaseDef(
            id=data.get("id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            steps=steps,
            depends_on=data.get("depends_on", []),
            condition=data.get("condition"),
            parallel=data.get("parallel", False)
        )
    
    def get_workflow(self, name: str) -> Optional[WorkflowDefinition]:
        """
        Get a workflow by name.
        
        Args:
            name: Workflow name
            
        Returns:
            WorkflowDefinition if found, None otherwise
        """
        return self.workflows.get(name)
    
    def list_workflows(self) -> List[Dict[str, Any]]:
        """
        List all loaded workflows.
        
        Returns:
            List of workflow summaries
        """
        return [
            {
                "name": wf.name,
                "description": wf.description,
                "version": wf.version,
                "estimated_duration": wf.estimated_duration,
                "metadata": wf.metadata
            }
            for wf in self.workflows.values()
        ]
    
    def validate_workflow(
        self, 
        workflow: WorkflowDefinition,
        available_tools: List[str]
    ) -> Dict[str, Any]:
        """
        Validate a workflow definition.
        
        Args:
            workflow: Workflow to validate
            available_tools: List of available tool names
            
        Returns:
            Validation results
        """
        errors = []
        warnings = []
        
        # Check required fields
        if not workflow.name:
            errors.append("Workflow name is required")
        
        # Validate steps reference valid tools
        all_steps = list(workflow.steps)
        for phase in workflow.phases:
            all_steps.extend(phase.steps)
        
        for step in all_steps:
            if step.tool and step.tool not in available_tools:
                errors.append(
                    f"Step '{step.id}' references unknown tool: {step.tool}"
                )
            
            # Check dependency references
            for dep in step.depends_on:
                dep_exists = any(s.id == dep for s in all_steps)
                if not dep_exists:
                    errors.append(
                        f"Step '{step.id}' depends on unknown step: {dep}"
                    )
        
        # Check for circular dependencies
        if self._has_circular_deps(workflow):
            errors.append("Workflow has circular dependencies")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings
        }
    
    def _has_circular_deps(self, workflow: WorkflowDefinition) -> bool:
        """Check for circular dependencies in workflow."""
        all_steps = {s.id: s for s in workflow.steps}
        for phase in workflow.phases:
            for step in phase.steps:
                all_steps[step.id] = step
        
        visited = set()
        rec_stack = set()
        
        def has_cycle(step_id: str) -> bool:
            visited.add(step_id)
            rec_stack.add(step_id)
            
            step = all_steps.get(step_id)
            if step:
                for dep in step.depends_on:
                    if dep not in visited:
                        if has_cycle(dep):
                            return True
                    elif dep in rec_stack:
                        return True
            
            rec_stack.remove(step_id)
            return False
        
        for step_id in all_steps:
            if step_id not in visited:
                if has_cycle(step_id):
                    return True
        
        return False


class TemplateRenderer:
    """
    Renders workflow templates with variable substitution.
    
    Supports:
    - Simple variable substitution: {{variable}}
    - Filters: {{variable|filter}}
    - Nested access: {{step.result.value}}
    """
    
    def __init__(self):
        """Initialize template renderer."""
        self.filters = {
            "domain": self._extract_domain,
            "host": self._extract_host,
            "lower": str.lower,
            "upper": str.upper,
            "strip": str.strip
        }
    
    def render(
        self, 
        template: Any, 
        context: Dict[str, Any]
    ) -> Any:
        """
        Render a template with context.
        
        Args:
            template: Template (string, dict, or list)
            context: Variable context
            
        Returns:
            Rendered template
        """
        if isinstance(template, str):
            return self._render_string(template, context)
        elif isinstance(template, dict):
            return {
                k: self.render(v, context) 
                for k, v in template.items()
            }
        elif isinstance(template, list):
            return [self.render(item, context) for item in template]
        else:
            return template
    
    def _render_string(self, template: str, context: Dict[str, Any]) -> str:
        """Render a string template."""
        pattern = r'\{\{([^}]+)\}\}'
        
        def replace(match):
            expr = match.group(1).strip()
            return str(self._evaluate(expr, context))
        
        return re.sub(pattern, replace, template)
    
    def _evaluate(self, expr: str, context: Dict[str, Any]) -> Any:
        """Evaluate a template expression."""
        # Check for filter
        if "|" in expr:
            parts = expr.split("|")
            value = self._get_value(parts[0].strip(), context)
            
            for filter_name in parts[1:]:
                filter_name = filter_name.strip()
                if filter_name in self.filters:
                    value = self.filters[filter_name](value)
            
            return value
        else:
            return self._get_value(expr, context)
    
    def _get_value(self, path: str, context: Dict[str, Any]) -> Any:
        """Get a value from context using dot notation."""
        parts = path.split(".")
        value = context
        
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part, "")
            else:
                return ""
        
        return value
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        import urllib.parse
        try:
            parsed = urllib.parse.urlparse(
                url if "://" in url else f"https://{url}"
            )
            return parsed.netloc or url
        except Exception:
            return url
    
    def _extract_host(self, url: str) -> str:
        """Extract host (without port) from URL."""
        domain = self._extract_domain(url)
        return domain.split(":")[0]
