"""
Integration Tests for Phase 3: Task System & Workflow Engine
============================================================
Tests for workflow engine, task queue, and report generation.
"""

import pytest
import asyncio
import tempfile
import json
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, AsyncMock, patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.core.workflow import WorkflowEngine, WorkflowStep, WorkflowState
from agent.core.task_queue import TaskQueue, Task, TaskPriority, TaskStatus, TaskBatch
from agent.core.workflow_loader import (
    WorkflowLoader, 
    WorkflowDefinition, 
    WorkflowParameter,
    TemplateRenderer
)
from agent.tools.reporter.report_generator import ReportGenerator, Finding, ScanResult
from agent.utils.pattern_loader import PatternLoader, PatternMatcher


class TestWorkflowEngine:
    """Test workflow engine functionality."""
    
    @pytest.fixture
    def mock_tool_registry(self):
        """Create mock tool registry."""
        registry = Mock()
        
        # Mock tool that returns success
        async def mock_execute(tool_name, params):
            return {
                "success": True,
                "tool": tool_name,
                "params": params,
                "result": {"status": "completed"}
            }
        
        registry.execute = AsyncMock(side_effect=mock_execute)
        registry.get_tool = Mock(return_value=Mock())
        return registry
    
    @pytest.fixture
    def workflow_engine(self, mock_tool_registry):
        """Create workflow engine with mock registry."""
        return WorkflowEngine(tool_registry=mock_tool_registry)
    
    @pytest.mark.asyncio
    async def test_workflow_creation(self, workflow_engine):
        """Test creating a workflow."""
        workflow = workflow_engine.create_workflow(
            name="test_workflow",
            description="Test workflow"
        )
        
        assert workflow.name == "test_workflow"
        assert workflow.status == WorkflowState.PENDING
        assert len(workflow.steps) == 0
    
    @pytest.mark.asyncio
    async def test_add_workflow_step(self, workflow_engine):
        """Test adding steps to workflow."""
        workflow = workflow_engine.create_workflow("test", "Test")
        
        step = WorkflowStep(
            id="step_1",
            name="Test Step",
            tool="test_tool",
            params={"key": "value"}
        )
        
        workflow_engine.add_step(workflow.name, step)
        assert len(workflow.steps) == 1
        assert workflow.steps[0].id == "step_1"
    
    @pytest.mark.asyncio
    async def test_workflow_execution(self, workflow_engine, mock_tool_registry):
        """Test executing a workflow."""
        # Create workflow with steps
        workflow = workflow_engine.create_workflow("exec_test", "Execution Test")
        
        workflow_engine.add_step("exec_test", WorkflowStep(
            id="step_1",
            name="First Step",
            tool="recon_tool",
            params={"target": "example.com"}
        ))
        
        workflow_engine.add_step("exec_test", WorkflowStep(
            id="step_2",
            name="Second Step",
            tool="scan_tool",
            params={"url": "https://example.com"},
            depends_on=["step_1"]
        ))
        
        # Execute workflow
        result = await workflow_engine.execute_workflow("exec_test")
        
        assert result["status"] == "completed"
        assert "step_1" in result["results"]
        assert "step_2" in result["results"]
    
    @pytest.mark.asyncio
    async def test_workflow_conditional_step(self, workflow_engine):
        """Test conditional step execution."""
        workflow = workflow_engine.create_workflow("cond_test", "Conditional Test")
        
        # Step with condition
        step = WorkflowStep(
            id="conditional_step",
            name="Conditional Step",
            tool="test_tool",
            params={},
            condition="context.should_run == True"
        )
        
        workflow_engine.add_step("cond_test", step)
        
        # Execute with condition false
        result = await workflow_engine.execute_workflow(
            "cond_test",
            context={"should_run": False}
        )
        
        # Step should be skipped
        assert result["results"]["conditional_step"]["skipped"] == True


class TestTaskQueue:
    """Test task queue functionality."""
    
    @pytest.fixture
    def task_queue(self):
        """Create task queue."""
        return TaskQueue(max_workers=2)
    
    def test_task_creation(self):
        """Test creating a task."""
        task = Task(
            id="task_1",
            name="Test Task",
            handler="test_handler",
            params={"key": "value"},
            priority=TaskPriority.HIGH
        )
        
        assert task.id == "task_1"
        assert task.status == TaskStatus.PENDING
        assert task.priority == TaskPriority.HIGH
    
    def test_task_priority_ordering(self, task_queue):
        """Test task priority ordering."""
        # Add tasks with different priorities
        task_queue.add_task(Task(
            id="low",
            name="Low Priority",
            handler="handler",
            priority=TaskPriority.LOW
        ))
        
        task_queue.add_task(Task(
            id="critical",
            name="Critical Priority",
            handler="handler",
            priority=TaskPriority.CRITICAL
        ))
        
        task_queue.add_task(Task(
            id="normal",
            name="Normal Priority",
            handler="handler",
            priority=TaskPriority.NORMAL
        ))
        
        # Get next task should return highest priority
        next_task = task_queue.get_next_task()
        assert next_task.id == "critical"
    
    def test_task_dependencies(self, task_queue):
        """Test task dependency handling."""
        parent = Task(
            id="parent",
            name="Parent Task",
            handler="handler"
        )
        
        child = Task(
            id="child",
            name="Child Task",
            handler="handler",
            dependencies=["parent"]
        )
        
        task_queue.add_task(parent)
        task_queue.add_task(child)
        
        # Child should not be ready until parent completes
        assert not task_queue.is_task_ready(child)
        
        # Complete parent
        parent.status = TaskStatus.COMPLETED
        task_queue.update_task(parent)
        
        # Now child should be ready
        assert task_queue.is_task_ready(child)
    
    @pytest.mark.asyncio
    async def test_task_batch_execution(self, task_queue):
        """Test batch task execution."""
        results = []
        
        async def test_handler(task):
            results.append(task.id)
            return {"status": "success"}
        
        batch = TaskBatch(
            id="batch_1",
            name="Test Batch",
            tasks=[
                Task(id="t1", name="Task 1", handler="test"),
                Task(id="t2", name="Task 2", handler="test"),
                Task(id="t3", name="Task 3", handler="test")
            ]
        )
        
        # Register handler
        task_queue.register_handler("test", test_handler)
        
        # Execute batch
        await task_queue.execute_batch(batch)
        
        assert len(results) == 3


class TestWorkflowLoader:
    """Test workflow YAML loader."""
    
    @pytest.fixture
    def sample_workflow_yaml(self):
        """Sample workflow YAML content."""
        return """
name: test_workflow
description: Test workflow for unit tests
version: "1.0.0"
estimated_duration: "5 minutes"

parameters:
  target:
    type: string
    required: true
    description: Target URL
    
  depth:
    type: string
    default: standard
    allowed_values:
      - light
      - standard
      - deep

steps:
  - id: step_1
    name: First Step
    tool: http_client
    params:
      url: "{{target}}"
      method: GET
    outputs:
      - response
      
  - id: step_2
    name: Second Step
    tool: analyzer
    depends_on:
      - step_1
    params:
      data: "{{step_1.response}}"
"""
    
    def test_load_workflow_string(self, sample_workflow_yaml):
        """Test loading workflow from string."""
        loader = WorkflowLoader()
        workflow = loader.load_workflow_string(sample_workflow_yaml)
        
        assert workflow.name == "test_workflow"
        assert workflow.version == "1.0.0"
        assert len(workflow.parameters) == 2
        assert len(workflow.steps) == 2
    
    def test_parameter_validation(self, sample_workflow_yaml):
        """Test parameter validation."""
        loader = WorkflowLoader()
        workflow = loader.load_workflow_string(sample_workflow_yaml)
        
        # Valid parameters
        errors = workflow.validate_parameters({
            "target": "https://example.com",
            "depth": "standard"
        })
        assert len(errors) == 0
        
        # Missing required parameter
        errors = workflow.validate_parameters({
            "depth": "standard"
        })
        assert "target" in errors
        
        # Invalid allowed value
        errors = workflow.validate_parameters({
            "target": "https://example.com",
            "depth": "invalid"
        })
        assert "depth" in errors
    
    def test_workflow_execution_order(self, sample_workflow_yaml):
        """Test getting execution order."""
        loader = WorkflowLoader()
        workflow = loader.load_workflow_string(sample_workflow_yaml)
        
        order = workflow.get_execution_order()
        
        # step_1 should come before step_2
        assert order.index("step_1") < order.index("step_2")


class TestTemplateRenderer:
    """Test template rendering."""
    
    @pytest.fixture
    def renderer(self):
        """Create template renderer."""
        return TemplateRenderer()
    
    def test_simple_substitution(self, renderer):
        """Test simple variable substitution."""
        template = "Hello {{name}}!"
        result = renderer.render(template, {"name": "World"})
        assert result == "Hello World!"
    
    def test_nested_access(self, renderer):
        """Test nested variable access."""
        template = "Result: {{step.result.value}}"
        context = {
            "step": {
                "result": {
                    "value": "success"
                }
            }
        }
        result = renderer.render(template, context)
        assert result == "Result: success"
    
    def test_filter_domain(self, renderer):
        """Test domain filter."""
        template = "{{url|domain}}"
        result = renderer.render(template, {"url": "https://www.example.com/path"})
        assert result == "www.example.com"
    
    def test_filter_host(self, renderer):
        """Test host filter."""
        template = "{{url|host}}"
        result = renderer.render(template, {"url": "https://example.com:8080/path"})
        assert result == "example.com"
    
    def test_dict_rendering(self, renderer):
        """Test rendering dict templates."""
        template = {
            "url": "https://{{target}}",
            "headers": {
                "Host": "{{target}}"
            }
        }
        result = renderer.render(template, {"target": "example.com"})
        
        assert result["url"] == "https://example.com"
        assert result["headers"]["Host"] == "example.com"


class TestReportGenerator:
    """Test report generation."""
    
    @pytest.fixture
    def sample_findings(self):
        """Create sample findings."""
        return [
            Finding(
                id="finding_1",
                title="SQL Injection",
                severity="critical",
                description="SQL injection vulnerability found",
                evidence="Error: SQL syntax",
                url="https://example.com/api",
                remediation="Use parameterized queries"
            ),
            Finding(
                id="finding_2",
                title="Missing Security Headers",
                severity="medium",
                description="X-Content-Type-Options header missing",
                url="https://example.com",
                remediation="Add X-Content-Type-Options: nosniff"
            )
        ]
    
    @pytest.fixture
    def sample_scan_result(self, sample_findings):
        """Create sample scan result."""
        return ScanResult(
            target="https://example.com",
            scan_type="full_assessment",
            start_time=datetime.now(),
            end_time=datetime.now(),
            findings=sample_findings,
            summary={
                "total_findings": 2,
                "critical": 1,
                "high": 0,
                "medium": 1,
                "low": 0,
                "info": 0
            }
        )
    
    def test_json_report_generation(self, sample_scan_result):
        """Test JSON report generation."""
        generator = ReportGenerator()
        report = generator.generate_json(sample_scan_result)
        
        data = json.loads(report)
        assert data["target"] == "https://example.com"
        assert len(data["findings"]) == 2
        assert data["summary"]["critical"] == 1
    
    def test_markdown_report_generation(self, sample_scan_result):
        """Test Markdown report generation."""
        generator = ReportGenerator()
        report = generator.generate_markdown(sample_scan_result)
        
        assert "# Security Assessment Report" in report
        assert "https://example.com" in report
        assert "SQL Injection" in report
        assert "CRITICAL" in report or "critical" in report.lower()
    
    def test_html_report_generation(self, sample_scan_result):
        """Test HTML report generation."""
        generator = ReportGenerator()
        report = generator.generate_html(sample_scan_result)
        
        assert "<html" in report
        assert "example.com" in report
        assert "SQL Injection" in report


class TestPatternLoader:
    """Test pattern loading and matching."""
    
    @pytest.fixture
    def temp_pattern_file(self):
        """Create temporary pattern file."""
        content = """
credentials:
  aws_access_key:
    pattern: 'AKIA[0-9A-Z]{16}'
    severity: critical
    description: "AWS Access Key ID"
    
  generic_api_key:
    pattern: 'api[_-]?key["\\'s]*[:=]\\s*["\\']+[a-zA-Z0-9_-]{20,}["\\'s]+'
    severity: high
    description: "Generic API Key"
    case_insensitive: true
"""
        with tempfile.NamedTemporaryFile(
            mode='w', 
            suffix='.yaml', 
            delete=False
        ) as f:
            f.write(content)
            return Path(f.name)
    
    def test_pattern_loading(self, temp_pattern_file):
        """Test loading patterns from file."""
        loader = PatternLoader()
        categories = loader.load_pattern_file(temp_pattern_file)
        
        assert "credentials" in categories
        assert "aws_access_key" in categories["credentials"].patterns
    
    def test_pattern_matching(self, temp_pattern_file):
        """Test pattern matching."""
        loader = PatternLoader()
        loader.load_pattern_file(temp_pattern_file)
        
        # Test AWS key pattern
        text = "Here is a key: AKIAIOSFODNN7EXAMPLE"
        matches = loader.match(text, categories=["credentials"])
        
        assert len(matches) > 0
        assert matches[0]["severity"] == "critical"
    
    def test_severity_filtering(self, temp_pattern_file):
        """Test filtering by severity."""
        loader = PatternLoader()
        loader.load_pattern_file(temp_pattern_file)
        
        text = "AKIAIOSFODNN7EXAMPLE api_key='test12345678901234567890'"
        
        # Only critical
        critical_matches = loader.match(
            text, 
            severity_filter=["critical"]
        )
        
        for match in critical_matches:
            assert match["severity"] == "critical"


class TestIntegration:
    """Integration tests combining multiple components."""
    
    @pytest.mark.asyncio
    async def test_full_workflow_execution(self):
        """Test complete workflow execution flow."""
        # Create mock components
        mock_registry = Mock()
        mock_registry.execute = AsyncMock(return_value={
            "success": True,
            "data": {"status": "ok"}
        })
        
        # Create workflow engine
        engine = WorkflowEngine(tool_registry=mock_registry)
        
        # Create workflow
        workflow = engine.create_workflow(
            "integration_test",
            "Integration test workflow"
        )
        
        # Add steps
        engine.add_step("integration_test", WorkflowStep(
            id="recon",
            name="Reconnaissance",
            tool="http_client",
            params={"url": "https://example.com"}
        ))
        
        engine.add_step("integration_test", WorkflowStep(
            id="scan",
            name="Vulnerability Scan",
            tool="nuclei",
            params={"target": "https://example.com"},
            depends_on=["recon"]
        ))
        
        engine.add_step("integration_test", WorkflowStep(
            id="analyze",
            name="Analysis",
            tool="analyzer",
            params={"data": "{{recon.result}}"},
            depends_on=["recon", "scan"]
        ))
        
        # Execute
        result = await engine.execute_workflow("integration_test")
        
        assert result["status"] == "completed"
        assert len(result["results"]) == 3
    
    @pytest.mark.asyncio
    async def test_workflow_with_task_queue(self):
        """Test workflow execution with task queue."""
        task_queue = TaskQueue(max_workers=2)
        results = []
        
        async def mock_handler(task):
            results.append(task.id)
            return {"success": True}
        
        task_queue.register_handler("mock", mock_handler)
        
        # Create tasks from workflow steps
        tasks = [
            Task(id="step_1", name="Step 1", handler="mock"),
            Task(id="step_2", name="Step 2", handler="mock", dependencies=["step_1"]),
            Task(id="step_3", name="Step 3", handler="mock", dependencies=["step_1"])
        ]
        
        for task in tasks:
            task_queue.add_task(task)
        
        # Process all tasks
        await task_queue.process_all()
        
        assert len(results) == 3
        # step_1 should be first
        assert results[0] == "step_1"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
