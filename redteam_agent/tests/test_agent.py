"""
Red Team Agent - Test Suite
===========================

Basic tests for the agent framework components.
"""

import unittest
import sys
from pathlib import Path

# Add agent to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestMemory(unittest.TestCase):
    """Test Memory module."""
    
    def setUp(self):
        from agent.core.memory import Memory
        self.memory = Memory()
        
    def test_add_and_get(self):
        """Test adding and retrieving from memory."""
        self.memory.add("test_key", "test_value")
        self.assertEqual(self.memory.get("test_key"), "test_value")
        
    def test_get_default(self):
        """Test default value for missing key."""
        result = self.memory.get("nonexistent", "default")
        self.assertEqual(result, "default")
        
    def test_long_term_memory(self):
        """Test long-term memory storage."""
        self.memory.add("persistent", "data", long_term=True)
        self.assertEqual(self.memory.get("persistent"), "data")
        
        # Clear short-term
        self.memory.clear()
        
        # Long-term should still exist
        self.assertEqual(self.memory.get("persistent"), "data")
        
    def test_contains(self):
        """Test key existence check."""
        self.memory.add("exists", True)
        self.assertIn("exists", self.memory)
        self.assertNotIn("not_exists", self.memory)


class TestSecurityGate(unittest.TestCase):
    """Test Security Gate module."""
    
    def setUp(self):
        from agent.security.gate import SecurityGate
        self.gate = SecurityGate(
            whitelist=["192.168.1.0/24", "example.com"],
            blacklist=["192.168.1.1"],
            enabled=True
        )
        
    def test_whitelist_ip(self):
        """Test whitelisted IP is authorized."""
        result = self.gate.authorize("scan", "192.168.1.100")
        self.assertTrue(result.authorized)
        
    def test_whitelist_domain(self):
        """Test whitelisted domain is authorized."""
        result = self.gate.authorize("scan", "example.com")
        self.assertTrue(result.authorized)
        
    def test_blacklist_denied(self):
        """Test blacklisted target is denied."""
        result = self.gate.authorize("scan", "192.168.1.1")
        self.assertFalse(result.authorized)
        
    def test_not_whitelisted_denied(self):
        """Test non-whitelisted target is denied."""
        result = self.gate.authorize("scan", "10.0.0.1")
        self.assertFalse(result.authorized)
        
    def test_safe_action_allowed(self):
        """Test safe actions are always allowed."""
        result = self.gate.authorize("analyze")
        self.assertTrue(result.authorized)
        
    def test_localhost_blocked(self):
        """Test localhost is always blocked."""
        result = self.gate.authorize("scan", "127.0.0.1")
        self.assertFalse(result.authorized)


class TestPlanner(unittest.TestCase):
    """Test Planner module."""
    
    def setUp(self):
        from agent.core.planner import Planner
        self.planner = Planner()
        
    def test_parse_json_plan(self):
        """Test parsing JSON plan from LLM response."""
        mock_response = '''
        Here is my plan:
        ```json
        {
            "objective": "Test scan",
            "steps": [
                {
                    "id": 1,
                    "tool": "nmap",
                    "action": "quick_scan",
                    "params": {"target": "192.168.1.1"},
                    "expected": "Open ports"
                }
            ]
        }
        ```
        '''
        plan = self.planner._parse_llm_plan(mock_response)
        self.assertIsNotNone(plan)
        self.assertEqual(len(plan["steps"]), 1)
        self.assertEqual(plan["steps"][0]["tool"], "nmap")


class TestExecutor(unittest.TestCase):
    """Test Executor module."""
    
    def setUp(self):
        from agent.core.executor import Executor
        from agent.security.gate import SecurityGate
        from agent.tools.registry import ToolRegistry
        
        self.gate = SecurityGate(whitelist=["test.com"], enabled=True)
        self.registry = ToolRegistry()
        self.executor = Executor(
            security_gate=self.gate,
            tool_registry=self.registry
        )
        
    def test_validate_action_authorized(self):
        """Test action validation for authorized target."""
        is_valid, reason = self.executor._validate_action({
            "tool": "nmap",
            "action": "scan",
            "params": {"target": "test.com"}
        })
        self.assertTrue(is_valid)
        
    def test_validate_action_denied(self):
        """Test action validation for unauthorized target."""
        is_valid, reason = self.executor._validate_action({
            "tool": "nmap",
            "action": "scan",
            "params": {"target": "unauthorized.com"}
        })
        self.assertFalse(is_valid)


class TestToolBase(unittest.TestCase):
    """Test Tool Base classes."""
    
    def test_tool_result(self):
        """Test ToolResult dataclass."""
        from agent.tools.base import ToolResult, ToolStatus
        
        result = ToolResult(
            status=ToolStatus.SUCCESS,
            output="test output",
            parsed={"key": "value"},
            duration=1.5
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.status, ToolStatus.SUCCESS)
        
        # Test to_dict
        result_dict = result.to_dict()
        self.assertEqual(result_dict["status"], "success")
        
    def test_tool_registry(self):
        """Test tool registration."""
        from agent.tools.registry import ToolRegistry
        from agent.tools.base import BaseTool, ToolResult, ToolStatus
        
        class MockTool(BaseTool):
            name = "mock"
            description = "Mock tool"
            category = "test"
            actions = ["test_action"]
            
            def execute(self, action, target, params=None):
                return ToolResult(
                    status=ToolStatus.SUCCESS,
                    output="mock output"
                )
                
            def parse_output(self, output):
                return {"raw": output}
                
        registry = ToolRegistry()
        mock_tool = MockTool()
        
        registry.register(mock_tool)
        
        self.assertTrue(registry.has_tool("mock"))
        self.assertEqual(len(registry.list_tools()), 1)


class TestReporter(unittest.TestCase):
    """Test Reporter module."""
    
    def setUp(self):
        from agent.core.reporter import Reporter
        self.reporter = Reporter()
        
    def test_calculate_statistics(self):
        """Test finding statistics calculation."""
        findings = [
            {"severity": "critical", "type": "sqli"},
            {"severity": "high", "type": "xss"},
            {"severity": "high", "type": "xss"},
            {"severity": "medium", "type": "info_disclosure"}
        ]
        
        stats = self.reporter._calculate_statistics(findings)
        
        self.assertEqual(stats["total"], 4)
        self.assertEqual(stats["by_severity"]["critical"], 1)
        self.assertEqual(stats["by_severity"]["high"], 2)
        self.assertEqual(stats["risk_level"], "CRITICAL")
        
    def test_sort_findings_by_severity(self):
        """Test findings are sorted by severity."""
        findings = [
            {"severity": "low"},
            {"severity": "critical"},
            {"severity": "medium"}
        ]
        
        sorted_findings = self.reporter._sort_findings_by_severity(findings)
        
        self.assertEqual(sorted_findings[0]["severity"], "critical")
        self.assertEqual(sorted_findings[-1]["severity"], "low")


class TestConfig(unittest.TestCase):
    """Test Config module."""
    
    def setUp(self):
        from agent.utils.config import Config
        self.config = Config()
        
    def test_default_values(self):
        """Test default configuration values."""
        self.assertIsNotNone(self.config.get("llm.model_path"))
        self.assertIsNotNone(self.config.get("agent.max_steps"))
        
    def test_get_with_default(self):
        """Test getting value with default."""
        result = self.config.get("nonexistent.key", "default_value")
        self.assertEqual(result, "default_value")
        
    def test_set_and_get(self):
        """Test setting and getting values."""
        self.config.set("test.nested.key", "test_value")
        self.assertEqual(self.config.get("test.nested.key"), "test_value")
        
    def test_get_section(self):
        """Test getting config section."""
        llm_section = self.config.get_section("llm")
        self.assertIn("model_path", llm_section)


class TestPromptTemplates(unittest.TestCase):
    """Test Prompt Templates."""
    
    def test_planning_prompt(self):
        """Test planning prompt generation."""
        from agent.llm.prompts import PromptTemplate
        
        prompt = PromptTemplate.planning_prompt(
            task="Scan target 192.168.1.1",
            context="Previous scan found port 80 open"
        )
        
        self.assertIn("Scan target", prompt)
        self.assertIn("Previous scan", prompt)
        
    def test_observation_prompt(self):
        """Test observation prompt generation."""
        from agent.llm.prompts import PromptTemplate
        
        prompt = PromptTemplate.observation_prompt(
            tool="nmap",
            action="scan",
            output="80/tcp open http"
        )
        
        self.assertIn("nmap", prompt)
        self.assertIn("80/tcp", prompt)


if __name__ == "__main__":
    # Run tests
    unittest.main(verbosity=2)
