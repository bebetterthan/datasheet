"""
LLM Response Parser Module
==========================

Parses structured responses from LLM into actionable data.
"""

import re
import json
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass

from agent.utils.logger import get_logger


@dataclass
class ToolCall:
    """Parsed tool call from LLM response."""
    tool: str
    action: str
    params: Dict[str, Any]
    reason: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "action": self.action,
            "params": self.params,
            "reason": self.reason
        }


@dataclass
class Finding:
    """Parsed finding from analysis."""
    type: str
    severity: str
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation
        }


class ResponseParser:
    """
    Parser for LLM responses.
    
    Handles multiple response formats:
    - XML-like structured responses
    - JSON responses
    - Natural language with embedded structure
    """
    
    def __init__(self):
        self.logger = get_logger("ResponseParser")
        
    def parse_tool_call(self, response: str) -> Optional[ToolCall]:
        """
        Extract tool call from LLM response.
        
        Args:
            response: Raw LLM response
            
        Returns:
            ToolCall object or None if not found
        """
        # Try XML format first
        tool_call = self._parse_xml_tool_call(response)
        if tool_call:
            return tool_call
            
        # Try JSON format
        tool_call = self._parse_json_tool_call(response)
        if tool_call:
            return tool_call
            
        # Try natural language extraction
        tool_call = self._parse_natural_tool_call(response)
        if tool_call:
            return tool_call
            
        return None
        
    def _parse_xml_tool_call(self, response: str) -> Optional[ToolCall]:
        """Parse XML-formatted tool call."""
        # Pattern: <tool_call>...</tool_call>
        pattern = r'<tool_call>(.*?)</tool_call>'
        match = re.search(pattern, response, re.DOTALL)
        
        if not match:
            return None
            
        content = match.group(1)
        
        try:
            # Extract components
            name_match = re.search(r'<name>(.*?)</name>', content)
            action_match = re.search(r'<action>(.*?)</action>', content)
            params_match = re.search(r'<params>(.*?)</params>', content, re.DOTALL)
            reason_match = re.search(r'<reason>(.*?)</reason>', content, re.DOTALL)
            
            if not name_match or not action_match:
                return None
                
            params = {}
            if params_match:
                try:
                    params = json.loads(params_match.group(1).strip())
                except json.JSONDecodeError:
                    # Try to extract key-value pairs
                    params = self._extract_params_from_text(params_match.group(1))
                    
            return ToolCall(
                tool=name_match.group(1).strip(),
                action=action_match.group(1).strip(),
                params=params,
                reason=reason_match.group(1).strip() if reason_match else None
            )
            
        except Exception as e:
            self.logger.debug(f"XML parse error: {e}")
            return None
            
    def _parse_json_tool_call(self, response: str) -> Optional[ToolCall]:
        """Parse JSON-formatted tool call."""
        # Look for JSON block
        json_patterns = [
            r'```json\s*(.*?)\s*```',
            r'```\s*({\s*"tool".*?})\s*```',
            r'(\{[^{}]*"tool"[^{}]*\})'
        ]
        
        for pattern in json_patterns:
            matches = re.findall(pattern, response, re.DOTALL)
            for match in matches:
                try:
                    data = json.loads(match)
                    if "tool" in data:
                        return ToolCall(
                            tool=data.get("tool", ""),
                            action=data.get("action", "execute"),
                            params=data.get("params", data.get("parameters", {})),
                            reason=data.get("reason")
                        )
                except json.JSONDecodeError:
                    continue
                    
        return None
        
    def _parse_natural_tool_call(self, response: str) -> Optional[ToolCall]:
        """Extract tool call from natural language."""
        # Common patterns
        patterns = [
            r'(?:use|run|execute|call)\s+(?:the\s+)?["\']?(\w+)["\']?\s+(?:tool\s+)?(?:with\s+)?(?:action\s+)?["\']?(\w+)?["\']?',
            r'Tool:\s*(\w+).*?Action:\s*(\w+)',
            r'(\w+)\.(\w+)\s*\(',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                tool = match.group(1)
                action = match.group(2) if match.lastindex >= 2 and match.group(2) else "execute"
                
                # Try to find parameters
                params = self._extract_params_from_text(response)
                
                return ToolCall(
                    tool=tool,
                    action=action,
                    params=params,
                    reason=None
                )
                
        return None
        
    def _extract_params_from_text(self, text: str) -> Dict[str, Any]:
        """Extract parameters from text."""
        params = {}
        
        # Look for key=value or key: value patterns
        kv_patterns = [
            r'(\w+)\s*[=:]\s*["\']([^"\']+)["\']',
            r'(\w+)\s*[=:]\s*(\S+)',
        ]
        
        for pattern in kv_patterns:
            matches = re.findall(pattern, text)
            for key, value in matches:
                key = key.lower()
                # Try to convert to appropriate type
                if value.lower() in ('true', 'false'):
                    params[key] = value.lower() == 'true'
                elif value.isdigit():
                    params[key] = int(value)
                else:
                    params[key] = value
                    
        # Look for URLs
        url_match = re.search(r'https?://[^\s<>"{}|\\^`\[\]]+', text)
        if url_match and 'url' not in params and 'target' not in params:
            params['target'] = url_match.group()
            
        return params
        
    def parse_plan(self, response: str) -> Optional[Dict[str, Any]]:
        """
        Extract execution plan from LLM response.
        
        Args:
            response: Raw LLM response
            
        Returns:
            Plan dictionary or None
        """
        # Try JSON format
        plan = self._parse_json_plan(response)
        if plan:
            return plan
            
        # Try XML format
        plan = self._parse_xml_plan(response)
        if plan:
            return plan
            
        return None
        
    def _parse_json_plan(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse JSON-formatted plan."""
        # Look for JSON with steps
        patterns = [
            r'```json\s*(.*?)\s*```',
            r'```\s*(\{.*?"steps".*?\})\s*```',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response, re.DOTALL)
            for match in matches:
                try:
                    data = json.loads(match)
                    if "steps" in data:
                        return data
                except json.JSONDecodeError:
                    continue
                    
        # Try to find raw JSON
        try:
            start = response.find('{')
            end = response.rfind('}') + 1
            if start != -1 and end > start:
                data = json.loads(response[start:end])
                if "steps" in data:
                    return data
        except:
            pass
            
        return None
        
    def _parse_xml_plan(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse XML-formatted plan."""
        pattern = r'<plan>(.*?)</plan>'
        match = re.search(pattern, response, re.DOTALL)
        
        if not match:
            return None
            
        content = match.group(1)
        
        # Extract steps
        step_pattern = r'<step\s+id=["\']?(\d+)["\']?\s+tool=["\']?(\w+)["\']?(?:\s+action=["\']?(\w+)["\']?)?(?:\s+depends=["\']?(\d+)?["\']?)?>(.*?)</step>'
        steps = []
        
        for step_match in re.finditer(step_pattern, content, re.DOTALL):
            step_id = int(step_match.group(1))
            tool = step_match.group(2)
            action = step_match.group(3) or "execute"
            depends = int(step_match.group(4)) if step_match.group(4) else None
            step_content = step_match.group(5)
            
            # Extract params
            params_match = re.search(r'<params>(.*?)</params>', step_content, re.DOTALL)
            params = {}
            if params_match:
                try:
                    params = json.loads(params_match.group(1).strip())
                except:
                    params = self._extract_params_from_text(params_match.group(1))
                    
            steps.append({
                "id": step_id,
                "tool": tool,
                "action": action,
                "params": params,
                "depends_on": depends
            })
            
        if steps:
            return {
                "steps": sorted(steps, key=lambda x: x["id"])
            }
            
        return None
        
    def parse_findings(self, response: str) -> List[Finding]:
        """
        Extract findings from analysis response.
        
        Args:
            response: Raw LLM response
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Try XML format
        findings.extend(self._parse_xml_findings(response))
        
        # Try JSON format
        findings.extend(self._parse_json_findings(response))
        
        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = (f.type, f.severity, f.description[:50])
            if key not in seen:
                seen.add(key)
                unique.append(f)
                
        return unique
        
    def _parse_xml_findings(self, response: str) -> List[Finding]:
        """Parse XML-formatted findings."""
        findings = []
        
        # Find analysis block
        analysis_match = re.search(r'<analysis>(.*?)</analysis>', response, re.DOTALL)
        content = analysis_match.group(1) if analysis_match else response
        
        # Find individual findings
        pattern = r'<finding\s+severity=["\']?(\w+)["\']?\s+type=["\']?([^"\']+)["\']?>(.*?)</finding>'
        
        for match in re.finditer(pattern, content, re.DOTALL):
            severity = match.group(1)
            finding_type = match.group(2)
            inner = match.group(3)
            
            desc_match = re.search(r'<description>(.*?)</description>', inner, re.DOTALL)
            evidence_match = re.search(r'<evidence>(.*?)</evidence>', inner, re.DOTALL)
            remediation_match = re.search(r'<remediation>(.*?)</remediation>', inner, re.DOTALL)
            
            findings.append(Finding(
                type=finding_type,
                severity=severity,
                description=desc_match.group(1).strip() if desc_match else "",
                evidence=evidence_match.group(1).strip() if evidence_match else None,
                remediation=remediation_match.group(1).strip() if remediation_match else None
            ))
            
        return findings
        
    def _parse_json_findings(self, response: str) -> List[Finding]:
        """Parse JSON-formatted findings."""
        findings = []
        
        # Look for findings array in JSON
        patterns = [
            r'"findings"\s*:\s*\[(.*?)\]',
            r'```json\s*(.*?)\s*```',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response, re.DOTALL)
            for match in matches:
                try:
                    # Try to parse as array
                    if not match.strip().startswith('['):
                        match = '[' + match + ']'
                    data = json.loads(match)
                    
                    for item in data:
                        if isinstance(item, dict) and 'type' in item:
                            findings.append(Finding(
                                type=item.get('type', 'unknown'),
                                severity=item.get('severity', 'info'),
                                description=item.get('description', ''),
                                evidence=item.get('evidence'),
                                remediation=item.get('remediation', item.get('recommendation'))
                            ))
                except:
                    continue
                    
        return findings
        
    def parse_next_action(self, response: str) -> Tuple[str, Optional[str]]:
        """
        Determine next action from LLM response.
        
        Args:
            response: Raw LLM response
            
        Returns:
            Tuple of (action_type, detail)
            action_type: "tool_call", "complete", "continue", "error"
        """
        response_lower = response.lower()
        
        # Check for completion signals
        completion_patterns = [
            "task complete",
            "scan complete",
            "assessment complete",
            "finished",
            "no further action",
            "report generated"
        ]
        
        for pattern in completion_patterns:
            if pattern in response_lower:
                return ("complete", None)
                
        # Check for tool call
        if self.parse_tool_call(response):
            return ("tool_call", None)
            
        # Check for error signals
        error_patterns = [
            "cannot proceed",
            "authorization denied",
            "out of scope",
            "error occurred"
        ]
        
        for pattern in error_patterns:
            if pattern in response_lower:
                return ("error", pattern)
                
        # Default to continue
        return ("continue", None)
        
    def clean_response(self, response: str) -> str:
        """
        Clean LLM response for display.
        
        Args:
            response: Raw LLM response
            
        Returns:
            Cleaned response
        """
        # Remove common artifacts
        response = response.strip()
        
        # Remove thinking tags if present
        response = re.sub(r'<thinking>.*?</thinking>', '', response, flags=re.DOTALL)
        
        # Remove excessive whitespace
        response = re.sub(r'\n{3,}', '\n\n', response)
        
        return response
