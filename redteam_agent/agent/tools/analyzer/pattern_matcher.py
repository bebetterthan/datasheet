"""
Pattern Matcher Tool
====================

Regex and pattern matching for security analysis.
"""

import re
from typing import Dict, Any, Optional, List, Pattern
from datetime import datetime

from agent.tools.base import BaseTool, ToolResult, ToolStatus


class PatternMatcher(BaseTool):
    """
    Pattern matching tool for content analysis.
    
    Actions:
        - match: Match patterns in content
        - extract: Extract matching content
        - search_vuln_patterns: Search for vulnerability indicators
    """
    
    name = "pattern_matcher"
    description = "Pattern matching and extraction"
    category = "analyzer"
    
    actions = ["match", "extract", "search_vuln_patterns"]
    timeout = 30
    
    # Built-in vulnerability patterns
    VULN_PATTERNS = {
        "sql_injection": [
            r"(?i)sql\s*syntax.*mysql",
            r"(?i)warning.*mysql_",
            r"(?i)unclosed\s*quotation\s*mark",
            r"(?i)quoted\s*string\s*not\s*properly\s*terminated",
            r"(?i)microsoft\s*ole\s*db\s*provider",
            r"(?i)odbc\s*sql\s*server\s*driver",
            r"(?i)supplied\s*argument\s*is\s*not\s*a\s*valid\s*MySQL",
            r"(?i)pg_query\(\)\s*:\s*query\s*failed",
            r"(?i)oracle\s*error",
            r"(?i)SQLite3::query\(\)"
        ],
        "xss": [
            r"<script[^>]*>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"onmouseover\s*="
        ],
        "path_traversal": [
            r"\.\./",
            r"\.\.\\",
            r"/etc/passwd",
            r"c:\\windows",
            r"/proc/self"
        ],
        "command_injection": [
            r"sh:\s*\d+:",
            r"/bin/sh",
            r"command\s*not\s*found",
            r"Permission\s*denied",
            r"uid=\d+\(.*\)\s*gid=\d+"
        ],
        "lfi_rfi": [
            r"Warning:\s*include\(",
            r"Warning:\s*require\(",
            r"failed\s*to\s*open\s*stream",
            r"No\s*such\s*file\s*or\s*directory"
        ],
        "ssrf": [
            r"(?i)refused\s*to\s*connect",
            r"(?i)connection\s*refused",
            r"(?i)couldn't\s*connect\s*to\s*host"
        ]
    }
    
    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """
        Execute pattern matching.
        
        Args:
            action: Match action
            target: Content to analyze
            params:
                - patterns: List of regex patterns
                - case_sensitive: Whether to use case-sensitive matching
                
        Returns:
            ToolResult with matches
        """
        params = params or {}
        start_time = datetime.now()
        
        self.validate_params(action, params)
        
        if action == "match":
            patterns = params.get("patterns", [])
            case_sensitive = params.get("case_sensitive", False)
            results = self._match_patterns(target, patterns, case_sensitive)
            
        elif action == "extract":
            patterns = params.get("patterns", [])
            results = self._extract_matches(target, patterns)
            
        elif action == "search_vuln_patterns":
            vuln_types = params.get("vuln_types", list(self.VULN_PATTERNS.keys()))
            results = self._search_vulnerabilities(target, vuln_types)
            
        else:
            results = {"matches": [], "count": 0}
            
        duration = (datetime.now() - start_time).total_seconds()
        
        return ToolResult(
            status=ToolStatus.SUCCESS,
            output=str(results),
            parsed=results,
            duration=duration,
            metadata={"action": action}
        )
        
    def _match_patterns(
        self,
        content: str,
        patterns: List[str],
        case_sensitive: bool = False
    ) -> Dict[str, Any]:
        """Match multiple patterns against content."""
        results = {
            "matches": [],
            "count": 0,
            "patterns_matched": []
        }
        
        flags = 0 if case_sensitive else re.IGNORECASE
        
        for pattern in patterns:
            try:
                compiled = re.compile(pattern, flags)
                matches = compiled.findall(content)
                
                if matches:
                    results["matches"].append({
                        "pattern": pattern,
                        "count": len(matches),
                        "matches": matches[:10]  # Limit to first 10
                    })
                    results["count"] += len(matches)
                    results["patterns_matched"].append(pattern)
                    
            except re.error as e:
                results["matches"].append({
                    "pattern": pattern,
                    "error": str(e)
                })
                
        return results
        
    def _extract_matches(
        self,
        content: str,
        patterns: List[str]
    ) -> Dict[str, Any]:
        """Extract all matches with positions."""
        results = {
            "extractions": [],
            "total_count": 0
        }
        
        for pattern in patterns:
            try:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    results["extractions"].append({
                        "pattern": pattern,
                        "match": match.group(),
                        "start": match.start(),
                        "end": match.end(),
                        "groups": match.groups() if match.groups() else None
                    })
                    results["total_count"] += 1
                    
            except re.error:
                continue
                
        return results
        
    def _search_vulnerabilities(
        self,
        content: str,
        vuln_types: List[str]
    ) -> Dict[str, Any]:
        """Search for vulnerability indicators."""
        results = {
            "vulnerabilities_detected": [],
            "findings": [],
            "risk_level": "info"
        }
        
        severity_map = {
            "sql_injection": "high",
            "xss": "medium",
            "command_injection": "critical",
            "path_traversal": "high",
            "lfi_rfi": "high",
            "ssrf": "medium"
        }
        
        max_severity = "info"
        severity_order = ["info", "low", "medium", "high", "critical"]
        
        for vuln_type in vuln_types:
            patterns = self.VULN_PATTERNS.get(vuln_type, [])
            
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        severity = severity_map.get(vuln_type, "medium")
                        
                        results["findings"].append({
                            "type": vuln_type,
                            "severity": severity,
                            "pattern": pattern,
                            "matches": matches[:5],
                            "match_count": len(matches)
                        })
                        
                        if vuln_type not in results["vulnerabilities_detected"]:
                            results["vulnerabilities_detected"].append(vuln_type)
                            
                        # Update max severity
                        if severity_order.index(severity) > severity_order.index(max_severity):
                            max_severity = severity
                            
                except re.error:
                    continue
                    
        results["risk_level"] = max_severity
        return results
        
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse output (not used for this tool)."""
        return {"raw": output}
        
    @classmethod
    def add_vuln_pattern(cls, vuln_type: str, pattern: str) -> None:
        """Add a custom vulnerability pattern."""
        if vuln_type not in cls.VULN_PATTERNS:
            cls.VULN_PATTERNS[vuln_type] = []
        cls.VULN_PATTERNS[vuln_type].append(pattern)
