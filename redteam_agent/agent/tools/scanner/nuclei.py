"""
Nuclei Tool
===========

Template-based vulnerability scanner.
"""

import subprocess
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

from agent.tools.base import BaseTool, ToolResult, ToolStatus


class NucleiTool(BaseTool):
    """
    Nuclei vulnerability scanner.
    
    Actions:
        - scan: Run nuclei scan with templates
        - scan_cve: Scan for specific CVEs
        - scan_tech: Technology-specific scan
        - scan_custom: Custom template scan
    """
    
    name = "nuclei"
    description = "Template-based vulnerability scanner"
    category = "scanner"
    
    actions = [
        "scan",
        "scan_cve",
        "scan_tech",
        "scan_custom",
        "scan_severity"
    ]
    
    timeout = 1800  # 30 minutes
    
    # Severity levels
    SEVERITIES = ["info", "low", "medium", "high", "critical"]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Nuclei tool."""
        super().__init__(config)
        self.nuclei_path = self.config.get("path", "nuclei")
        self.templates_path = self.config.get(
            "templates_path",
            "~/nuclei-templates"
        )
        
    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """
        Execute nuclei scan.
        
        Args:
            action: Scan type
            target: Target URL/IP
            params:
                - templates: List of template tags
                - severity: Minimum severity level
                - cve: Specific CVE to scan for
                - rate_limit: Requests per second
                
        Returns:
            ToolResult with findings
        """
        params = params or {}
        start_time = datetime.now()
        
        self.validate_params(action, params)
        
        # Build command
        cmd_parts = [self.nuclei_path, "-u", target, "-j"]  # JSON output
        
        # Action-specific options
        if action == "scan":
            # Default scan
            tags = params.get("tags", ["cve", "exposure", "misconfig"])
            cmd_parts.extend(["-t", ",".join(tags)])
            
        elif action == "scan_cve":
            cve = params.get("cve")
            if cve:
                cmd_parts.extend(["-t", f"cves/{cve}"])
            else:
                cmd_parts.extend(["-t", "cves/"])
                
        elif action == "scan_tech":
            tech = params.get("technology", "").lower()
            cmd_parts.extend(["-t", f"technologies/{tech}"])
            
        elif action == "scan_custom":
            template_path = params.get("template")
            if template_path:
                cmd_parts.extend(["-t", template_path])
                
        elif action == "scan_severity":
            severity = params.get("severity", "medium")
            cmd_parts.extend(["-s", severity])
            
        # Common options
        if params.get("severity"):
            cmd_parts.extend(["-s", params["severity"]])
        if params.get("rate_limit"):
            cmd_parts.extend(["-rl", str(params["rate_limit"])])
        if params.get("timeout"):
            cmd_parts.extend(["-timeout", str(params["timeout"])])
            
        # Disable update checks for cleaner output
        cmd_parts.append("-duc")
        
        cmd = " ".join(cmd_parts)
        self.logger.info(f"Executing: {cmd}")
        
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            duration = (datetime.now() - start_time).total_seconds()
            
            # Parse JSON lines output
            parsed = self.parse_output(result.stdout)
            
            return ToolResult(
                status=ToolStatus.SUCCESS if not result.returncode else ToolStatus.FAILURE,
                output=result.stdout,
                parsed=parsed,
                duration=duration,
                error=result.stderr if result.returncode else None,
                metadata={
                    "command": cmd,
                    "action": action,
                    "target": target,
                    "findings_count": len(parsed.get("findings", []))
                }
            )
            
        except subprocess.TimeoutExpired:
            return ToolResult(
                status=ToolStatus.TIMEOUT,
                output="",
                error=f"Scan timed out after {self.timeout}s",
                duration=self.timeout
            )
        except Exception as e:
            return ToolResult(
                status=ToolStatus.ERROR,
                output="",
                error=str(e)
            )
            
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse nuclei JSON output."""
        parsed = {
            "findings": [],
            "by_severity": {},
            "by_type": {},
            "templates_matched": []
        }
        
        for line in output.strip().split('\n'):
            if not line:
                continue
                
            try:
                finding = json.loads(line)
                
                # Extract key information
                processed = {
                    "template_id": finding.get("template-id", ""),
                    "name": finding.get("info", {}).get("name", ""),
                    "severity": finding.get("info", {}).get("severity", "info"),
                    "type": finding.get("type", ""),
                    "host": finding.get("host", ""),
                    "matched_at": finding.get("matched-at", ""),
                    "description": finding.get("info", {}).get("description", ""),
                    "reference": finding.get("info", {}).get("reference", []),
                    "extracted": finding.get("extracted-results", []),
                    "curl_command": finding.get("curl-command", ""),
                    "tags": finding.get("info", {}).get("tags", [])
                }
                
                parsed["findings"].append(processed)
                
                # Count by severity
                sev = processed["severity"]
                parsed["by_severity"][sev] = parsed["by_severity"].get(sev, 0) + 1
                
                # Count by type
                ftype = processed["type"]
                parsed["by_type"][ftype] = parsed["by_type"].get(ftype, 0) + 1
                
                # Track templates
                if processed["template_id"] not in parsed["templates_matched"]:
                    parsed["templates_matched"].append(processed["template_id"])
                    
            except json.JSONDecodeError:
                continue
                
        return parsed
