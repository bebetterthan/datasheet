"""
FFUF Tool
=========

Fast web fuzzer for directory/parameter fuzzing.
"""

import subprocess
import json
import re
from typing import Dict, Any, Optional, List
from datetime import datetime

from agent.tools.base import BaseTool, ToolResult, ToolStatus


class FFufTool(BaseTool):
    """
    FFUF fuzzing tool.
    
    Actions:
        - dir: Directory fuzzing
        - param: Parameter fuzzing
        - vhost: Virtual host fuzzing
        - header: Header fuzzing
    """
    
    name = "ffuf"
    description = "Fast web fuzzer for directories, parameters, and vhosts"
    category = "scanner"
    
    actions = ["dir", "param", "vhost", "header", "custom"]
    timeout = 1200  # 20 minutes
    
    # Default wordlists
    DEFAULT_WORDLISTS = {
        "dir": "/usr/share/wordlists/dirb/common.txt",
        "param": "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt",
        "vhost": "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize FFUF tool."""
        super().__init__(config)
        self.ffuf_path = self.config.get("path", "ffuf")
        
    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """
        Execute FFUF fuzzing.
        
        Args:
            action: Fuzzing mode
            target: Target URL (use FUZZ keyword for fuzzing point)
            params:
                - wordlist: Path to wordlist
                - threads: Number of threads
                - rate: Requests per second
                - mc: Match HTTP codes
                - fc: Filter HTTP codes
                - ms: Match response size
                - fs: Filter response size
                - extensions: File extensions for dir mode
                
        Returns:
            ToolResult with findings
        """
        params = params or {}
        start_time = datetime.now()
        
        self.validate_params(action, params)
        
        # Ensure URL has protocol
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
            
        # Get wordlist
        wordlist = params.get("wordlist", self.DEFAULT_WORDLISTS.get(action, ""))
        if not wordlist:
            return ToolResult(
                status=ToolStatus.ERROR,
                output="",
                error="No wordlist specified"
            )
            
        # Build command
        cmd_parts = [self.ffuf_path, "-json", "-silent"]
        
        # Configure based on action
        if action == "dir":
            # Add FUZZ to URL if not present
            if "FUZZ" not in target:
                target = target.rstrip('/') + "/FUZZ"
            cmd_parts.extend(["-u", target, "-w", wordlist])
            
            # Add extensions
            if params.get("extensions"):
                cmd_parts.extend(["-e", params["extensions"]])
                
        elif action == "param":
            # Add FUZZ to parameter
            if "FUZZ" not in target:
                target = target + "?FUZZ=test"
            cmd_parts.extend(["-u", target, "-w", wordlist])
            
        elif action == "vhost":
            cmd_parts.extend(["-u", target, "-w", wordlist])
            cmd_parts.extend(["-H", "Host: FUZZ." + urlparse(target).netloc])
            
        elif action == "header":
            header_name = params.get("header_name", "X-Custom-Header")
            cmd_parts.extend(["-u", target, "-w", wordlist])
            cmd_parts.extend(["-H", f"{header_name}: FUZZ"])
            
        elif action == "custom":
            cmd_parts.extend(["-u", target, "-w", wordlist])
            
        # Common options
        threads = params.get("threads", 40)
        cmd_parts.extend(["-t", str(threads)])
        
        if params.get("rate"):
            cmd_parts.extend(["-rate", str(params["rate"])])
            
        # Status code filters
        if params.get("mc"):
            cmd_parts.extend(["-mc", params["mc"]])
        else:
            cmd_parts.extend(["-mc", "200,204,301,302,307,401,403,405"])
            
        if params.get("fc"):
            cmd_parts.extend(["-fc", params["fc"]])
            
        # Size filters
        if params.get("ms"):
            cmd_parts.extend(["-ms", params["ms"]])
        if params.get("fs"):
            cmd_parts.extend(["-fs", params["fs"]])
            
        # Timeout
        cmd_parts.extend(["-timeout", str(params.get("timeout", 10))])
        
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
            
            # Parse JSON output
            parsed = self.parse_output(result.stdout)
            
            return ToolResult(
                status=ToolStatus.SUCCESS if result.returncode == 0 else ToolStatus.FAILURE,
                output=result.stdout,
                parsed=parsed,
                duration=duration,
                error=result.stderr if result.returncode != 0 else None,
                metadata={
                    "command": cmd,
                    "action": action,
                    "target": target,
                    "found_count": len(parsed.get("results", []))
                }
            )
            
        except subprocess.TimeoutExpired:
            return ToolResult(
                status=ToolStatus.TIMEOUT,
                output="",
                error=f"Fuzzing timed out after {self.timeout}s",
                duration=self.timeout
            )
        except Exception as e:
            return ToolResult(
                status=ToolStatus.ERROR,
                output="",
                error=str(e)
            )
            
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse FFUF JSON output."""
        parsed = {
            "results": [],
            "by_status": {},
            "total": 0,
            "config": {}
        }
        
        for line in output.strip().split('\n'):
            if not line:
                continue
                
            try:
                data = json.loads(line)
                
                # Check if it's a result line
                if "input" in data and "status" in data:
                    result = {
                        "input": data.get("input", {}).get("FUZZ", ""),
                        "url": data.get("url", ""),
                        "status": data.get("status", 0),
                        "length": data.get("length", 0),
                        "words": data.get("words", 0),
                        "lines": data.get("lines", 0),
                        "content_type": data.get("content-type", ""),
                        "redirect_location": data.get("redirectlocation", "")
                    }
                    
                    parsed["results"].append(result)
                    parsed["total"] += 1
                    
                    # Count by status
                    status = str(result["status"])
                    parsed["by_status"][status] = parsed["by_status"].get(status, 0) + 1
                    
                elif "config" in data:
                    parsed["config"] = data.get("config", {})
                    
            except json.JSONDecodeError:
                continue
                
        return parsed


# Import urlparse for vhost action
from urllib.parse import urlparse
