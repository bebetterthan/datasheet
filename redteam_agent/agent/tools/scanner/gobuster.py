"""
Gobuster Tool
=============

Directory and DNS brute-forcing tool.
"""

import subprocess
import re
from typing import Dict, Any, Optional, List
from datetime import datetime

from agent.tools.base import BaseTool, ToolResult, ToolStatus


class GobusterTool(BaseTool):
    """
    Gobuster brute-force tool.
    
    Actions:
        - dir: Directory brute-force
        - dns: DNS subdomain enumeration
        - vhost: Virtual host enumeration
    """
    
    name = "gobuster"
    description = "Directory and subdomain brute-forcing"
    category = "scanner"
    
    actions = ["dir", "dns", "vhost"]
    timeout = 1200  # 20 minutes
    
    # Default wordlists
    DEFAULT_WORDLISTS = {
        "dir": "/usr/share/wordlists/dirb/common.txt",
        "dns": "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "vhost": "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Gobuster tool."""
        super().__init__(config)
        self.gobuster_path = self.config.get("path", "gobuster")
        
    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """
        Execute gobuster scan.
        
        Args:
            action: Scan mode (dir, dns, vhost)
            target: Target URL/domain
            params:
                - wordlist: Path to wordlist
                - extensions: File extensions for dir mode
                - threads: Number of threads
                - status_codes: HTTP status codes to include
                
        Returns:
            ToolResult with findings
        """
        params = params or {}
        start_time = datetime.now()
        
        self.validate_params(action, params)
        
        # Get wordlist
        wordlist = params.get("wordlist", self.DEFAULT_WORDLISTS.get(action, ""))
        if not wordlist:
            return ToolResult(
                status=ToolStatus.ERROR,
                output="",
                error="No wordlist specified"
            )
            
        # Build command
        cmd_parts = [self.gobuster_path, action]
        
        if action == "dir":
            # Ensure target has protocol
            if not target.startswith("http"):
                target = f"http://{target}"
            cmd_parts.extend(["-u", target, "-w", wordlist])
            
            # Extensions
            if params.get("extensions"):
                cmd_parts.extend(["-x", params["extensions"]])
                
            # Status codes
            status_codes = params.get("status_codes", "200,204,301,302,307,401,403")
            cmd_parts.extend(["-s", status_codes])
            
        elif action == "dns":
            cmd_parts.extend(["-d", target, "-w", wordlist])
            
        elif action == "vhost":
            if not target.startswith("http"):
                target = f"http://{target}"
            cmd_parts.extend(["-u", target, "-w", wordlist])
            
        # Common options
        threads = params.get("threads", 10)
        cmd_parts.extend(["-t", str(threads)])
        
        # No color for easier parsing
        cmd_parts.append("--no-color")
        
        # Don't print progress
        cmd_parts.append("-q")
        
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
            
            parsed = self.parse_output(result.stdout, action)
            
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
                    "wordlist": wordlist,
                    "found_count": len(parsed.get("found", []))
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
            
    def parse_output(self, output: str, mode: str) -> Dict[str, Any]:
        """Parse gobuster output."""
        parsed = {
            "found": [],
            "by_status": {},
            "directories": [],
            "files": [],
            "subdomains": []
        }
        
        for line in output.strip().split('\n'):
            if not line:
                continue
                
            if mode == "dir":
                # Parse directory results
                # Format: /path (Status: 200) [Size: 1234]
                match = re.match(r'^(/.+?)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?', line)
                if match:
                    path = match.group(1)
                    status = match.group(2)
                    size = match.group(3) if match.group(3) else "0"
                    
                    entry = {
                        "path": path,
                        "status": status,
                        "size": size
                    }
                    
                    parsed["found"].append(entry)
                    
                    # Categorize
                    if '.' in path.split('/')[-1]:
                        parsed["files"].append(path)
                    else:
                        parsed["directories"].append(path)
                        
                    # Count by status
                    parsed["by_status"][status] = parsed["by_status"].get(status, 0) + 1
                    
            elif mode == "dns":
                # Parse DNS results
                # Format: Found: subdomain.example.com
                if line.startswith("Found:"):
                    subdomain = line.replace("Found:", "").strip()
                    parsed["found"].append({"subdomain": subdomain})
                    parsed["subdomains"].append(subdomain)
                    
            elif mode == "vhost":
                # Parse vhost results
                # Format: Found: vhost.example.com (Status: 200) [Size: 1234]
                match = re.match(r'^Found:\s*(.+?)\s+\(Status:\s*(\d+)\)', line)
                if match:
                    vhost = match.group(1)
                    status = match.group(2)
                    parsed["found"].append({"vhost": vhost, "status": status})
                    
        return parsed
