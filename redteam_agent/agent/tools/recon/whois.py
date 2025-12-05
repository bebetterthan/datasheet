"""
WHOIS Tool
==========

Domain and IP WHOIS lookup tool.
"""

import subprocess
import re
from typing import Dict, Any, Optional
from datetime import datetime

from agent.tools.base import BaseTool, ToolResult, ToolStatus


class WhoisTool(BaseTool):
    """
    WHOIS lookup tool.
    
    Actions:
        - lookup: Basic WHOIS lookup
        - domain_info: Extract domain registration info
        - ip_info: IP address information
    """
    
    name = "whois"
    description = "WHOIS lookup for domain and IP information"
    category = "recon"
    
    actions = ["lookup", "domain_info", "ip_info"]
    timeout = 30
    
    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """Execute WHOIS lookup."""
        params = params or {}
        start_time = datetime.now()
        
        self.validate_params(action, params)
        
        cmd = f"whois {target}"
        
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            duration = (datetime.now() - start_time).total_seconds()
            output = result.stdout
            
            if result.returncode == 0 and output:
                parsed = self.parse_output(output)
                
                return ToolResult(
                    status=ToolStatus.SUCCESS,
                    output=output,
                    parsed=parsed,
                    duration=duration,
                    metadata={"target": target, "action": action}
                )
            else:
                return ToolResult(
                    status=ToolStatus.FAILURE,
                    output=result.stderr or output,
                    error="WHOIS lookup failed",
                    duration=duration
                )
                
        except subprocess.TimeoutExpired:
            return ToolResult(
                status=ToolStatus.TIMEOUT,
                output="",
                error="WHOIS lookup timed out"
            )
        except Exception as e:
            return ToolResult(
                status=ToolStatus.ERROR,
                output="",
                error=str(e)
            )
            
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse WHOIS output."""
        parsed = {
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "name_servers": [],
            "registrant": {},
            "admin": {},
            "tech": {},
            "status": [],
            "raw_sections": {}
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('%') or line.startswith('#'):
                continue
                
            if ':' in line:
                key, _, value = line.partition(':')
                key = key.strip().lower()
                value = value.strip()
                
                if not value:
                    continue
                    
                # Map common fields
                if 'registrar' in key and not parsed["registrar"]:
                    parsed["registrar"] = value
                elif 'creation' in key or 'created' in key:
                    parsed["creation_date"] = value
                elif 'expir' in key:
                    parsed["expiration_date"] = value
                elif 'name server' in key or 'nserver' in key:
                    parsed["name_servers"].append(value)
                elif 'status' in key:
                    parsed["status"].append(value)
                elif 'registrant' in key:
                    parsed["registrant"][key] = value
                elif 'admin' in key:
                    parsed["admin"][key] = value
                elif 'tech' in key:
                    parsed["tech"][key] = value
                    
        return parsed


class DNSTool(BaseTool):
    """
    DNS enumeration tool.
    
    Actions:
        - resolve: Basic DNS resolution
        - enumerate: DNS record enumeration
        - zone_transfer: Attempt zone transfer
    """
    
    name = "dns"
    description = "DNS resolution and enumeration"
    category = "recon"
    
    actions = ["resolve", "enumerate", "zone_transfer", "reverse"]
    timeout = 60
    
    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """Execute DNS operation."""
        params = params or {}
        start_time = datetime.now()
        
        self.validate_params(action, params)
        
        if action == "resolve":
            cmd = f"dig {target} +short"
        elif action == "enumerate":
            # Query multiple record types
            record_types = params.get("types", ["A", "AAAA", "MX", "NS", "TXT", "SOA"])
            results = []
            for rtype in record_types:
                cmd = f"dig {target} {rtype} +short"
                try:
                    result = subprocess.run(
                        cmd, shell=True, capture_output=True,
                        text=True, timeout=10
                    )
                    if result.stdout.strip():
                        results.append(f"{rtype}: {result.stdout.strip()}")
                except:
                    pass
            output = "\n".join(results)
            duration = (datetime.now() - start_time).total_seconds()
            return ToolResult(
                status=ToolStatus.SUCCESS,
                output=output,
                parsed=self.parse_output(output),
                duration=duration
            )
        elif action == "zone_transfer":
            ns = params.get("nameserver", target)
            cmd = f"dig axfr @{ns} {target}"
        elif action == "reverse":
            cmd = f"dig -x {target} +short"
        else:
            cmd = f"dig {target}"
            
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            duration = (datetime.now() - start_time).total_seconds()
            
            return ToolResult(
                status=ToolStatus.SUCCESS if result.returncode == 0 else ToolStatus.FAILURE,
                output=result.stdout,
                parsed=self.parse_output(result.stdout),
                duration=duration,
                error=result.stderr if result.returncode != 0 else None
            )
            
        except subprocess.TimeoutExpired:
            return ToolResult(
                status=ToolStatus.TIMEOUT,
                output="",
                error="DNS operation timed out"
            )
        except Exception as e:
            return ToolResult(
                status=ToolStatus.ERROR,
                output="",
                error=str(e)
            )
            
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse DNS output."""
        parsed = {
            "records": [],
            "addresses": [],
            "nameservers": [],
            "mail_servers": []
        }
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            # Parse different record types
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', line):
                parsed["addresses"].append(line)
            elif line.startswith("A:"):
                parsed["records"].append({"type": "A", "value": line[2:].strip()})
            elif line.startswith("MX:"):
                parsed["mail_servers"].append(line[3:].strip())
            elif line.startswith("NS:"):
                parsed["nameservers"].append(line[3:].strip())
            else:
                parsed["records"].append({"raw": line})
                
        return parsed
