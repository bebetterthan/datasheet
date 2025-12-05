"""
Nmap Tool
=========

Network scanner and port discovery tool.
"""

import subprocess
import shlex
import re
from typing import Dict, Any, Optional, List
from datetime import datetime

from agent.tools.base import BaseTool, ToolResult, ToolStatus


class NmapTool(BaseTool):
    """
    Nmap network scanner tool.
    
    Actions:
        - quick_scan: Fast scan of common ports
        - full_scan: Comprehensive scan
        - service_scan: Version detection
        - vuln_scan: Vulnerability scripts
        - stealth_scan: SYN scan (requires root)
    """
    
    name = "nmap"
    description = "Network scanner for port discovery and service detection"
    category = "recon"
    
    actions = [
        "quick_scan",
        "full_scan",
        "service_scan",
        "vuln_scan",
        "stealth_scan",
        "os_detect"
    ]
    
    timeout = 600  # 10 minutes max
    
    # Nmap command templates
    SCAN_TEMPLATES = {
        "quick_scan": "-T4 -F --top-ports 100",
        "full_scan": "-T4 -p- -sV -sC",
        "service_scan": "-sV -sC --version-intensity 5",
        "vuln_scan": "-sV --script vuln",
        "stealth_scan": "-sS -T4 -Pn",
        "os_detect": "-O --osscan-guess"
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Nmap tool."""
        super().__init__(config)
        self.nmap_path = self.config.get("path", "nmap")
        
    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """
        Execute nmap scan.
        
        Args:
            action: Scan type
            target: Target IP/hostname
            params: Additional parameters
                - ports: Specific ports to scan
                - extra_args: Additional nmap arguments
                
        Returns:
            ToolResult with scan results
        """
        params = params or {}
        start_time = datetime.now()
        
        # Validate
        self.validate_params(action, params)
        
        # Build command
        base_args = self.SCAN_TEMPLATES.get(action, "-T4 -F")
        
        # Add specific ports if provided
        if "ports" in params:
            base_args = f"-p {params['ports']} {base_args}"
            
        # Add extra args
        if "extra_args" in params:
            base_args = f"{base_args} {params['extra_args']}"
            
        # Output in XML for easier parsing
        base_args = f"{base_args} -oX -"
        
        cmd = f"{self.nmap_path} {base_args} {shlex.quote(target)}"
        
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
            
            if result.returncode == 0:
                # Parse output
                parsed = self.parse_output(result.stdout)
                
                return ToolResult(
                    status=ToolStatus.SUCCESS,
                    output=result.stdout,
                    parsed=parsed,
                    duration=duration,
                    metadata={
                        "command": cmd,
                        "action": action,
                        "target": target
                    }
                )
            else:
                return ToolResult(
                    status=ToolStatus.FAILURE,
                    output=result.stderr or result.stdout,
                    error=f"Nmap exited with code {result.returncode}",
                    duration=duration,
                    metadata={"command": cmd}
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
        """
        Parse nmap XML output.
        
        Args:
            output: Raw nmap XML output
            
        Returns:
            Parsed scan results
        """
        parsed = {
            "hosts": [],
            "ports": [],
            "services": [],
            "os_matches": [],
            "scripts": []
        }
        
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(output)
            
            for host in root.findall(".//host"):
                host_info = {
                    "status": host.find("status").get("state") if host.find("status") is not None else "unknown",
                    "addresses": [],
                    "hostnames": [],
                    "ports": []
                }
                
                # Get addresses
                for addr in host.findall("address"):
                    host_info["addresses"].append({
                        "addr": addr.get("addr"),
                        "type": addr.get("addrtype")
                    })
                    
                # Get hostnames
                for hostname in host.findall(".//hostname"):
                    host_info["hostnames"].append(hostname.get("name"))
                    
                # Get ports
                for port in host.findall(".//port"):
                    port_info = {
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "state": port.find("state").get("state") if port.find("state") is not None else "unknown"
                    }
                    
                    service = port.find("service")
                    if service is not None:
                        port_info["service"] = {
                            "name": service.get("name"),
                            "product": service.get("product"),
                            "version": service.get("version"),
                            "extrainfo": service.get("extrainfo")
                        }
                        parsed["services"].append(port_info["service"])
                        
                    # Script results
                    for script in port.findall("script"):
                        script_info = {
                            "id": script.get("id"),
                            "output": script.get("output"),
                            "port": port.get("portid")
                        }
                        parsed["scripts"].append(script_info)
                        
                    host_info["ports"].append(port_info)
                    parsed["ports"].append({
                        "port": port_info["port"],
                        "state": port_info["state"],
                        "service": port_info.get("service", {}).get("name")
                    })
                    
                # OS detection
                for os_match in host.findall(".//osmatch"):
                    parsed["os_matches"].append({
                        "name": os_match.get("name"),
                        "accuracy": os_match.get("accuracy")
                    })
                    
                parsed["hosts"].append(host_info)
                
        except ET.ParseError:
            # Fallback to text parsing
            parsed = self._parse_text_output(output)
            
        return parsed
        
    def _parse_text_output(self, output: str) -> Dict[str, Any]:
        """Fallback text parsing for non-XML output."""
        parsed = {
            "hosts": [],
            "ports": [],
            "raw": output
        }
        
        # Extract open ports
        port_pattern = r'(\d+)/(tcp|udp)\s+(\w+)\s+(.+)'
        for match in re.finditer(port_pattern, output):
            parsed["ports"].append({
                "port": match.group(1),
                "protocol": match.group(2),
                "state": match.group(3),
                "service": match.group(4).strip()
            })
            
        return parsed
