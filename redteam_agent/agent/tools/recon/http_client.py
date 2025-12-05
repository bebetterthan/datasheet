"""
HTTP Client Tool
================

HTTP probing and request tool for reconnaissance.
"""

import subprocess
import re
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from urllib.parse import urlparse

from agent.tools.base import BaseTool, ToolResult, ToolStatus


class HTTPClientTool(BaseTool):
    """
    HTTP client tool for probing and requests.
    
    Actions:
        - probe: Check if URL is alive
        - get: GET request
        - post: POST request
        - headers: Get response headers
        - follow_redirects: Follow redirect chain
    """
    
    name = "http_client"
    description = "HTTP probing and request tool"
    category = "recon"
    
    actions = [
        "probe",
        "get",
        "post",
        "headers",
        "follow_redirects"
    ]
    
    timeout = 30
    
    # Default headers
    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5"
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize HTTP client tool."""
        super().__init__(config)
        self.verify_ssl = self.config.get("verify_ssl", True)
        
    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """
        Execute HTTP operation.
        
        Args:
            action: HTTP action
            target: Target URL
            params:
                - headers: Custom headers
                - data: POST data
                - timeout: Request timeout
                - follow_redirects: Whether to follow redirects
                
        Returns:
            ToolResult with response data
        """
        params = params or {}
        start_time = datetime.now()
        
        self.validate_params(action, params)
        
        # Ensure URL has protocol
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
            
        # Build curl command
        cmd_parts = ["curl", "-s", "-w", '"%{http_code}|%{time_total}|%{redirect_url}"']
        
        # Add headers
        headers = {**self.DEFAULT_HEADERS, **params.get("headers", {})}
        for key, value in headers.items():
            cmd_parts.extend(["-H", f'"{key}: {value}"'])
            
        # SSL verification
        if not self.verify_ssl:
            cmd_parts.append("-k")
            
        # Action-specific options
        if action == "probe":
            cmd_parts.extend(["-o", "/dev/null", "-I"])
        elif action == "headers":
            cmd_parts.append("-I")
        elif action == "get":
            pass  # Default behavior
        elif action == "post":
            cmd_parts.append("-X POST")
            if "data" in params:
                cmd_parts.extend(["-d", f'"{params["data"]}"'])
        elif action == "follow_redirects":
            cmd_parts.extend(["-L", "--max-redirs", "10"])
            
        # Timeout
        timeout = params.get("timeout", self.timeout)
        cmd_parts.extend(["--connect-timeout", str(timeout), "-m", str(timeout)])
        
        # Add URL
        cmd_parts.append(f'"{target}"')
        
        cmd = " ".join(cmd_parts)
        
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout + 5
            )
            
            duration = (datetime.now() - start_time).total_seconds()
            
            # Parse output
            parsed = self._parse_curl_output(result.stdout, result.stderr, target)
            
            status = ToolStatus.SUCCESS if parsed.get("status_code", 0) > 0 else ToolStatus.FAILURE
            
            return ToolResult(
                status=status,
                output=result.stdout,
                parsed=parsed,
                duration=duration,
                metadata={
                    "url": target,
                    "action": action,
                    "status_code": parsed.get("status_code")
                }
            )
            
        except subprocess.TimeoutExpired:
            return ToolResult(
                status=ToolStatus.TIMEOUT,
                output="",
                error=f"Request timed out after {timeout}s",
                duration=timeout
            )
        except Exception as e:
            return ToolResult(
                status=ToolStatus.ERROR,
                output="",
                error=str(e)
            )
            
    def _parse_curl_output(
        self,
        stdout: str,
        stderr: str,
        url: str
    ) -> Dict[str, Any]:
        """Parse curl output."""
        parsed = {
            "url": url,
            "status_code": 0,
            "response_time": 0,
            "redirect_url": None,
            "headers": {},
            "body": "",
            "server": None,
            "content_type": None,
            "content_length": 0
        }
        
        # Extract status info from -w output
        # Format: "status_code|time|redirect_url"
        status_match = re.search(r'"?(\d{3})\|([\d.]+)\|([^"]*)"?$', stdout)
        if status_match:
            parsed["status_code"] = int(status_match.group(1))
            parsed["response_time"] = float(status_match.group(2))
            parsed["redirect_url"] = status_match.group(3) or None
            
            # Remove the status line from output
            stdout = stdout[:status_match.start()].strip()
            
        # Parse headers if present
        if stdout.startswith("HTTP/"):
            header_section, _, body = stdout.partition("\r\n\r\n")
            if not body:
                header_section, _, body = stdout.partition("\n\n")
                
            parsed["body"] = body
            
            # Parse individual headers
            for line in header_section.split('\n'):
                if ':' in line:
                    key, _, value = line.partition(':')
                    key = key.strip().lower()
                    value = value.strip()
                    parsed["headers"][key] = value
                    
                    # Extract common fields
                    if key == "server":
                        parsed["server"] = value
                    elif key == "content-type":
                        parsed["content_type"] = value
                    elif key == "content-length":
                        try:
                            parsed["content_length"] = int(value)
                        except:
                            pass
        else:
            parsed["body"] = stdout
            
        return parsed
        
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse raw output."""
        return {"raw": output}


class TechDetectorTool(BaseTool):
    """
    Technology detection tool.
    
    Detects technologies, frameworks, and libraries used by a target.
    """
    
    name = "tech_detector"
    description = "Detect technologies and frameworks"
    category = "recon"
    
    actions = ["detect", "fingerprint"]
    timeout = 60
    
    # Technology signatures
    SIGNATURES = {
        # Server signatures
        "nginx": {"headers": ["server: nginx"], "patterns": []},
        "apache": {"headers": ["server: apache"], "patterns": []},
        "iis": {"headers": ["server: microsoft-iis"], "patterns": []},
        "cloudflare": {"headers": ["server: cloudflare", "cf-ray:"], "patterns": []},
        
        # Frameworks
        "wordpress": {"headers": [], "patterns": [r'wp-content/', r'wp-includes/', r'/wp-json/']},
        "drupal": {"headers": ["x-drupal-cache", "x-generator: drupal"], "patterns": [r'/sites/default/', r'Drupal\.settings']},
        "joomla": {"headers": [], "patterns": [r'/administrator/', r'/components/', r'/modules/']},
        "magento": {"headers": [], "patterns": [r'Mage\.Cookies', r'/skin/frontend/', r'magento']},
        "shopify": {"headers": [], "patterns": [r'cdn\.shopify\.com', r'shopify\.com']},
        
        # JavaScript frameworks
        "react": {"headers": [], "patterns": [r'react\.', r'_reactRoot', r'__NEXT_DATA__']},
        "vue": {"headers": [], "patterns": [r'vue\.', r'__vue__', r'Vue\.']},
        "angular": {"headers": [], "patterns": [r'ng-version', r'angular\.', r'ng-app']},
        "jquery": {"headers": [], "patterns": [r'jquery', r'jQuery']},
        
        # Analytics
        "google_analytics": {"headers": [], "patterns": [r'google-analytics\.com', r'gtag\(', r'ga\(']},
        "google_tag_manager": {"headers": [], "patterns": [r'googletagmanager\.com']},
        
        # CDN
        "cloudfront": {"headers": ["x-amz-cf-id", "via: .* cloudfront"], "patterns": []},
        "akamai": {"headers": ["x-akamai-"], "patterns": []},
    }
    
    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """Execute technology detection."""
        params = params or {}
        start_time = datetime.now()
        
        self.validate_params(action, params)
        
        # Get HTTP response first
        http_tool = HTTPClientTool()
        response = http_tool.execute("get", target, params)
        
        if response.status != ToolStatus.SUCCESS:
            return response
            
        # Detect technologies
        detected = self._detect_technologies(
            response.parsed.get("headers", {}),
            response.parsed.get("body", "")
        )
        
        duration = (datetime.now() - start_time).total_seconds()
        
        return ToolResult(
            status=ToolStatus.SUCCESS,
            output=str(detected),
            parsed={
                "technologies": detected,
                "count": len(detected),
                "url": target
            },
            duration=duration,
            metadata={"action": action, "target": target}
        )
        
    def _detect_technologies(
        self,
        headers: Dict[str, str],
        body: str
    ) -> List[Dict[str, Any]]:
        """Detect technologies from headers and body."""
        detected = []
        headers_str = "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()
        body_lower = body.lower()
        
        for tech, signatures in self.SIGNATURES.items():
            confidence = 0
            evidence = []
            
            # Check headers
            for header_sig in signatures.get("headers", []):
                if header_sig.lower() in headers_str:
                    confidence += 50
                    evidence.append(f"Header: {header_sig}")
                    
            # Check body patterns
            for pattern in signatures.get("patterns", []):
                if re.search(pattern, body, re.IGNORECASE):
                    confidence += 30
                    evidence.append(f"Pattern: {pattern}")
                    
            if confidence > 0:
                detected.append({
                    "technology": tech,
                    "confidence": min(confidence, 100),
                    "evidence": evidence
                })
                
        # Sort by confidence
        detected.sort(key=lambda x: x["confidence"], reverse=True)
        
        return detected
        
    def parse_output(self, output: str) -> Dict[str, Any]:
        return {"raw": output}
