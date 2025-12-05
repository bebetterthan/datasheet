"""
Response Analyzer Tool
======================

Analyzes HTTP responses and tool outputs for security issues.
"""

import re
from typing import Dict, Any, Optional, List
from datetime import datetime

from agent.tools.base import BaseTool, ToolResult, ToolStatus


class ResponseAnalyzer(BaseTool):
    """
    Response analyzer for security findings.
    
    Actions:
        - analyze_http: Analyze HTTP response for issues
        - analyze_headers: Security header analysis
        - analyze_cookies: Cookie security analysis
        - find_secrets: Search for exposed secrets/credentials
    """
    
    name = "response_analyzer"
    description = "Analyzes responses for security issues"
    category = "analyzer"
    
    actions = [
        "analyze_http",
        "analyze_headers",
        "analyze_cookies",
        "find_secrets",
        "find_info_disclosure"
    ]
    
    timeout = 60
    
    # Security headers to check
    SECURITY_HEADERS = {
        "strict-transport-security": {
            "name": "HSTS",
            "severity": "medium",
            "description": "HTTP Strict Transport Security"
        },
        "content-security-policy": {
            "name": "CSP",
            "severity": "medium",
            "description": "Content Security Policy"
        },
        "x-frame-options": {
            "name": "X-Frame-Options",
            "severity": "medium",
            "description": "Clickjacking protection"
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options",
            "severity": "low",
            "description": "MIME type sniffing prevention"
        },
        "x-xss-protection": {
            "name": "X-XSS-Protection",
            "severity": "low",
            "description": "XSS filter"
        },
        "referrer-policy": {
            "name": "Referrer-Policy",
            "severity": "low",
            "description": "Controls referrer information"
        },
        "permissions-policy": {
            "name": "Permissions-Policy",
            "severity": "low",
            "description": "Browser feature permissions"
        }
    }
    
    # Patterns for secret detection
    SECRET_PATTERNS = {
        "aws_key": r'AKIA[0-9A-Z]{16}',
        "aws_secret": r'[0-9a-zA-Z/+]{40}',
        "github_token": r'ghp_[0-9a-zA-Z]{36}',
        "slack_token": r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
        "private_key": r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
        "api_key": r'(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
        "password": r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{8,})',
        "jwt": r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*',
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "ip_address": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        "internal_url": r'https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[:/]?'
    }
    
    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """
        Execute analysis.
        
        Args:
            action: Analysis type
            target: Content to analyze (raw response or URL)
            params:
                - headers: Dict of HTTP headers
                - body: Response body
                - cookies: List of cookie strings
                
        Returns:
            ToolResult with findings
        """
        params = params or {}
        start_time = datetime.now()
        
        self.validate_params(action, params)
        
        findings = []
        
        if action == "analyze_http":
            findings = self._analyze_http(params)
        elif action == "analyze_headers":
            findings = self._analyze_headers(params.get("headers", {}))
        elif action == "analyze_cookies":
            findings = self._analyze_cookies(params.get("cookies", []))
        elif action == "find_secrets":
            content = params.get("body", target)
            findings = self._find_secrets(content)
        elif action == "find_info_disclosure":
            content = params.get("body", target)
            findings = self._find_info_disclosure(content)
            
        duration = (datetime.now() - start_time).total_seconds()
        
        parsed = {
            "findings": findings,
            "count": len(findings),
            "by_severity": self._count_by_severity(findings)
        }
        
        return ToolResult(
            status=ToolStatus.SUCCESS,
            output=str(findings),
            parsed=parsed,
            duration=duration,
            metadata={"action": action, "findings_count": len(findings)}
        )
        
    def _analyze_http(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Full HTTP response analysis."""
        findings = []
        
        # Analyze headers
        if "headers" in params:
            findings.extend(self._analyze_headers(params["headers"]))
            
        # Analyze cookies
        if "cookies" in params:
            findings.extend(self._analyze_cookies(params["cookies"]))
            
        # Search for secrets in body
        if "body" in params:
            findings.extend(self._find_secrets(params["body"]))
            findings.extend(self._find_info_disclosure(params["body"]))
            
        return findings
        
    def _analyze_headers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Analyze HTTP headers for security issues."""
        findings = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Check for missing security headers
        for header, info in self.SECURITY_HEADERS.items():
            if header not in headers_lower:
                findings.append({
                    "type": "missing_security_header",
                    "severity": info["severity"],
                    "description": f"Missing {info['name']} header: {info['description']}",
                    "evidence": f"Header '{header}' not present",
                    "recommendation": f"Add {info['name']} header"
                })
                
        # Check for information disclosure headers
        info_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
        for header in info_headers:
            if header in headers_lower:
                findings.append({
                    "type": "information_disclosure",
                    "severity": "low",
                    "description": f"Server information disclosed via {header} header",
                    "evidence": f"{header}: {headers_lower[header]}",
                    "recommendation": "Remove or obfuscate server version headers"
                })
                
        return findings
        
    def _analyze_cookies(self, cookies: List[str]) -> List[Dict[str, Any]]:
        """Analyze cookies for security issues."""
        findings = []
        
        for cookie in cookies:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split('=')[0] if '=' in cookie else cookie
            
            issues = []
            
            if "secure" not in cookie_lower:
                issues.append("missing Secure flag")
            if "httponly" not in cookie_lower:
                issues.append("missing HttpOnly flag")
            if "samesite" not in cookie_lower:
                issues.append("missing SameSite attribute")
                
            if issues:
                findings.append({
                    "type": "insecure_cookie",
                    "severity": "medium",
                    "description": f"Cookie '{cookie_name}' has security issues",
                    "evidence": f"Issues: {', '.join(issues)}",
                    "recommendation": "Add Secure, HttpOnly, and SameSite=Strict flags"
                })
                
        return findings
        
    def _find_secrets(self, content: str) -> List[Dict[str, Any]]:
        """Search for exposed secrets in content."""
        findings = []
        
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            for match in matches:
                # Mask the actual value
                if isinstance(match, tuple):
                    match = match[0] if match else ""
                masked = match[:10] + "..." + match[-4:] if len(match) > 14 else match[:4] + "..."
                
                findings.append({
                    "type": f"exposed_{secret_type}",
                    "severity": "high" if secret_type in ["private_key", "aws_key", "password"] else "medium",
                    "description": f"Potential {secret_type.replace('_', ' ')} exposed",
                    "evidence": f"Found pattern matching {secret_type}: {masked}",
                    "recommendation": "Remove exposed credentials and rotate if necessary"
                })
                
        return findings
        
    def _find_info_disclosure(self, content: str) -> List[Dict[str, Any]]:
        """Find information disclosure issues."""
        findings = []
        
        # Stack traces
        stack_patterns = [
            (r'Traceback \(most recent call last\)', "Python traceback"),
            (r'at .+\(.+:\d+\)', "Java/JavaScript stack trace"),
            (r'Stack trace:', "Generic stack trace"),
            (r'Fatal error:', "Fatal error message"),
            (r'Warning: .+ in .+ on line \d+', "PHP warning/error")
        ]
        
        for pattern, trace_type in stack_patterns:
            if re.search(pattern, content):
                findings.append({
                    "type": "stack_trace_disclosure",
                    "severity": "medium",
                    "description": f"{trace_type} exposed in response",
                    "evidence": f"Pattern found: {pattern}",
                    "recommendation": "Disable debug mode and error display in production"
                })
                
        # Version disclosure
        version_patterns = [
            (r'PHP/[\d.]+', "PHP version"),
            (r'Apache/[\d.]+', "Apache version"),
            (r'nginx/[\d.]+', "Nginx version"),
            (r'Microsoft-IIS/[\d.]+', "IIS version")
        ]
        
        for pattern, version_type in version_patterns:
            match = re.search(pattern, content)
            if match:
                findings.append({
                    "type": "version_disclosure",
                    "severity": "low",
                    "description": f"{version_type} disclosed",
                    "evidence": match.group(),
                    "recommendation": "Hide server version information"
                })
                
        return findings
        
    def _count_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {}
        for f in findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts
        
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse output (not used for this tool)."""
        return {"raw": output}
