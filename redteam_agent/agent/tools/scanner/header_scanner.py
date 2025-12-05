"""
Header Scanner Tool
===================

Security header analysis tool.
"""

import subprocess
import re
from typing import Dict, Any, Optional, List
from datetime import datetime

from agent.tools.base import BaseTool, ToolResult, ToolStatus


class HeaderScannerTool(BaseTool):
    """
    HTTP security header scanner.
    
    Actions:
        - scan: Full security header scan
        - check_csp: Analyze CSP header
        - check_hsts: Analyze HSTS header
        - check_cors: Analyze CORS headers
    """
    
    name = "header_scanner"
    description = "Scans and analyzes HTTP security headers"
    category = "scanner"
    
    actions = ["scan", "check_csp", "check_hsts", "check_cors", "check_cookies"]
    timeout = 30
    
    # Security headers to check
    SECURITY_HEADERS = {
        "strict-transport-security": {
            "name": "HSTS",
            "severity": "high",
            "description": "Forces HTTPS connections",
            "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
        },
        "content-security-policy": {
            "name": "CSP",
            "severity": "high",
            "description": "Controls resource loading",
            "recommendation": "Implement a strict CSP policy"
        },
        "x-frame-options": {
            "name": "X-Frame-Options",
            "severity": "medium",
            "description": "Prevents clickjacking",
            "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options",
            "severity": "low",
            "description": "Prevents MIME type sniffing",
            "recommendation": "Add: X-Content-Type-Options: nosniff"
        },
        "x-xss-protection": {
            "name": "X-XSS-Protection",
            "severity": "low",
            "description": "XSS filter (deprecated but still useful)",
            "recommendation": "Add: X-XSS-Protection: 1; mode=block"
        },
        "referrer-policy": {
            "name": "Referrer-Policy",
            "severity": "low",
            "description": "Controls referrer information",
            "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
        },
        "permissions-policy": {
            "name": "Permissions-Policy",
            "severity": "low",
            "description": "Controls browser features",
            "recommendation": "Implement Permissions-Policy to restrict features"
        },
        "cross-origin-opener-policy": {
            "name": "COOP",
            "severity": "medium",
            "description": "Isolates browsing context",
            "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin"
        },
        "cross-origin-resource-policy": {
            "name": "CORP",
            "severity": "medium",
            "description": "Protects resources from cross-origin requests",
            "recommendation": "Add: Cross-Origin-Resource-Policy: same-origin"
        },
        "cross-origin-embedder-policy": {
            "name": "COEP",
            "severity": "medium",
            "description": "Requires CORS for subresources",
            "recommendation": "Add: Cross-Origin-Embedder-Policy: require-corp"
        }
    }
    
    # Dangerous CSP directives
    UNSAFE_CSP = [
        ("unsafe-inline", "high", "Allows inline scripts/styles"),
        ("unsafe-eval", "high", "Allows eval() and similar"),
        ("data:", "medium", "Allows data: URIs"),
        ("*", "high", "Wildcard allows any source"),
        ("'none'", "info", "Blocks all sources (may be intentional)")
    ]
    
    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """
        Execute header scan.
        
        Args:
            action: Scan action
            target: Target URL
            params:
                - follow_redirects: Follow redirects
                - include_cookies: Analyze cookie security
                
        Returns:
            ToolResult with findings
        """
        params = params or {}
        start_time = datetime.now()
        
        self.validate_params(action, params)
        
        # Ensure URL has protocol
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
            
        # Get headers using curl
        cmd = f'curl -s -I -L --connect-timeout {self.timeout} "{target}"'
        
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout + 5
            )
            
            duration = (datetime.now() - start_time).total_seconds()
            
            # Parse headers
            headers = self._parse_headers(result.stdout)
            
            # Analyze based on action
            if action == "scan":
                findings = self._full_scan(headers)
            elif action == "check_csp":
                findings = self._analyze_csp(headers.get("content-security-policy", ""))
            elif action == "check_hsts":
                findings = self._analyze_hsts(headers.get("strict-transport-security", ""))
            elif action == "check_cors":
                findings = self._analyze_cors(headers)
            elif action == "check_cookies":
                findings = self._analyze_cookies(headers.get("set-cookie", []))
            else:
                findings = []
                
            parsed = {
                "url": target,
                "headers": headers,
                "findings": findings,
                "score": self._calculate_score(findings),
                "missing_headers": [f["header"] for f in findings if f.get("type") == "missing"]
            }
            
            return ToolResult(
                status=ToolStatus.SUCCESS,
                output=result.stdout,
                parsed=parsed,
                duration=duration,
                metadata={
                    "action": action,
                    "target": target,
                    "findings_count": len(findings)
                }
            )
            
        except subprocess.TimeoutExpired:
            return ToolResult(
                status=ToolStatus.TIMEOUT,
                output="",
                error=f"Request timed out after {self.timeout}s"
            )
        except Exception as e:
            return ToolResult(
                status=ToolStatus.ERROR,
                output="",
                error=str(e)
            )
            
    def _parse_headers(self, raw: str) -> Dict[str, Any]:
        """Parse raw headers into dictionary."""
        headers = {}
        cookies = []
        
        for line in raw.split('\n'):
            line = line.strip()
            if ':' in line:
                key, _, value = line.partition(':')
                key = key.strip().lower()
                value = value.strip()
                
                if key == "set-cookie":
                    cookies.append(value)
                else:
                    headers[key] = value
                    
        if cookies:
            headers["set-cookie"] = cookies
            
        return headers
        
    def _full_scan(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Perform full security header scan."""
        findings = []
        
        # Check for missing headers
        for header, info in self.SECURITY_HEADERS.items():
            if header not in headers:
                findings.append({
                    "type": "missing",
                    "header": info["name"],
                    "severity": info["severity"],
                    "description": f"Missing {info['name']}: {info['description']}",
                    "recommendation": info["recommendation"]
                })
                
        # Check for information disclosure
        info_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
        for header in info_headers:
            if header in headers:
                findings.append({
                    "type": "info_disclosure",
                    "header": header,
                    "severity": "low",
                    "value": headers[header],
                    "description": f"Server information disclosed: {headers[header]}",
                    "recommendation": "Remove or obfuscate server version information"
                })
                
        # Analyze CSP if present
        if "content-security-policy" in headers:
            findings.extend(self._analyze_csp(headers["content-security-policy"]))
            
        # Analyze HSTS if present
        if "strict-transport-security" in headers:
            findings.extend(self._analyze_hsts(headers["strict-transport-security"]))
            
        return findings
        
    def _analyze_csp(self, csp: str) -> List[Dict[str, Any]]:
        """Analyze Content-Security-Policy."""
        findings = []
        
        if not csp:
            return [{
                "type": "missing",
                "header": "CSP",
                "severity": "high",
                "description": "No Content-Security-Policy header",
                "recommendation": "Implement a strict CSP policy"
            }]
            
        # Check for unsafe directives
        for unsafe, severity, description in self.UNSAFE_CSP:
            if unsafe in csp:
                findings.append({
                    "type": "unsafe_csp",
                    "severity": severity,
                    "directive": unsafe,
                    "description": f"CSP contains {unsafe}: {description}",
                    "recommendation": f"Remove '{unsafe}' from CSP if possible"
                })
                
        # Check for missing important directives
        important = ["default-src", "script-src", "style-src", "object-src", "frame-ancestors"]
        for directive in important:
            if directive not in csp:
                findings.append({
                    "type": "missing_directive",
                    "severity": "medium",
                    "directive": directive,
                    "description": f"CSP missing {directive} directive",
                    "recommendation": f"Add {directive} directive to CSP"
                })
                
        return findings
        
    def _analyze_hsts(self, hsts: str) -> List[Dict[str, Any]]:
        """Analyze HSTS header."""
        findings = []
        
        if not hsts:
            return [{
                "type": "missing",
                "header": "HSTS",
                "severity": "high",
                "description": "No HSTS header",
                "recommendation": "Add Strict-Transport-Security header"
            }]
            
        # Check max-age
        max_age_match = re.search(r'max-age=(\d+)', hsts)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # Less than 1 year
                findings.append({
                    "type": "weak_hsts",
                    "severity": "medium",
                    "description": f"HSTS max-age is {max_age}s (less than 1 year)",
                    "recommendation": "Set max-age to at least 31536000 (1 year)"
                })
                
        # Check for includeSubDomains
        if "includesubdomains" not in hsts.lower():
            findings.append({
                "type": "weak_hsts",
                "severity": "low",
                "description": "HSTS does not include subdomains",
                "recommendation": "Add includeSubDomains to HSTS"
            })
            
        # Check for preload
        if "preload" not in hsts.lower():
            findings.append({
                "type": "improvement",
                "severity": "info",
                "description": "HSTS preload not enabled",
                "recommendation": "Consider adding preload for HSTS"
            })
            
        return findings
        
    def _analyze_cors(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Analyze CORS headers."""
        findings = []
        
        acao = headers.get("access-control-allow-origin", "")
        
        if acao == "*":
            findings.append({
                "type": "open_cors",
                "severity": "high",
                "description": "CORS allows any origin (*)",
                "recommendation": "Restrict Access-Control-Allow-Origin to specific domains"
            })
            
        acac = headers.get("access-control-allow-credentials", "")
        if acac.lower() == "true" and acao == "*":
            findings.append({
                "type": "dangerous_cors",
                "severity": "critical",
                "description": "CORS allows credentials with wildcard origin",
                "recommendation": "Never use Access-Control-Allow-Credentials with wildcard origin"
            })
            
        return findings
        
    def _analyze_cookies(self, cookies: List[str]) -> List[Dict[str, Any]]:
        """Analyze cookie security."""
        findings = []
        
        for cookie in cookies:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split('=')[0] if '=' in cookie else "unknown"
            
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
                    "cookie": cookie_name,
                    "issues": issues,
                    "description": f"Cookie '{cookie_name}': {', '.join(issues)}",
                    "recommendation": "Add Secure, HttpOnly, and SameSite=Strict flags"
                })
                
        return findings
        
    def _calculate_score(self, findings: List[Dict[str, Any]]) -> int:
        """Calculate security score (0-100)."""
        score = 100
        
        severity_penalties = {
            "critical": 25,
            "high": 15,
            "medium": 10,
            "low": 5,
            "info": 0
        }
        
        for finding in findings:
            severity = finding.get("severity", "info")
            score -= severity_penalties.get(severity, 0)
            
        return max(0, score)
        
    def parse_output(self, output: str) -> Dict[str, Any]:
        return {"raw": output}
