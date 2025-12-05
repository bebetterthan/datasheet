"""
CSP (Content Security Policy) Analyzer Tool
============================================

Analyzes Content Security Policy headers for security issues.
"""

import subprocess
import re
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from urllib.parse import urlparse

from agent.tools.base import BaseTool, ToolResult, ToolStatus


class CSPAnalyzerTool(BaseTool):
    """
    Content Security Policy analyzer.
    
    Actions:
        - analyze: Analyze CSP header from URL
        - parse: Parse raw CSP string
        - check_bypass: Check for common CSP bypasses
        - generate: Generate recommended CSP
    """
    
    name = "csp_analyzer"
    description = "Content Security Policy security analyzer"
    category = "analyzer"
    
    actions = [
        "analyze",
        "parse",
        "check_bypass",
        "generate"
    ]
    
    timeout = 60
    
    # Risky directives and values
    DANGEROUS_SOURCES = {
        "'unsafe-inline'": {
            "risk": "high",
            "description": "Allows inline scripts/styles, XSS risk"
        },
        "'unsafe-eval'": {
            "risk": "high",
            "description": "Allows eval(), potential code injection"
        },
        "*": {
            "risk": "high",
            "description": "Allows all sources, defeats CSP purpose"
        },
        "data:": {
            "risk": "medium",
            "description": "Allows data: URIs, can embed malicious content"
        },
        "blob:": {
            "risk": "medium",
            "description": "Allows blob: URIs, can bypass restrictions"
        },
    }
    
    # Known CSP bypass domains
    BYPASS_DOMAINS = {
        # JSONP endpoints
        "accounts.google.com": "JSONP callback available",
        "cse.google.com": "JSONP callback available",
        "translate.google.com": "JSONP callback available",
        "ajax.googleapis.com": "Angular/jQuery available for bypass",
        "cdnjs.cloudflare.com": "Vulnerable libraries available",
        "cdn.jsdelivr.net": "Arbitrary content hosting",
        "unpkg.com": "Arbitrary content hosting",
        "raw.githubusercontent.com": "Arbitrary content hosting",
        "pastebin.com": "Arbitrary content hosting",
        "www.google-analytics.com": "JSONP callback available",
        "*.firebaseapp.com": "Hosting arbitrary content",
        "*.herokuapp.com": "Hosting arbitrary content",
    }
    
    # Important CSP directives
    IMPORTANT_DIRECTIVES = [
        "default-src",
        "script-src",
        "style-src",
        "img-src",
        "connect-src",
        "font-src",
        "object-src",
        "media-src",
        "frame-src",
        "frame-ancestors",
        "form-action",
        "base-uri",
        "upgrade-insecure-requests",
        "block-all-mixed-content",
        "report-uri",
        "report-to"
    ]
    
    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """
        Execute CSP analysis.
        
        Args:
            action: Analysis action
            target: URL or CSP string
            params:
                - strict: Enable strict checking
                
        Returns:
            ToolResult with analysis
        """
        params = params or {}
        start_time = datetime.now()
        
        self.validate_params(action, params)
        
        if action == "analyze":
            result = self._analyze_url(target, params)
            
        elif action == "parse":
            result = self._parse_csp(target)
            
        elif action == "check_bypass":
            result = self._check_bypass(target, params)
            
        elif action == "generate":
            result = self._generate_csp(target, params)
            
        else:
            result = {"error": f"Unknown action: {action}"}
            
        duration = (datetime.now() - start_time).total_seconds()
        
        return ToolResult(
            status=ToolStatus.SUCCESS if "error" not in result else ToolStatus.FAILURE,
            output=json.dumps(result, indent=2),
            parsed=result,
            duration=duration,
            metadata={"action": action, "target": target}
        )
        
    def _analyze_url(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze CSP from URL."""
        result = {
            "url": url,
            "has_csp": False,
            "csp_header": None,
            "csp_report_only": None,
            "analysis": None,
            "findings": [],
            "score": 100
        }
        
        try:
            # Fetch headers
            cmd = f'curl -s -I -L --connect-timeout 30 "{url}"'
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            headers = proc.stdout
            
            # Extract CSP headers
            csp_match = re.search(
                r'content-security-policy:\s*(.+?)(?:\r?\n(?!\s)|\r?\n\r?\n|$)',
                headers,
                re.IGNORECASE | re.DOTALL
            )
            
            csp_report_match = re.search(
                r'content-security-policy-report-only:\s*(.+?)(?:\r?\n(?!\s)|\r?\n\r?\n|$)',
                headers,
                re.IGNORECASE | re.DOTALL
            )
            
            if csp_match:
                result["has_csp"] = True
                result["csp_header"] = csp_match.group(1).strip()
                result["analysis"] = self._parse_csp(result["csp_header"])
                result["findings"] = self._evaluate_csp(result["analysis"])
                result["score"] = self._calculate_score(result["findings"])
                
            if csp_report_match:
                result["csp_report_only"] = csp_report_match.group(1).strip()
                
            if not result["has_csp"]:
                result["findings"].append({
                    "type": "missing_csp",
                    "severity": "high",
                    "description": "No Content-Security-Policy header found"
                })
                result["score"] = 0
                
        except Exception as e:
            result["error"] = str(e)
            
        return result
        
    def _parse_csp(self, csp_string: str) -> Dict[str, Any]:
        """Parse CSP string into directives."""
        result = {
            "raw": csp_string,
            "directives": {},
            "missing_directives": [],
            "nonces": [],
            "hashes": []
        }
        
        # Split into directives
        directives = csp_string.split(';')
        
        for directive in directives:
            directive = directive.strip()
            if not directive:
                continue
                
            parts = directive.split()
            if not parts:
                continue
                
            directive_name = parts[0].lower()
            values = parts[1:] if len(parts) > 1 else []
            
            result["directives"][directive_name] = values
            
            # Extract nonces
            for value in values:
                if value.startswith("'nonce-"):
                    result["nonces"].append(value)
                elif value.startswith("'sha256-") or value.startswith("'sha384-") or value.startswith("'sha512-"):
                    result["hashes"].append(value)
                    
        # Check for missing important directives
        for directive in self.IMPORTANT_DIRECTIVES:
            if directive not in result["directives"]:
                # Check if covered by default-src
                if directive != "default-src" and "default-src" not in result["directives"]:
                    result["missing_directives"].append(directive)
                elif directive in ["frame-ancestors", "form-action", "base-uri"]:
                    # These don't fallback to default-src
                    result["missing_directives"].append(directive)
                    
        return result
        
    def _evaluate_csp(self, parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate parsed CSP for issues."""
        findings = []
        directives = parsed["directives"]
        
        # Check each directive for dangerous values
        for directive, values in directives.items():
            for value in values:
                if value in self.DANGEROUS_SOURCES:
                    info = self.DANGEROUS_SOURCES[value]
                    findings.append({
                        "type": "dangerous_source",
                        "severity": info["risk"],
                        "directive": directive,
                        "value": value,
                        "description": info["description"]
                    })
                    
                # Check for bypass domains
                for domain, bypass_info in self.BYPASS_DOMAINS.items():
                    if domain in value or (value.startswith('*.') and domain.endswith(value[1:])):
                        findings.append({
                            "type": "bypass_domain",
                            "severity": "medium",
                            "directive": directive,
                            "domain": value,
                            "description": bypass_info
                        })
                        
        # Check for missing critical directives
        if "script-src" not in directives and "default-src" not in directives:
            findings.append({
                "type": "missing_script_src",
                "severity": "high",
                "description": "No script-src directive, scripts from any source allowed"
            })
            
        if "object-src" not in directives:
            findings.append({
                "type": "missing_object_src",
                "severity": "medium",
                "description": "No object-src directive, plugin content may be allowed"
            })
            
        if "base-uri" not in directives:
            findings.append({
                "type": "missing_base_uri",
                "severity": "medium",
                "description": "No base-uri directive, base tag injection possible"
            })
            
        if "form-action" not in directives:
            findings.append({
                "type": "missing_form_action",
                "severity": "medium",
                "description": "No form-action directive, forms can submit anywhere"
            })
            
        if "frame-ancestors" not in directives:
            findings.append({
                "type": "missing_frame_ancestors",
                "severity": "medium",
                "description": "No frame-ancestors directive, clickjacking possible"
            })
            
        # Check for HTTP sources on HTTPS
        for directive, values in directives.items():
            for value in values:
                if value.startswith('http://'):
                    findings.append({
                        "type": "http_source",
                        "severity": "medium",
                        "directive": directive,
                        "value": value,
                        "description": "HTTP source on potentially HTTPS page"
                    })
                    
        # Check for overly permissive policies
        for directive, values in directives.items():
            if '*' in values or "'unsafe-inline'" in values or "'unsafe-eval'" in values:
                if directive in ['script-src', 'default-src']:
                    findings.append({
                        "type": "permissive_policy",
                        "severity": "high",
                        "directive": directive,
                        "description": f"{directive} is overly permissive"
                    })
                    
        # Positive findings
        if parsed["nonces"]:
            findings.append({
                "type": "uses_nonces",
                "severity": "info",
                "description": f"CSP uses nonces ({len(parsed['nonces'])} found)"
            })
            
        if parsed["hashes"]:
            findings.append({
                "type": "uses_hashes",
                "severity": "info",
                "description": f"CSP uses hashes ({len(parsed['hashes'])} found)"
            })
            
        if "upgrade-insecure-requests" in directives:
            findings.append({
                "type": "upgrade_requests",
                "severity": "info",
                "description": "CSP includes upgrade-insecure-requests"
            })
            
        return findings
        
    def _calculate_score(self, findings: List[Dict[str, Any]]) -> int:
        """Calculate security score based on findings."""
        score = 100
        
        for finding in findings:
            severity = finding.get("severity", "low")
            if severity == "critical":
                score -= 30
            elif severity == "high":
                score -= 20
            elif severity == "medium":
                score -= 10
            elif severity == "low":
                score -= 5
                
        return max(0, score)
        
    def _check_bypass(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Check for CSP bypass opportunities."""
        result = {
            "target": target,
            "bypasses": [],
            "recommendations": []
        }
        
        # Determine if target is URL or CSP string
        if target.startswith('http'):
            analysis = self._analyze_url(target, params)
            if not analysis.get("has_csp"):
                result["bypasses"].append({
                    "type": "no_csp",
                    "description": "No CSP present, all bypasses available"
                })
                return result
            parsed = analysis.get("analysis", {})
        else:
            parsed = self._parse_csp(target)
            
        directives = parsed.get("directives", {})
        
        # Check for JSONP bypasses
        script_sources = directives.get("script-src", directives.get("default-src", []))
        
        for source in script_sources:
            for domain, info in self.BYPASS_DOMAINS.items():
                if domain in source:
                    result["bypasses"].append({
                        "type": "jsonp_bypass",
                        "domain": domain,
                        "description": info,
                        "payload_hint": f"<script src='https://{domain}/...'></script>"
                    })
                    
        # Check unsafe-inline bypass
        if "'unsafe-inline'" in script_sources:
            result["bypasses"].append({
                "type": "inline_script",
                "description": "Inline scripts allowed",
                "payload_hint": "<script>alert(1)</script>"
            })
            
        # Check unsafe-eval bypass
        if "'unsafe-eval'" in script_sources:
            result["bypasses"].append({
                "type": "eval_bypass",
                "description": "eval() allowed",
                "payload_hint": "eval('alert(1)')"
            })
            
        # Check for Angular bypass
        if any('angular' in s.lower() or 'googleapis' in s.lower() for s in script_sources):
            result["bypasses"].append({
                "type": "angular_bypass",
                "description": "AngularJS can bypass CSP",
                "payload_hint": "<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>"
            })
            
        # Check base-uri bypass
        if "base-uri" not in directives:
            result["bypasses"].append({
                "type": "base_uri_bypass",
                "description": "No base-uri restriction",
                "payload_hint": "<base href='https://attacker.com/'>"
            })
            
        # Generate recommendations
        if "'unsafe-inline'" in script_sources:
            result["recommendations"].append("Replace 'unsafe-inline' with nonces or hashes")
            
        if "'unsafe-eval'" in script_sources:
            result["recommendations"].append("Remove 'unsafe-eval' and refactor code")
            
        if "base-uri" not in directives:
            result["recommendations"].append("Add base-uri 'self' or 'none'")
            
        for bypass in result["bypasses"]:
            if bypass["type"] == "jsonp_bypass":
                result["recommendations"].append(f"Remove or restrict {bypass['domain']}")
                
        return result
        
    def _generate_csp(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Generate recommended CSP for target."""
        result = {
            "target": target,
            "recommended_csp": "",
            "strict_csp": "",
            "notes": []
        }
        
        # Basic recommended CSP
        recommended = [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",  # Often needed for inline styles
            "img-src 'self' data: https:",
            "font-src 'self'",
            "connect-src 'self'",
            "frame-ancestors 'self'",
            "form-action 'self'",
            "base-uri 'self'",
            "object-src 'none'",
            "upgrade-insecure-requests"
        ]
        
        result["recommended_csp"] = "; ".join(recommended)
        
        # Strict CSP with nonces (template)
        strict = [
            "default-src 'none'",
            "script-src 'nonce-{RANDOM}'",
            "style-src 'nonce-{RANDOM}'",
            "img-src 'self'",
            "font-src 'self'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "base-uri 'none'",
            "object-src 'none'",
            "require-trusted-types-for 'script'",
            "upgrade-insecure-requests"
        ]
        
        result["strict_csp"] = "; ".join(strict)
        
        # Notes
        result["notes"] = [
            "Replace {RANDOM} with a unique nonce per request",
            "Test thoroughly before deploying to production",
            "Use report-uri or report-to to monitor violations",
            "Consider using Content-Security-Policy-Report-Only first"
        ]
        
        # If analyzing existing site, customize recommendations
        if target.startswith('http'):
            try:
                content = self._fetch_url(target)
                
                # Check for inline scripts
                if re.search(r'<script[^>]*>[^<]+</script>', content):
                    result["notes"].append("Site has inline scripts - use nonces or refactor")
                    
                # Check for external scripts
                external_scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', content)
                if external_scripts:
                    domains = set()
                    for script in external_scripts:
                        parsed = urlparse(script)
                        if parsed.netloc:
                            domains.add(parsed.netloc)
                    if domains:
                        result["notes"].append(f"External script domains found: {', '.join(domains)}")
                        result["notes"].append("Add these to script-src if trusted")
                        
            except Exception:
                pass
                
        return result
        
    def _fetch_url(self, url: str) -> str:
        """Fetch URL content."""
        try:
            cmd = f'curl -s -L --connect-timeout 30 "{url}"'
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            return proc.stdout
        except:
            return ""
            
    def parse_output(self, output: str) -> Dict[str, Any]:
        try:
            return json.loads(output)
        except:
            return {"raw": output}
