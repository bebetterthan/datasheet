"""
JavaScript Analyzer Tool
========================

Analyzes JavaScript for security issues, skimmers, and malicious patterns.
"""

import subprocess
import re
import json
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime
from urllib.parse import urlparse

from agent.tools.base import BaseTool, ToolResult, ToolStatus


class JSAnalyzerTool(BaseTool):
    """
    JavaScript security analyzer.
    
    Actions:
        - enumerate: Find all JS files on a page
        - analyze: Analyze JS content for issues
        - detect_skimmer: Detect Magecart/skimmer patterns
        - find_secrets: Find exposed secrets in JS
    """
    
    name = "js_analyzer"
    description = "JavaScript security analyzer for skimmers and malicious code"
    category = "analyzer"
    
    actions = [
        "enumerate",
        "analyze",
        "detect_skimmer",
        "find_secrets",
        "find_endpoints"
    ]
    
    timeout = 120
    
    # Skimmer/Magecart patterns
    SKIMMER_PATTERNS = {
        # Form data exfiltration
        "form_grab": [
            r'document\.forms',
            r'getElementsByTagName\s*\(\s*["\']form["\']',
            r'querySelectorAll\s*\(\s*["\']form',
            r'addEventListener\s*\(\s*["\']submit',
        ],
        
        # Input field monitoring
        "input_monitor": [
            r'\.value',
            r'getElementById\s*\(\s*["\'](?:cc|card|cvv|cvc|exp|credit)',
            r'querySelector\s*\(\s*["\']input\[name.*(?:card|credit|cc|cvv)',
            r'addEventListener\s*\(\s*["\'](?:keyup|keydown|input|change)',
        ],
        
        # Data exfiltration
        "exfil": [
            r'new\s+Image\s*\(\s*\)\.src\s*=',
            r'\.src\s*=\s*["\']https?://[^"\']+\?',
            r'navigator\.sendBeacon',
            r'fetch\s*\(\s*["\']https?://(?!.*(?:' + '|'.join([
                'google', 'facebook', 'twitter', 'analytics', 'cdn'
            ]) + ')',
            r'XMLHttpRequest.*\.open\s*\(\s*["\'](?:POST|GET)',
        ],
        
        # Obfuscation indicators
        "obfuscation": [
            r'eval\s*\(',
            r'Function\s*\(\s*["\']return',
            r'fromCharCode',
            r'atob\s*\(',
            r'btoa\s*\(',
            r'unescape\s*\(',
            r'\\x[0-9a-fA-F]{2}',
            r'\\u[0-9a-fA-F]{4}',
        ],
        
        # Known skimmer domains
        "known_domains": [
            r'google-anaiytic',
            r'googletagmanager\.eu',
            r'jquery-cdn',
            r'js-cdn',
            r'magento-analytics',
            r'magento-cdn',
            r'payment-api',
            r'secure-payment',
        ],
        
        # Payment keywords
        "payment_keywords": [
            r'(?:credit|debit)[\s_-]*card',
            r'card[\s_-]*number',
            r'cvv|cvc|csc',
            r'expir(?:y|ation)',
            r'payment[\s_-]*(?:info|details|data)',
            r'billing[\s_-]*address',
        ],
        
        # Encoding/encryption (data hiding)
        "encoding": [
            r'\.replace\s*\(\s*/[^/]+/g?\s*,',
            r'split\s*\(\s*["\']["\']?\s*\)\s*\.reverse',
            r'charCodeAt',
            r'String\.fromCharCode',
        ],
    }
    
    # Secret patterns
    SECRET_PATTERNS = {
        "api_key": r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
        "aws_key": r'AKIA[0-9A-Z]{16}',
        "github_token": r'ghp_[0-9a-zA-Z]{36}',
        "slack_token": r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
        "private_key": r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
        "jwt": r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*',
        "password": r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^\s"\']{8,})["\']',
        "secret": r'(?:secret|token)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
    }
    
    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """
        Execute JavaScript analysis.
        
        Args:
            action: Analysis action
            target: Target URL or JS content
            params:
                - content: Direct JS content to analyze
                - depth: Depth for enumeration
                
        Returns:
            ToolResult with analysis
        """
        params = params or {}
        start_time = datetime.now()
        
        self.validate_params(action, params)
        
        # Determine if target is URL or content
        is_url = target.startswith(('http://', 'https://'))
        
        if action == "enumerate":
            if not is_url:
                return ToolResult(
                    status=ToolStatus.ERROR,
                    output="",
                    error="enumerate action requires a URL"
                )
            result = self._enumerate_scripts(target, params)
            
        elif action == "analyze":
            content = params.get("content") or (self._fetch_content(target) if is_url else target)
            result = self._analyze_js(content, target if is_url else None)
            
        elif action == "detect_skimmer":
            content = params.get("content") or (self._fetch_content(target) if is_url else target)
            result = self._detect_skimmer(content, target if is_url else None)
            
        elif action == "find_secrets":
            content = params.get("content") or (self._fetch_content(target) if is_url else target)
            result = self._find_secrets(content)
            
        elif action == "find_endpoints":
            content = params.get("content") or (self._fetch_content(target) if is_url else target)
            result = self._find_endpoints(content)
            
        else:
            result = {"error": "Unknown action"}
            
        duration = (datetime.now() - start_time).total_seconds()
        
        return ToolResult(
            status=ToolStatus.SUCCESS if "error" not in result else ToolStatus.FAILURE,
            output=json.dumps(result, indent=2),
            parsed=result,
            duration=duration,
            metadata={"action": action, "target": target}
        )
        
    def _enumerate_scripts(
        self,
        url: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Find all JavaScript files on a page."""
        result = {
            "url": url,
            "inline_scripts": [],
            "external_scripts": [],
            "third_party": [],
            "first_party": [],
            "total_count": 0
        }
        
        try:
            # Fetch page content
            cmd = f'curl -s -L --connect-timeout 30 "{url}"'
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            content = proc.stdout
            
            parsed_url = urlparse(url)
            base_domain = parsed_url.netloc
            
            # Find external scripts
            script_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
            for match in re.finditer(script_pattern, content, re.IGNORECASE):
                src = match.group(1)
                
                # Resolve relative URLs
                if src.startswith('//'):
                    src = 'https:' + src
                elif src.startswith('/'):
                    src = f"{parsed_url.scheme}://{base_domain}{src}"
                elif not src.startswith('http'):
                    src = f"{parsed_url.scheme}://{base_domain}/{src}"
                    
                script_info = {
                    "src": src,
                    "hash": None
                }
                
                result["external_scripts"].append(script_info)
                
                # Categorize as first or third party
                script_domain = urlparse(src).netloc
                if base_domain in script_domain or script_domain in base_domain:
                    result["first_party"].append(src)
                else:
                    result["third_party"].append(src)
                    
            # Find inline scripts
            inline_pattern = r'<script[^>]*>([\s\S]*?)</script>'
            for match in re.finditer(inline_pattern, content, re.IGNORECASE):
                script_content = match.group(1).strip()
                if script_content and 'src=' not in match.group(0):
                    script_hash = hashlib.md5(script_content.encode()).hexdigest()[:16]
                    result["inline_scripts"].append({
                        "hash": script_hash,
                        "length": len(script_content),
                        "preview": script_content[:200] + "..." if len(script_content) > 200 else script_content
                    })
                    
            result["total_count"] = len(result["external_scripts"]) + len(result["inline_scripts"])
            
        except Exception as e:
            result["error"] = str(e)
            
        return result
        
    def _fetch_content(self, url: str) -> str:
        """Fetch content from URL."""
        try:
            cmd = f'curl -s -L --connect-timeout 30 "{url}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            return result.stdout
        except:
            return ""
            
    def _analyze_js(
        self,
        content: str,
        source_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """Analyze JavaScript content."""
        result = {
            "source": source_url,
            "size": len(content),
            "findings": [],
            "risk_level": "low",
            "statistics": {}
        }
        
        # Check for obfuscation
        obfuscation_score = 0
        for pattern in self.SKIMMER_PATTERNS["obfuscation"]:
            matches = re.findall(pattern, content)
            if matches:
                obfuscation_score += len(matches)
                
        if obfuscation_score > 5:
            result["findings"].append({
                "type": "obfuscation",
                "severity": "medium",
                "description": f"Heavy obfuscation detected (score: {obfuscation_score})",
                "indicators": obfuscation_score
            })
            result["risk_level"] = "medium"
            
        # Check for suspicious patterns
        for category, patterns in self.SKIMMER_PATTERNS.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, content, re.IGNORECASE)
                matches.extend(found)
                
            if matches:
                result["statistics"][category] = len(matches)
                
        # Entropy analysis (high entropy = possible obfuscation)
        entropy = self._calculate_entropy(content)
        result["statistics"]["entropy"] = round(entropy, 2)
        
        if entropy > 5.5:
            result["findings"].append({
                "type": "high_entropy",
                "severity": "low",
                "description": f"High entropy detected ({entropy:.2f}), possible obfuscation"
            })
            
        return result
        
    def _detect_skimmer(
        self,
        content: str,
        source_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """Detect Magecart/skimmer patterns."""
        result = {
            "source": source_url,
            "is_suspicious": False,
            "risk_score": 0,
            "findings": [],
            "indicators": {}
        }
        
        risk_score = 0
        
        # Check each pattern category
        for category, patterns in self.SKIMMER_PATTERNS.items():
            category_matches = []
            
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Get surrounding context
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end]
                    
                    category_matches.append({
                        "pattern": pattern,
                        "match": match.group()[:100],
                        "context": context
                    })
                    
            if category_matches:
                severity = "high" if category in ["exfil", "known_domains"] else "medium"
                risk_weight = 30 if category in ["exfil", "known_domains"] else 15
                
                result["findings"].append({
                    "category": category,
                    "severity": severity,
                    "count": len(category_matches),
                    "samples": category_matches[:3]  # Limit to 3 samples
                })
                
                result["indicators"][category] = len(category_matches)
                risk_score += min(risk_weight * len(category_matches), risk_weight * 3)
                
        result["risk_score"] = min(risk_score, 100)
        result["is_suspicious"] = risk_score >= 40
        
        # Set risk level
        if risk_score >= 70:
            result["risk_level"] = "critical"
        elif risk_score >= 50:
            result["risk_level"] = "high"
        elif risk_score >= 30:
            result["risk_level"] = "medium"
        else:
            result["risk_level"] = "low"
            
        return result
        
    def _find_secrets(self, content: str) -> Dict[str, Any]:
        """Find exposed secrets in JavaScript."""
        result = {
            "secrets_found": [],
            "count": 0
        }
        
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                # Mask the secret
                secret = match.group()
                masked = secret[:10] + "..." + secret[-4:] if len(secret) > 14 else secret[:4] + "..."
                
                result["secrets_found"].append({
                    "type": secret_type,
                    "masked_value": masked,
                    "severity": "high" if secret_type in ["private_key", "aws_key"] else "medium"
                })
                result["count"] += 1
                
        return result
        
    def _find_endpoints(self, content: str) -> Dict[str, Any]:
        """Extract API endpoints from JavaScript."""
        result = {
            "endpoints": [],
            "domains": set(),
            "paths": []
        }
        
        # URL patterns
        url_pattern = r'["\'](?:https?://[^\s"\'<>]+|/[a-zA-Z0-9_\-/]+)["\']'
        
        for match in re.finditer(url_pattern, content):
            url = match.group().strip('"\'')
            
            if url.startswith('http'):
                result["endpoints"].append(url)
                parsed = urlparse(url)
                result["domains"].add(parsed.netloc)
            elif url.startswith('/') and len(url) > 1:
                result["paths"].append(url)
                
        # Convert set to list for JSON serialization
        result["domains"] = list(result["domains"])
        result["unique_endpoints"] = len(set(result["endpoints"]))
        result["unique_paths"] = len(set(result["paths"]))
        
        return result
        
    def _calculate_entropy(self, content: str) -> float:
        """Calculate Shannon entropy of content."""
        import math
        
        if not content:
            return 0.0
            
        frequency = {}
        for char in content:
            frequency[char] = frequency.get(char, 0) + 1
            
        entropy = 0.0
        length = len(content)
        
        for count in frequency.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
            
        return entropy
        
    def parse_output(self, output: str) -> Dict[str, Any]:
        try:
            return json.loads(output)
        except:
            return {"raw": output}
