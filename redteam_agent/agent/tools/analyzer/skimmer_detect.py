"""
Skimmer Detection Tool
======================

Specialized tool for detecting Magecart and payment card skimmers.
"""

import subprocess
import re
import json
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime
from urllib.parse import urlparse

from agent.tools.base import BaseTool, ToolResult, ToolStatus


class SkimmerDetectTool(BaseTool):
    """
    Magecart/Skimmer detection specialist.
    
    Actions:
        - scan_page: Full page scan for skimmer indicators
        - check_forms: Analyze checkout/payment forms
        - monitor_changes: Compare scripts against baselines
        - analyze_network: Check for suspicious network calls
    """
    
    name = "skimmer_detect"
    description = "Magecart/payment skimmer detection"
    category = "analyzer"
    
    actions = [
        "scan_page",
        "check_forms",
        "analyze_checkout",
        "check_integrity"
    ]
    
    timeout = 180
    
    # Known Magecart group signatures
    MAGECART_SIGNATURES = {
        "group_4": [
            r'jquery-migrate',
            r'google-analyitics',  # Typo is intentional
            r'bootstrapcdn\.net',
        ],
        "group_5": [
            r'reactjslib',
            r'jquerystatic',
        ],
        "group_6": [
            r'magento-analytics',
            r'magento-cdn',
        ],
        "group_7": [
            r'g-statistic',
            r'googletagsmanager',
        ],
        "group_8": [
            r'segmentify',
            r'chatango',
        ],
        "group_9": [
            r'font-assets',
            r'google-payments',
        ],
        "inter": [
            r'magento\.name',
            r'statistic\.su',
        ],
        "keeper": [
            r'fileskeeper',
            r'fresh-keeper',
        ]
    }
    
    # Payment form selectors commonly targeted
    PAYMENT_FORM_PATTERNS = [
        r'payment[-_]form',
        r'checkout[-_]form',
        r'billing[-_]form',
        r'credit[-_]card',
        r'card[-_]number',
        r'cc[-_]number',
        r'cvv|cvc|csc',
        r'expiry[-_]date',
        r'cardholder',
    ]
    
    # Suspicious behavior patterns
    BEHAVIOR_PATTERNS = {
        "keylogger": [
            r'addEventListener\s*\(\s*["\']key(down|up|press)["\']',
            r'onkeydown|onkeyup|onkeypress',
            r'\.which|\.keyCode|\.charCode',
        ],
        "form_hijacker": [
            r'addEventListener\s*\(\s*["\']submit["\']',
            r'\.submit\s*\(',
            r'preventDefault.*submit',
            r'onsubmit\s*=',
        ],
        "data_harvester": [
            r'\.value\s*=|\.value;',
            r'querySelectorAll.*input',
            r'getElementsByTagName.*input',
        ],
        "exfiltrator": [
            r'new\s+Image\s*\(\s*\)\.src',
            r'sendBeacon',
            r'XMLHttpRequest',
            r'fetch\s*\(',
            r'\.ajax\s*\(',
        ],
        "encoder": [
            r'btoa\s*\(',
            r'atob\s*\(',
            r'encodeURIComponent',
            r'JSON\.stringify',
        ]
    }
    
    # Malicious domain TLDs and patterns
    SUSPICIOUS_TLDS = ['.su', '.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq']
    
    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """
        Execute skimmer detection.
        
        Args:
            action: Detection action
            target: Target URL
            params:
                - baseline: Previous script hashes for comparison
                - deep_scan: Enable deep analysis
                
        Returns:
            ToolResult with detection results
        """
        params = params or {}
        start_time = datetime.now()
        
        self.validate_params(action, params)
        
        if action == "scan_page":
            result = self._scan_page(target, params)
            
        elif action == "check_forms":
            result = self._check_forms(target, params)
            
        elif action == "analyze_checkout":
            result = self._analyze_checkout(target, params)
            
        elif action == "check_integrity":
            result = self._check_integrity(target, params)
            
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
        
    def _scan_page(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive page scan for skimmers."""
        result = {
            "url": url,
            "scan_time": datetime.now().isoformat(),
            "risk_score": 0,
            "skimmer_detected": False,
            "magecart_group": None,
            "findings": [],
            "scripts_analyzed": 0,
            "suspicious_scripts": []
        }
        
        try:
            # Fetch page
            page_content = self._fetch_url(url)
            if not page_content:
                result["error"] = "Failed to fetch page"
                return result
                
            parsed_url = urlparse(url)
            base_domain = parsed_url.netloc
            
            # Extract and analyze scripts
            scripts = self._extract_scripts(page_content, url)
            result["scripts_analyzed"] = len(scripts["external"]) + len(scripts["inline"])
            
            # Check inline scripts
            for idx, script in enumerate(scripts["inline"]):
                findings = self._analyze_script_content(script["content"], f"inline_script_{idx}")
                if findings["risk_score"] > 30:
                    result["suspicious_scripts"].append({
                        "type": "inline",
                        "hash": script["hash"],
                        "findings": findings
                    })
                    result["risk_score"] += findings["risk_score"]
                    
            # Check external scripts
            for script_url in scripts["external"]:
                # Check for suspicious domains
                script_domain = urlparse(script_url).netloc
                
                # Check TLD
                for tld in self.SUSPICIOUS_TLDS:
                    if script_domain.endswith(tld):
                        result["findings"].append({
                            "type": "suspicious_tld",
                            "severity": "high",
                            "script": script_url,
                            "detail": f"Suspicious TLD: {tld}"
                        })
                        result["risk_score"] += 25
                        
                # Check against Magecart signatures
                group = self._check_magecart_signature(script_url)
                if group:
                    result["magecart_group"] = group
                    result["risk_score"] += 50
                    result["findings"].append({
                        "type": "magecart_signature",
                        "severity": "critical",
                        "script": script_url,
                        "detail": f"Matches Magecart {group} signature"
                    })
                    
                # Fetch and analyze external script content
                if params.get("deep_scan", True):
                    script_content = self._fetch_url(script_url)
                    if script_content:
                        findings = self._analyze_script_content(script_content, script_url)
                        if findings["risk_score"] > 30:
                            result["suspicious_scripts"].append({
                                "type": "external",
                                "url": script_url,
                                "findings": findings
                            })
                            result["risk_score"] += findings["risk_score"]
                            
            # Check for payment form presence
            has_payment_form = self._detect_payment_forms(page_content)
            result["has_payment_form"] = has_payment_form
            
            if has_payment_form and result["risk_score"] > 0:
                result["risk_score"] *= 1.5  # Increase risk for payment pages
                
            # Determine final verdict
            result["risk_score"] = min(100, int(result["risk_score"]))
            
            if result["risk_score"] >= 70:
                result["skimmer_detected"] = True
                result["severity"] = "critical"
            elif result["risk_score"] >= 50:
                result["skimmer_detected"] = True
                result["severity"] = "high"
            elif result["risk_score"] >= 30:
                result["severity"] = "medium"
            else:
                result["severity"] = "low"
                
        except Exception as e:
            result["error"] = str(e)
            
        return result
        
    def _check_forms(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Check for suspicious form modifications."""
        result = {
            "url": url,
            "forms_found": 0,
            "payment_forms": [],
            "suspicious_handlers": [],
            "findings": []
        }
        
        try:
            content = self._fetch_url(url)
            if not content:
                result["error"] = "Failed to fetch page"
                return result
                
            # Find all forms
            form_pattern = r'<form[^>]*>([\s\S]*?)</form>'
            forms = re.findall(form_pattern, content, re.IGNORECASE)
            result["forms_found"] = len(forms)
            
            for idx, form_content in enumerate(forms):
                form_info = {"index": idx, "suspicious": False, "issues": []}
                
                # Check if payment form
                is_payment = any(
                    re.search(pattern, form_content, re.IGNORECASE)
                    for pattern in self.PAYMENT_FORM_PATTERNS
                )
                
                if is_payment:
                    form_info["is_payment_form"] = True
                    
                    # Check for suspicious attributes
                    if re.search(r'action\s*=\s*["\'][^"\']*(?:' + '|'.join(self.SUSPICIOUS_TLDS) + ')', form_content, re.IGNORECASE):
                        form_info["issues"].append("Form action points to suspicious domain")
                        form_info["suspicious"] = True
                        
                    # Check for inline event handlers
                    handlers = re.findall(r'on(submit|change|input|keyup)\s*=\s*["\']([^"\']+)["\']', form_content, re.IGNORECASE)
                    if handlers:
                        form_info["inline_handlers"] = len(handlers)
                        result["suspicious_handlers"].extend(handlers)
                        
                    result["payment_forms"].append(form_info)
                    
        except Exception as e:
            result["error"] = str(e)
            
        return result
        
    def _analyze_checkout(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Specialized checkout page analysis."""
        result = {
            "url": url,
            "is_checkout": False,
            "payment_fields": [],
            "third_party_scripts": [],
            "data_destinations": [],
            "findings": []
        }
        
        try:
            content = self._fetch_url(url)
            if not content:
                result["error"] = "Failed to fetch page"
                return result
                
            # Check if checkout page
            checkout_indicators = [
                'checkout', 'payment', 'billing', 'order',
                'cart', 'purchase', 'card-number'
            ]
            result["is_checkout"] = any(
                indicator in content.lower()
                for indicator in checkout_indicators
            )
            
            # Find payment fields
            input_pattern = r'<input[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>'
            inputs = re.findall(input_pattern, content, re.IGNORECASE)
            
            payment_field_keywords = ['card', 'credit', 'cc', 'cvv', 'cvc', 'exp', 'number']
            result["payment_fields"] = [
                inp for inp in inputs
                if any(kw in inp.lower() for kw in payment_field_keywords)
            ]
            
            # Find third-party scripts on checkout
            script_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
            scripts = re.findall(script_pattern, content, re.IGNORECASE)
            
            parsed_url = urlparse(url)
            base_domain = parsed_url.netloc
            
            for script in scripts:
                script_domain = urlparse(script).netloc
                if script_domain and script_domain != base_domain:
                    result["third_party_scripts"].append({
                        "url": script,
                        "domain": script_domain,
                        "suspicious": any(script_domain.endswith(tld) for tld in self.SUSPICIOUS_TLDS)
                    })
                    
            # Check for data being sent elsewhere
            fetch_pattern = r'(?:fetch|XMLHttpRequest|\.ajax)\s*\(\s*["\']([^"\']+)["\']'
            destinations = re.findall(fetch_pattern, content)
            
            for dest in destinations:
                if dest.startswith('http'):
                    dest_domain = urlparse(dest).netloc
                    if dest_domain and dest_domain != base_domain:
                        result["data_destinations"].append({
                            "url": dest,
                            "domain": dest_domain
                        })
                        
            # Risk assessment
            if result["third_party_scripts"]:
                suspicious_3p = [s for s in result["third_party_scripts"] if s["suspicious"]]
                if suspicious_3p:
                    result["findings"].append({
                        "type": "suspicious_third_party",
                        "severity": "high",
                        "detail": f"{len(suspicious_3p)} suspicious third-party scripts on checkout"
                    })
                    
            if result["data_destinations"]:
                result["findings"].append({
                    "type": "external_data_transfer",
                    "severity": "medium",
                    "detail": f"Data sent to {len(result['data_destinations'])} external destinations"
                })
                
        except Exception as e:
            result["error"] = str(e)
            
        return result
        
    def _check_integrity(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Check script integrity against baseline."""
        result = {
            "url": url,
            "scripts": [],
            "changes_detected": False,
            "modified_scripts": [],
            "new_scripts": [],
            "removed_scripts": []
        }
        
        baseline = params.get("baseline", {})
        
        try:
            content = self._fetch_url(url)
            if not content:
                result["error"] = "Failed to fetch page"
                return result
                
            scripts = self._extract_scripts(content, url)
            
            current_hashes = {}
            
            # Hash inline scripts
            for script in scripts["inline"]:
                current_hashes[f"inline:{script['hash']}"] = script["content"][:100]
                
            # Hash external scripts
            for script_url in scripts["external"]:
                script_content = self._fetch_url(script_url)
                if script_content:
                    script_hash = hashlib.sha256(script_content.encode()).hexdigest()
                    current_hashes[script_url] = script_hash
                    
            # Compare with baseline
            if baseline:
                for key, value in current_hashes.items():
                    if key in baseline:
                        if value != baseline[key]:
                            result["modified_scripts"].append(key)
                            result["changes_detected"] = True
                    else:
                        result["new_scripts"].append(key)
                        result["changes_detected"] = True
                        
                for key in baseline:
                    if key not in current_hashes:
                        result["removed_scripts"].append(key)
                        result["changes_detected"] = True
                        
            result["current_hashes"] = current_hashes
            result["scripts_count"] = len(current_hashes)
            
        except Exception as e:
            result["error"] = str(e)
            
        return result
        
    def _fetch_url(self, url: str) -> str:
        """Fetch URL content."""
        try:
            cmd = f'curl -s -L --connect-timeout 30 -A "Mozilla/5.0" "{url}"'
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            return proc.stdout
        except:
            return ""
            
    def _extract_scripts(self, content: str, base_url: str) -> Dict[str, List]:
        """Extract scripts from page content."""
        result = {"inline": [], "external": []}
        
        parsed_url = urlparse(base_url)
        
        # External scripts
        script_src_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
        for match in re.finditer(script_src_pattern, content, re.IGNORECASE):
            src = match.group(1)
            if src.startswith('//'):
                src = 'https:' + src
            elif src.startswith('/'):
                src = f"{parsed_url.scheme}://{parsed_url.netloc}{src}"
            elif not src.startswith('http'):
                src = f"{parsed_url.scheme}://{parsed_url.netloc}/{src}"
            result["external"].append(src)
            
        # Inline scripts
        inline_pattern = r'<script[^>]*>([\s\S]*?)</script>'
        for match in re.finditer(inline_pattern, content, re.IGNORECASE):
            script_content = match.group(1).strip()
            if script_content and 'src=' not in match.group(0):
                result["inline"].append({
                    "content": script_content,
                    "hash": hashlib.md5(script_content.encode()).hexdigest()
                })
                
        return result
        
    def _analyze_script_content(self, content: str, source: str) -> Dict[str, Any]:
        """Analyze script content for malicious patterns."""
        result = {
            "source": source,
            "risk_score": 0,
            "behaviors": [],
            "indicators": []
        }
        
        for behavior, patterns in self.BEHAVIOR_PATTERNS.items():
            matches = 0
            for pattern in patterns:
                found = re.findall(pattern, content, re.IGNORECASE)
                matches += len(found)
                
            if matches > 0:
                result["behaviors"].append({
                    "type": behavior,
                    "count": matches
                })
                
                # Weight different behaviors
                if behavior == "exfiltrator":
                    result["risk_score"] += 20 * min(matches, 3)
                elif behavior == "keylogger":
                    result["risk_score"] += 15 * min(matches, 3)
                elif behavior == "form_hijacker":
                    result["risk_score"] += 15 * min(matches, 3)
                else:
                    result["risk_score"] += 5 * min(matches, 3)
                    
        return result
        
    def _check_magecart_signature(self, script_url: str) -> Optional[str]:
        """Check if script URL matches known Magecart signatures."""
        for group, patterns in self.MAGECART_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, script_url, re.IGNORECASE):
                    return group
        return None
        
    def _detect_payment_forms(self, content: str) -> bool:
        """Detect presence of payment forms."""
        return any(
            re.search(pattern, content, re.IGNORECASE)
            for pattern in self.PAYMENT_FORM_PATTERNS
        )
        
    def parse_output(self, output: str) -> Dict[str, Any]:
        try:
            return json.loads(output)
        except:
            return {"raw": output}
