"""
Technology Detection Tool
=========================

Detects web technologies, frameworks, and CMS systems.
"""

import subprocess
import re
import json
from typing import Dict, Any, Optional, List
from datetime import datetime

from agent.tools.base import BaseTool, ToolResult, ToolStatus


class TechDetectTool(BaseTool):
    """
    Web technology fingerprinting tool.
    
    Actions:
        - detect: Full technology detection
        - identify_cms: CMS identification
        - identify_framework: Framework detection
        - identify_server: Server fingerprinting
    """
    
    name = "tech_detect"
    description = "Web technology and CMS fingerprinting"
    category = "recon"
    
    actions = [
        "detect",
        "identify_cms",
        "identify_framework",
        "identify_server"
    ]
    
    timeout = 120
    
    # Technology signatures
    SIGNATURES = {
        "cms": {
            "wordpress": {
                "patterns": [
                    r'/wp-content/',
                    r'/wp-includes/',
                    r'wp-json',
                    r'wordpress',
                    r'<meta name="generator" content="WordPress',
                ],
                "headers": {
                    "x-powered-by": r'wordpress',
                    "link": r'wp-json'
                }
            },
            "magento": {
                "patterns": [
                    r'/skin/frontend/',
                    r'/js/mage/',
                    r'Mage\.Cookies',
                    r'Magento',
                    r'/static/version',
                    r'requirejs/require',
                    r'mage/cookies',
                ],
                "headers": {
                    "x-magento": r'.',
                },
                "cookies": [
                    r'frontend_cid',
                    r'mage-cache',
                    r'PHPSESSID'
                ]
            },
            "shopify": {
                "patterns": [
                    r'cdn\.shopify\.com',
                    r'shopify\.com',
                    r'myshopify\.com',
                    r'Shopify\.theme',
                ],
                "headers": {
                    "x-shopify": r'.',
                    "x-sorting-hat-shopid": r'.'
                }
            },
            "woocommerce": {
                "patterns": [
                    r'woocommerce',
                    r'wc-add-to-cart',
                    r'/wc-api/',
                ],
                "headers": {}
            },
            "drupal": {
                "patterns": [
                    r'Drupal\.settings',
                    r'/sites/default/files/',
                    r'/misc/drupal\.js',
                    r'<meta name="Generator" content="Drupal',
                ],
                "headers": {
                    "x-drupal": r'.',
                    "x-generator": r'drupal'
                }
            },
            "joomla": {
                "patterns": [
                    r'/components/com_',
                    r'/media/jui/',
                    r'<meta name="generator" content="Joomla',
                    r'Joomla!',
                ],
                "headers": {}
            },
            "prestashop": {
                "patterns": [
                    r'prestashop',
                    r'/modules/ps_',
                    r'/themes/classic/',
                ],
                "headers": {
                    "x-prestashop": r'.'
                }
            },
            "opencart": {
                "patterns": [
                    r'catalog/view/theme',
                    r'route=common/',
                    r'OpenCart',
                ],
                "headers": {}
            }
        },
        "frameworks": {
            "react": {
                "patterns": [
                    r'react\.production\.min\.js',
                    r'react-dom',
                    r'__REACT_DEVTOOLS',
                    r'data-reactroot',
                    r'_reactRootContainer',
                ]
            },
            "angular": {
                "patterns": [
                    r'ng-version',
                    r'angular\.js',
                    r'ng-app',
                    r'ng-controller',
                    r'angular\.min\.js',
                ]
            },
            "vue": {
                "patterns": [
                    r'vue\.js',
                    r'vue\.min\.js',
                    r'v-cloak',
                    r'v-bind',
                    r'Vue\.component',
                    r'__vue__',
                ]
            },
            "jquery": {
                "patterns": [
                    r'jquery',
                    r'\$\(document\)',
                    r'\$\(function',
                    r'jQuery',
                ]
            },
            "bootstrap": {
                "patterns": [
                    r'bootstrap\.min\.js',
                    r'bootstrap\.min\.css',
                    r'class="[^"]*btn[^"]*"',
                    r'class="[^"]*container[^"]*"',
                ]
            },
            "laravel": {
                "patterns": [
                    r'laravel',
                    r'csrf-token',
                    r'/storage/app',
                ],
                "headers": {
                    "x-powered-by": r'laravel',
                },
                "cookies": [
                    r'laravel_session',
                    r'XSRF-TOKEN'
                ]
            },
            "django": {
                "patterns": [
                    r'csrfmiddlewaretoken',
                    r'__admin__',
                ],
                "cookies": [
                    r'csrftoken',
                    r'sessionid'
                ]
            },
            "rails": {
                "patterns": [
                    r'csrf-token',
                    r'data-turbolinks',
                    r'rails-ujs',
                ],
                "cookies": [
                    r'_session_id'
                ]
            },
            "express": {
                "headers": {
                    "x-powered-by": r'express'
                }
            },
            "asp.net": {
                "patterns": [
                    r'__VIEWSTATE',
                    r'__EVENTVALIDATION',
                    r'aspnetForm',
                ],
                "headers": {
                    "x-powered-by": r'asp\.net',
                    "x-aspnet-version": r'.'
                },
                "cookies": [
                    r'ASP\.NET_SessionId',
                    r'\.ASPXAUTH'
                ]
            }
        },
        "servers": {
            "nginx": {
                "headers": {
                    "server": r'nginx'
                }
            },
            "apache": {
                "headers": {
                    "server": r'apache'
                }
            },
            "iis": {
                "headers": {
                    "server": r'microsoft-iis'
                }
            },
            "cloudflare": {
                "headers": {
                    "server": r'cloudflare',
                    "cf-ray": r'.'
                }
            },
            "varnish": {
                "headers": {
                    "x-varnish": r'.',
                    "via": r'varnish'
                }
            },
            "litespeed": {
                "headers": {
                    "server": r'litespeed'
                }
            }
        },
        "security": {
            "waf_cloudflare": {
                "headers": {
                    "cf-ray": r'.',
                    "cf-cache-status": r'.'
                }
            },
            "waf_akamai": {
                "headers": {
                    "x-akamai": r'.',
                    "akamai": r'.'
                }
            },
            "waf_sucuri": {
                "headers": {
                    "x-sucuri": r'.',
                    "server": r'sucuri'
                }
            },
            "waf_imperva": {
                "headers": {
                    "x-cdn": r'imperva'
                }
            },
            "waf_modsecurity": {
                "headers": {
                    "server": r'modsecurity'
                }
            }
        },
        "analytics": {
            "google_analytics": {
                "patterns": [
                    r'google-analytics\.com',
                    r'googletagmanager\.com',
                    r'gtag\(',
                    r'ga\(',
                    r'GoogleAnalyticsObject',
                ]
            },
            "hotjar": {
                "patterns": [
                    r'hotjar\.com',
                    r'_hjSettings',
                ]
            },
            "mixpanel": {
                "patterns": [
                    r'mixpanel\.com',
                    r'mixpanel\.track',
                ]
            }
        },
        "payment": {
            "stripe": {
                "patterns": [
                    r'js\.stripe\.com',
                    r'Stripe\(',
                    r'stripe-js',
                ]
            },
            "paypal": {
                "patterns": [
                    r'paypal\.com/sdk',
                    r'paypalobjects\.com',
                    r'paypal\.Buttons',
                ]
            },
            "braintree": {
                "patterns": [
                    r'braintreegateway\.com',
                    r'braintree-web',
                ]
            },
            "adyen": {
                "patterns": [
                    r'adyen\.com',
                    r'AdyenCheckout',
                ]
            },
            "authorize_net": {
                "patterns": [
                    r'authorize\.net',
                    r'Accept\.js',
                ]
            }
        }
    }
    
    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """
        Execute technology detection.
        
        Args:
            action: Detection action
            target: Target URL
            params:
                - detailed: Include detailed evidence
                
        Returns:
            ToolResult with findings
        """
        params = params or {}
        start_time = datetime.now()
        
        self.validate_params(action, params)
        
        if action == "detect":
            result = self._full_detect(target, params)
            
        elif action == "identify_cms":
            result = self._identify_cms(target, params)
            
        elif action == "identify_framework":
            result = self._identify_framework(target, params)
            
        elif action == "identify_server":
            result = self._identify_server(target, params)
            
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
        
    def _full_detect(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Full technology detection."""
        result = {
            "url": url,
            "technologies": {},
            "cms": None,
            "frameworks": [],
            "server": None,
            "waf": None,
            "analytics": [],
            "payment_processors": [],
            "confidence": {}
        }
        
        try:
            # Fetch page and headers
            headers, cookies, content = self._fetch_all(url)
            
            # Check all categories
            for category, techs in self.SIGNATURES.items():
                for tech_name, signatures in techs.items():
                    confidence = self._check_signatures(
                        signatures, headers, cookies, content
                    )
                    
                    if confidence > 0:
                        if category == "cms":
                            if not result["cms"] or confidence > result["confidence"].get("cms", 0):
                                result["cms"] = tech_name
                                result["confidence"]["cms"] = confidence
                        elif category == "frameworks":
                            result["frameworks"].append({
                                "name": tech_name,
                                "confidence": confidence
                            })
                        elif category == "servers":
                            if not result["server"] or confidence > result["confidence"].get("server", 0):
                                result["server"] = tech_name
                                result["confidence"]["server"] = confidence
                        elif category == "security":
                            result["waf"] = tech_name
                        elif category == "analytics":
                            result["analytics"].append(tech_name)
                        elif category == "payment":
                            result["payment_processors"].append(tech_name)
                            
                        result["technologies"][tech_name] = {
                            "category": category,
                            "confidence": confidence
                        }
                        
            # Additional server version detection
            server_header = headers.get("server", "")
            if server_header:
                version_match = re.search(r'[\d.]+', server_header)
                if version_match:
                    result["server_version"] = version_match.group()
                    
            # Detect PHP version
            php_version = headers.get("x-powered-by", "")
            if "php" in php_version.lower():
                version_match = re.search(r'PHP/([\d.]+)', php_version, re.IGNORECASE)
                if version_match:
                    result["php_version"] = version_match.group(1)
                    
        except Exception as e:
            result["error"] = str(e)
            
        return result
        
    def _identify_cms(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Identify CMS specifically."""
        result = {
            "url": url,
            "cms": None,
            "version": None,
            "confidence": 0,
            "evidence": []
        }
        
        try:
            headers, cookies, content = self._fetch_all(url)
            
            best_match = None
            best_confidence = 0
            best_evidence = []
            
            for cms_name, signatures in self.SIGNATURES["cms"].items():
                confidence, evidence = self._check_signatures_detailed(
                    signatures, headers, cookies, content
                )
                
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = cms_name
                    best_evidence = evidence
                    
            if best_match:
                result["cms"] = best_match
                result["confidence"] = best_confidence
                result["evidence"] = best_evidence
                
                # Try to detect version
                version = self._detect_cms_version(best_match, content, headers)
                if version:
                    result["version"] = version
                    
        except Exception as e:
            result["error"] = str(e)
            
        return result
        
    def _identify_framework(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Identify frameworks specifically."""
        result = {
            "url": url,
            "frameworks": [],
            "frontend": [],
            "backend": []
        }
        
        try:
            headers, cookies, content = self._fetch_all(url)
            
            for fw_name, signatures in self.SIGNATURES["frameworks"].items():
                confidence, evidence = self._check_signatures_detailed(
                    signatures, headers, cookies, content
                )
                
                if confidence > 0:
                    fw_info = {
                        "name": fw_name,
                        "confidence": confidence,
                        "evidence": evidence[:3]  # Limit evidence
                    }
                    
                    result["frameworks"].append(fw_info)
                    
                    # Categorize as frontend or backend
                    frontend_fws = ["react", "angular", "vue", "jquery", "bootstrap"]
                    backend_fws = ["laravel", "django", "rails", "express", "asp.net"]
                    
                    if fw_name in frontend_fws:
                        result["frontend"].append(fw_name)
                    elif fw_name in backend_fws:
                        result["backend"].append(fw_name)
                        
        except Exception as e:
            result["error"] = str(e)
            
        return result
        
    def _identify_server(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Identify server and infrastructure."""
        result = {
            "url": url,
            "server": None,
            "server_version": None,
            "os_hint": None,
            "waf": None,
            "cdn": None,
            "headers": {}
        }
        
        try:
            headers, _, _ = self._fetch_all(url)
            
            # Store relevant headers
            relevant_headers = [
                "server", "x-powered-by", "x-aspnet-version",
                "x-generator", "via", "x-cache", "cf-ray"
            ]
            
            for header in relevant_headers:
                if header in headers:
                    result["headers"][header] = headers[header]
                    
            # Detect server
            for server_name, signatures in self.SIGNATURES["servers"].items():
                confidence = self._check_signatures(signatures, headers, {}, "")
                if confidence > 0:
                    result["server"] = server_name
                    break
                    
            # Extract version
            server_header = headers.get("server", "")
            if server_header:
                version_match = re.search(r'[\d.]+', server_header)
                if version_match:
                    result["server_version"] = version_match.group()
                    
                # OS hints
                if "ubuntu" in server_header.lower():
                    result["os_hint"] = "Ubuntu Linux"
                elif "debian" in server_header.lower():
                    result["os_hint"] = "Debian Linux"
                elif "centos" in server_header.lower():
                    result["os_hint"] = "CentOS Linux"
                elif "win" in server_header.lower():
                    result["os_hint"] = "Windows"
                    
            # Detect WAF/CDN
            for security_name, signatures in self.SIGNATURES["security"].items():
                confidence = self._check_signatures(signatures, headers, {}, "")
                if confidence > 0:
                    if "waf" in security_name:
                        result["waf"] = security_name.replace("waf_", "")
                    else:
                        result["cdn"] = security_name
                    break
                    
        except Exception as e:
            result["error"] = str(e)
            
        return result
        
    def _fetch_all(self, url: str) -> tuple:
        """Fetch headers, cookies, and content."""
        headers = {}
        cookies = {}
        content = ""
        
        try:
            # Fetch headers
            cmd = f'curl -s -I -L --connect-timeout 30 "{url}"'
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            
            for line in proc.stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
                    
                    # Extract cookies
                    if key.strip().lower() == 'set-cookie':
                        cookie_parts = value.split(';')[0]
                        if '=' in cookie_parts:
                            c_key, c_val = cookie_parts.split('=', 1)
                            cookies[c_key.strip()] = c_val.strip()
                            
            # Fetch content
            cmd = f'curl -s -L --connect-timeout 30 "{url}"'
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            content = proc.stdout
            
        except Exception:
            pass
            
        return headers, cookies, content
        
    def _check_signatures(
        self,
        signatures: Dict,
        headers: Dict,
        cookies: Dict,
        content: str
    ) -> int:
        """Check signatures and return confidence score."""
        score = 0
        
        # Check patterns in content
        patterns = signatures.get("patterns", [])
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                score += 25
                
        # Check headers
        header_sigs = signatures.get("headers", {})
        for header, pattern in header_sigs.items():
            if header in headers and re.search(pattern, headers[header], re.IGNORECASE):
                score += 35
                
        # Check cookies
        cookie_patterns = signatures.get("cookies", [])
        for pattern in cookie_patterns:
            for cookie_name in cookies.keys():
                if re.search(pattern, cookie_name, re.IGNORECASE):
                    score += 20
                    
        return min(score, 100)
        
    def _check_signatures_detailed(
        self,
        signatures: Dict,
        headers: Dict,
        cookies: Dict,
        content: str
    ) -> tuple:
        """Check signatures and return confidence with evidence."""
        score = 0
        evidence = []
        
        # Check patterns
        patterns = signatures.get("patterns", [])
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                score += 25
                evidence.append(f"Pattern: {match.group()[:50]}")
                
        # Check headers
        header_sigs = signatures.get("headers", {})
        for header, pattern in header_sigs.items():
            if header in headers:
                match = re.search(pattern, headers[header], re.IGNORECASE)
                if match:
                    score += 35
                    evidence.append(f"Header {header}: {headers[header][:50]}")
                    
        # Check cookies
        cookie_patterns = signatures.get("cookies", [])
        for pattern in cookie_patterns:
            for cookie_name in cookies.keys():
                if re.search(pattern, cookie_name, re.IGNORECASE):
                    score += 20
                    evidence.append(f"Cookie: {cookie_name}")
                    
        return min(score, 100), evidence
        
    def _detect_cms_version(
        self,
        cms: str,
        content: str,
        headers: Dict
    ) -> Optional[str]:
        """Try to detect CMS version."""
        version_patterns = {
            "wordpress": [
                r'<meta name="generator" content="WordPress ([\d.]+)"',
                r'wp-includes/version.php.*version\s*=\s*[\'"]([\d.]+)',
            ],
            "magento": [
                r'Magento/([\d.]+)',
                r'Enterprise Edition ([\d.]+)',
            ],
            "drupal": [
                r'<meta name="Generator" content="Drupal ([\d.]+)',
                r'Drupal ([\d.]+)',
            ],
            "joomla": [
                r'<meta name="generator" content="Joomla!?\s*([\d.]+)',
            ],
        }
        
        patterns = version_patterns.get(cms, [])
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return None
        
    def parse_output(self, output: str) -> Dict[str, Any]:
        try:
            return json.loads(output)
        except:
            return {"raw": output}
