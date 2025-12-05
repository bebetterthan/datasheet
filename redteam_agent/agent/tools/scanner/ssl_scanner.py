"""
SSL Scanner Tool
================

SSL/TLS configuration scanner.
"""

import subprocess
import re
import json
from typing import Dict, Any, Optional, List
from datetime import datetime

from agent.tools.base import BaseTool, ToolResult, ToolStatus


class SSLScannerTool(BaseTool):
    """
    SSL/TLS configuration scanner.
    
    Actions:
        - scan: Full SSL scan
        - check_cert: Certificate validation
        - check_protocols: Protocol version check
        - check_ciphers: Cipher suite analysis
    """
    
    name = "ssl_scanner"
    description = "SSL/TLS configuration and certificate scanner"
    category = "scanner"
    
    actions = ["scan", "check_cert", "check_protocols", "check_ciphers"]
    timeout = 60
    
    # Weak protocols
    WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
    
    # Weak ciphers patterns
    WEAK_CIPHER_PATTERNS = [
        r"RC4",
        r"DES",
        r"3DES",
        r"MD5",
        r"NULL",
        r"EXPORT",
        r"anon",
        r"ADH",
        r"AECDH"
    ]
    
    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """
        Execute SSL scan.
        
        Args:
            action: Scan action
            target: Target host (domain:port or domain)
            params:
                - port: Port to scan (default 443)
                - sni: Server Name Indication hostname
                
        Returns:
            ToolResult with findings
        """
        params = params or {}
        start_time = datetime.now()
        
        self.validate_params(action, params)
        
        # Parse target
        if ':' in target:
            host, port = target.rsplit(':', 1)
        else:
            host = target
            port = params.get("port", "443")
            
        # Remove protocol if present
        host = re.sub(r'^https?://', '', host).split('/')[0]
        
        findings = []
        cert_info = {}
        protocols = {}
        ciphers = []
        
        # Get certificate info
        if action in ["scan", "check_cert"]:
            cert_info, cert_findings = self._check_certificate(host, port)
            findings.extend(cert_findings)
            
        # Check protocols
        if action in ["scan", "check_protocols"]:
            protocols, proto_findings = self._check_protocols(host, port)
            findings.extend(proto_findings)
            
        # Check ciphers (basic check with openssl)
        if action in ["scan", "check_ciphers"]:
            ciphers, cipher_findings = self._check_ciphers(host, port)
            findings.extend(cipher_findings)
            
        duration = (datetime.now() - start_time).total_seconds()
        
        parsed = {
            "host": host,
            "port": port,
            "certificate": cert_info,
            "protocols": protocols,
            "ciphers": ciphers,
            "findings": findings,
            "score": self._calculate_score(findings)
        }
        
        return ToolResult(
            status=ToolStatus.SUCCESS,
            output=json.dumps(parsed, indent=2),
            parsed=parsed,
            duration=duration,
            metadata={
                "action": action,
                "target": f"{host}:{port}",
                "findings_count": len(findings)
            }
        )
        
    def _check_certificate(
        self,
        host: str,
        port: str
    ) -> tuple:
        """Check SSL certificate."""
        findings = []
        cert_info = {}
        
        try:
            # Get certificate using openssl
            cmd = f'echo | openssl s_client -connect {host}:{port} -servername {host} 2>/dev/null | openssl x509 -noout -dates -subject -issuer -text 2>/dev/null'
            
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = result.stdout
            
            # Parse subject
            subject_match = re.search(r'subject=(.+)', output)
            if subject_match:
                cert_info["subject"] = subject_match.group(1).strip()
                
            # Parse issuer
            issuer_match = re.search(r'issuer=(.+)', output)
            if issuer_match:
                cert_info["issuer"] = issuer_match.group(1).strip()
                
            # Parse dates
            not_before = re.search(r'notBefore=(.+)', output)
            not_after = re.search(r'notAfter=(.+)', output)
            
            if not_before:
                cert_info["not_before"] = not_before.group(1).strip()
            if not_after:
                cert_info["not_after"] = not_after.group(1).strip()
                # Check expiration
                self._check_expiration(not_after.group(1), findings)
                
            # Check for self-signed
            if cert_info.get("subject") == cert_info.get("issuer"):
                findings.append({
                    "type": "self_signed",
                    "severity": "high",
                    "description": "Certificate appears to be self-signed",
                    "recommendation": "Use a certificate from a trusted CA"
                })
                
            # Check for wildcard
            if "*." in str(cert_info.get("subject", "")):
                findings.append({
                    "type": "wildcard_cert",
                    "severity": "info",
                    "description": "Wildcard certificate in use",
                    "recommendation": "Consider if wildcard is necessary"
                })
                
            # Parse SANs
            san_match = re.search(r'Subject Alternative Name:([^X]+)', output, re.DOTALL)
            if san_match:
                sans = re.findall(r'DNS:([^,\s]+)', san_match.group(1))
                cert_info["san"] = sans
                
        except subprocess.TimeoutExpired:
            findings.append({
                "type": "timeout",
                "severity": "medium",
                "description": "Certificate check timed out"
            })
        except Exception as e:
            self.logger.error(f"Certificate check error: {e}")
            
        return cert_info, findings
        
    def _check_expiration(self, date_str: str, findings: List[Dict]):
        """Check certificate expiration."""
        try:
            from datetime import datetime
            # Parse date (format: Apr 15 12:00:00 2024 GMT)
            date_str = date_str.strip()
            cert_date = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
            now = datetime.now()
            
            days_until_expiry = (cert_date - now).days
            
            if days_until_expiry < 0:
                findings.append({
                    "type": "expired_cert",
                    "severity": "critical",
                    "description": f"Certificate expired {-days_until_expiry} days ago",
                    "recommendation": "Renew certificate immediately"
                })
            elif days_until_expiry < 30:
                findings.append({
                    "type": "expiring_soon",
                    "severity": "high",
                    "description": f"Certificate expires in {days_until_expiry} days",
                    "recommendation": "Renew certificate soon"
                })
            elif days_until_expiry < 90:
                findings.append({
                    "type": "expiring_soon",
                    "severity": "medium",
                    "description": f"Certificate expires in {days_until_expiry} days",
                    "recommendation": "Plan certificate renewal"
                })
                
        except Exception as e:
            self.logger.debug(f"Date parse error: {e}")
            
    def _check_protocols(
        self,
        host: str,
        port: str
    ) -> tuple:
        """Check supported SSL/TLS protocols."""
        findings = []
        protocols = {}
        
        protocol_flags = {
            "SSLv3": "-ssl3",
            "TLSv1.0": "-tls1",
            "TLSv1.1": "-tls1_1",
            "TLSv1.2": "-tls1_2",
            "TLSv1.3": "-tls1_3"
        }
        
        for proto, flag in protocol_flags.items():
            try:
                cmd = f'echo | openssl s_client {flag} -connect {host}:{port} 2>&1'
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                # Check if connection succeeded
                if "CONNECTED" in result.stdout and "error" not in result.stderr.lower():
                    protocols[proto] = True
                    
                    if proto in self.WEAK_PROTOCOLS:
                        findings.append({
                            "type": "weak_protocol",
                            "severity": "high" if proto in ["SSLv2", "SSLv3"] else "medium",
                            "protocol": proto,
                            "description": f"Weak protocol {proto} is supported",
                            "recommendation": f"Disable {proto}"
                        })
                else:
                    protocols[proto] = False
                    
            except:
                protocols[proto] = "unknown"
                
        # Check if TLSv1.2/1.3 is supported
        if not protocols.get("TLSv1.2") and not protocols.get("TLSv1.3"):
            findings.append({
                "type": "no_modern_tls",
                "severity": "high",
                "description": "Neither TLSv1.2 nor TLSv1.3 is supported",
                "recommendation": "Enable TLSv1.2 or TLSv1.3"
            })
            
        return protocols, findings
        
    def _check_ciphers(
        self,
        host: str,
        port: str
    ) -> tuple:
        """Check cipher suites."""
        findings = []
        ciphers = []
        
        try:
            # Get cipher list
            cmd = f'echo | openssl s_client -connect {host}:{port} -cipher ALL 2>/dev/null | grep "Cipher is"'
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=15
            )
            
            cipher_match = re.search(r'Cipher is (.+)', result.stdout)
            if cipher_match:
                cipher = cipher_match.group(1).strip()
                ciphers.append(cipher)
                
                # Check for weak ciphers
                for pattern in self.WEAK_CIPHER_PATTERNS:
                    if re.search(pattern, cipher, re.IGNORECASE):
                        findings.append({
                            "type": "weak_cipher",
                            "severity": "high",
                            "cipher": cipher,
                            "pattern": pattern,
                            "description": f"Weak cipher in use: {cipher}",
                            "recommendation": "Disable weak cipher suites"
                        })
                        break
                        
        except Exception as e:
            self.logger.debug(f"Cipher check error: {e}")
            
        return ciphers, findings
        
    def _calculate_score(self, findings: List[Dict[str, Any]]) -> int:
        """Calculate SSL security score."""
        score = 100
        
        severity_penalties = {
            "critical": 30,
            "high": 20,
            "medium": 10,
            "low": 5,
            "info": 0
        }
        
        for finding in findings:
            severity = finding.get("severity", "info")
            score -= severity_penalties.get(severity, 0)
            
        return max(0, min(100, score))
        
    def parse_output(self, output: str) -> Dict[str, Any]:
        try:
            return json.loads(output)
        except:
            return {"raw": output}
