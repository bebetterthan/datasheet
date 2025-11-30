"""
Category classifier for security content.
Automatically categorizes content based on keywords and patterns.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict


@dataclass
class CategoryMatch:
    """Result of category matching."""
    primary_category: str
    subcategory: Optional[str]
    confidence: float
    all_matches: Dict[str, float]
    tags: List[str]


class CategoryClassifier:
    """
    Classifies security content into categories.
    Uses keyword matching and pattern recognition.
    """
    
    # Main category definitions with keywords and patterns
    CATEGORIES = {
        "reconnaissance": {
            "keywords": [
                "recon", "reconnaissance", "enumeration", "scanning", "osint",
                "footprinting", "information gathering", "discovery", "dns",
                "subdomain", "whois", "nmap", "masscan", "shodan", "censys",
                "google dork", "theHarvester", "amass", "subfinder"
            ],
            "patterns": [
                r"nmap\s+-", r"dig\s+", r"host\s+", r"whois\s+",
                r"enumerate\s+\w+", r"scan\s+(for|the)"
            ],
            "subcategories": {
                "network_scanning": ["nmap", "masscan", "port scan", "service detection"],
                "osint": ["osint", "google dork", "shodan", "social media"],
                "subdomain_enum": ["subdomain", "dns enum", "amass", "subfinder"],
                "web_recon": ["dirb", "gobuster", "ffuf", "web enum"],
            }
        },
        "exploitation": {
            "keywords": [
                "exploit", "exploitation", "payload", "shell", "reverse shell",
                "bind shell", "rce", "remote code execution", "code execution",
                "metasploit", "msfvenom", "searchsploit", "poc", "proof of concept"
            ],
            "patterns": [
                r"exploit\s+\w+", r"reverse\s+shell", r"bind\s+shell",
                r"msfvenom\s+", r"nc\s+-[lv]", r"python\s+-c"
            ],
            "subcategories": {
                "web_exploitation": ["web exploit", "http", "web shell"],
                "binary_exploitation": ["buffer overflow", "bof", "stack", "heap", "rop"],
                "network_exploitation": ["smb", "ssh", "ftp", "telnet", "network exploit"],
            }
        },
        "web_security": {
            "keywords": [
                "sql injection", "sqli", "xss", "cross-site scripting",
                "xxe", "xml external entity", "ssrf", "server-side request",
                "csrf", "cross-site request forgery", "idor", "lfi", "rfi",
                "file inclusion", "path traversal", "directory traversal",
                "deserialization", "ssti", "template injection", "csp bypass",
                "burp", "burpsuite", "owasp", "web vulnerability"
            ],
            "patterns": [
                r"sql\s*injection", r"xss", r"union\s+select",
                r"<script>", r"\.\./\.\.", r"php://", r"data://"
            ],
            "subcategories": {
                "sql_injection": ["sqli", "sql injection", "union", "blind sql"],
                "xss": ["xss", "cross-site scripting", "reflected", "stored xss"],
                "ssrf": ["ssrf", "server-side request forgery"],
                "file_inclusion": ["lfi", "rfi", "file inclusion", "path traversal"],
                "deserialization": ["deserialize", "pickle", "yaml.load", "unserialize"],
            }
        },
        "privilege_escalation": {
            "keywords": [
                "privilege escalation", "privesc", "priv esc", "root",
                "administrator", "sudo", "suid", "capabilities", "gtfobins",
                "lolbas", "uac bypass", "token impersonation", "potato",
                "lateral movement", "linpeas", "winpeas", "linux privesc",
                "windows privesc"
            ],
            "patterns": [
                r"sudo\s+-l", r"find\s+.*-perm", r"getcap",
                r"whoami\s*/priv", r"SeImpersonate"
            ],
            "subcategories": {
                "linux_privesc": ["linux", "sudo", "suid", "capabilities", "cron"],
                "windows_privesc": ["windows", "uac", "token", "potato", "service"],
                "container_escape": ["docker", "container", "kubernetes", "escape"],
            }
        },
        "credential_access": {
            "keywords": [
                "credential", "password", "hash", "ntlm", "kerberos",
                "mimikatz", "secretsdump", "hashcat", "john", "brute force",
                "dictionary attack", "pass the hash", "pth", "golden ticket",
                "silver ticket", "asreproast", "kerberoast", "lsass"
            ],
            "patterns": [
                r"mimikatz", r"sekurlsa::", r"hashcat\s+",
                r"john\s+", r"GetNPUsers", r"GetUserSPNs"
            ],
            "subcategories": {
                "password_cracking": ["hashcat", "john", "crack", "brute"],
                "credential_dumping": ["mimikatz", "lsass", "sam", "secretsdump"],
                "kerberos_attacks": ["kerberoast", "asreproast", "golden", "silver ticket"],
            }
        },
        "persistence": {
            "keywords": [
                "persistence", "backdoor", "implant", "rootkit", "webshell",
                "scheduled task", "cron job", "registry", "startup",
                "service installation", "dll hijacking", "com hijacking"
            ],
            "patterns": [
                r"crontab\s+-", r"schtasks\s+", r"reg\s+add",
                r"webshell", r"reverse.*persistent"
            ],
            "subcategories": {
                "webshell": ["webshell", "web shell", "php shell"],
                "scheduled_task": ["cron", "scheduled task", "at job"],
                "registry_persistence": ["registry", "run key", "startup"],
            }
        },
        "defense_evasion": {
            "keywords": [
                "evasion", "bypass", "obfuscation", "encoding", "antivirus",
                "av bypass", "edr", "amsi bypass", "applocker bypass",
                "uac bypass", "disable defender", "process injection",
                "dll injection", "shellcode", "packer"
            ],
            "patterns": [
                r"amsi.*bypass", r"disable.*defender", r"av.*evasion",
                r"base64.*encode", r"powershell.*-enc"
            ],
            "subcategories": {
                "av_evasion": ["antivirus", "av bypass", "edr", "defender"],
                "amsi_bypass": ["amsi", "powershell bypass"],
                "obfuscation": ["obfuscate", "encode", "encrypt", "packer"],
            }
        },
        "cloud_security": {
            "keywords": [
                "aws", "azure", "gcp", "google cloud", "cloud", "s3",
                "ec2", "iam", "lambda", "kubernetes", "k8s", "docker",
                "container", "terraform", "cloudformation", "metadata",
                "imds", "instance metadata", "cloud enum"
            ],
            "patterns": [
                r"aws\s+\w+", r"az\s+\w+", r"gcloud\s+",
                r"kubectl\s+", r"docker\s+", r"169\.254\.169\.254"
            ],
            "subcategories": {
                "aws": ["aws", "s3", "ec2", "iam", "lambda"],
                "azure": ["azure", "blob", "active directory"],
                "gcp": ["gcp", "google cloud", "gke"],
                "kubernetes": ["kubernetes", "k8s", "kubectl", "pod"],
                "docker": ["docker", "container", "dockerfile"],
            }
        },
        "network_security": {
            "keywords": [
                "network", "firewall", "ids", "ips", "packet", "tcp",
                "udp", "icmp", "arp", "mitm", "man in the middle",
                "sniffing", "wireshark", "tcpdump", "responder",
                "relay attack", "dns poisoning"
            ],
            "patterns": [
                r"tcpdump\s+", r"wireshark", r"tshark\s+",
                r"iptables\s+", r"netcat|nc\s+"
            ],
            "subcategories": {
                "packet_analysis": ["wireshark", "tcpdump", "packet"],
                "mitm": ["mitm", "arp", "responder", "relay"],
                "firewall": ["firewall", "iptables", "ufw"],
            }
        },
        "mobile_security": {
            "keywords": [
                "android", "ios", "mobile", "apk", "ipa", "frida",
                "objection", "jadx", "apktool", "mobile pentest",
                "certificate pinning", "root detection", "jailbreak"
            ],
            "patterns": [
                r"frida\s+", r"objection\s+", r"apktool\s+",
                r"adb\s+", r"drozer"
            ],
            "subcategories": {
                "android": ["android", "apk", "adb", "jadx"],
                "ios": ["ios", "ipa", "jailbreak", "cycript"],
            }
        },
        "cryptography": {
            "keywords": [
                "crypto", "cryptography", "encryption", "decryption",
                "hash", "rsa", "aes", "des", "cipher", "openssl",
                "certificate", "ssl", "tls", "pgp", "gpg"
            ],
            "patterns": [
                r"openssl\s+", r"hashlib\.", r"crypto\.",
                r"encrypt|decrypt", r"base64"
            ],
            "subcategories": {
                "encryption": ["encrypt", "decrypt", "aes", "rsa", "cipher"],
                "hashing": ["hash", "md5", "sha", "bcrypt"],
                "ssl_tls": ["ssl", "tls", "certificate", "openssl"],
            }
        },
        "forensics": {
            "keywords": [
                "forensics", "incident response", "memory forensics",
                "disk forensics", "volatility", "autopsy", "sleuthkit",
                "timeline", "artifact", "malware analysis", "reverse engineering",
                "strings", "ghidra", "ida", "binary ninja"
            ],
            "patterns": [
                r"volatility\s+", r"strings\s+", r"file\s+",
                r"binwalk\s+", r"foremost\s+"
            ],
            "subcategories": {
                "memory_forensics": ["memory", "volatility", "ram", "dump"],
                "disk_forensics": ["disk", "autopsy", "sleuthkit", "carving"],
                "malware_analysis": ["malware", "reverse", "ghidra", "ida"],
            }
        },
        "social_engineering": {
            "keywords": [
                "phishing", "social engineering", "pretexting", "vishing",
                "smishing", "spear phishing", "gophish", "evilginx",
                "credential harvesting", "clone site"
            ],
            "patterns": [
                r"phish", r"social\s+engineer", r"gophish",
                r"evilginx", r"setoolkit"
            ],
            "subcategories": {
                "phishing": ["phishing", "gophish", "evilginx"],
                "vishing": ["vishing", "voice", "phone"],
            }
        },
    }
    
    # Difficulty indicators
    DIFFICULTY_INDICATORS = {
        "beginner": [
            "basic", "introduction", "beginner", "simple", "easy",
            "getting started", "first step", "fundamental", "101"
        ],
        "intermediate": [
            "intermediate", "moderate", "standard", "common",
            "typical", "regular", "practical"
        ],
        "advanced": [
            "advanced", "expert", "complex", "sophisticated",
            "deep dive", "in-depth", "cutting edge", "novel"
        ]
    }
    
    def __init__(
        self,
        custom_categories: Optional[Dict] = None,
        min_confidence: float = 0.1,
    ):
        """
        Initialize classifier.
        
        Args:
            custom_categories: Additional custom categories
            min_confidence: Minimum confidence for category match
        """
        self.categories = self.CATEGORIES.copy()
        if custom_categories:
            self.categories.update(custom_categories)
        self.min_confidence = min_confidence
        
        # Pre-compile patterns
        self._compiled_patterns = {}
        for cat, data in self.categories.items():
            patterns = data.get("patterns", [])
            self._compiled_patterns[cat] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
    
    def classify(
        self,
        text: str,
        return_all_matches: bool = False,
    ) -> CategoryMatch:
        """
        Classify text into a category.
        
        Args:
            text: Text to classify
            return_all_matches: Include all matching categories
            
        Returns:
            CategoryMatch with classification results
        """
        text_lower = text.lower()
        scores = {}
        subcategory_matches = {}
        all_tags = set()
        
        for category, data in self.categories.items():
            score = 0.0
            matched_sub = None
            
            # Keyword matching
            keywords = data.get("keywords", [])
            keyword_matches = sum(1 for kw in keywords if kw in text_lower)
            score += keyword_matches * 0.1
            
            # Pattern matching (weighted higher)
            patterns = self._compiled_patterns.get(category, [])
            pattern_matches = sum(1 for p in patterns if p.search(text_lower))
            score += pattern_matches * 0.2
            
            # Subcategory matching
            subcategories = data.get("subcategories", {})
            for subcat, sub_keywords in subcategories.items():
                sub_matches = sum(1 for kw in sub_keywords if kw in text_lower)
                if sub_matches > 0:
                    if matched_sub is None or sub_matches > subcategory_matches.get(category, 0):
                        matched_sub = subcat
                        subcategory_matches[category] = sub_matches
                    # Add subcategory keywords as tags
                    for kw in sub_keywords:
                        if kw in text_lower:
                            all_tags.add(kw)
            
            # Normalize score
            max_possible = len(keywords) * 0.1 + len(patterns) * 0.2
            if max_possible > 0:
                score = min(1.0, score / max_possible)
            
            if score >= self.min_confidence:
                scores[category] = score
                if matched_sub:
                    scores[f"{category}/{matched_sub}"] = score
        
        # Find primary category
        if not scores:
            return CategoryMatch(
                primary_category="uncategorized",
                subcategory=None,
                confidence=0.0,
                all_matches={},
                tags=list(all_tags),
            )
        
        # Get highest scoring category
        primary = max(scores.items(), key=lambda x: x[1])
        primary_cat = primary[0].split('/')[0]
        primary_sub = primary[0].split('/')[1] if '/' in primary[0] else None
        
        return CategoryMatch(
            primary_category=primary_cat,
            subcategory=primary_sub,
            confidence=primary[1],
            all_matches=scores if return_all_matches else {},
            tags=list(all_tags),
        )
    
    def classify_sample(
        self,
        sample: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Classify a sample and add category information.
        
        Args:
            sample: Sample dictionary
            
        Returns:
            Sample with category, tags, and difficulty added
        """
        # Combine relevant text fields
        text_parts = []
        for field in ['instruction', 'input', 'output', 'title']:
            if field in sample and sample[field]:
                text_parts.append(str(sample[field]))
        
        combined_text = ' '.join(text_parts)
        
        # Classify
        result = self.classify(combined_text, return_all_matches=False)
        
        # Determine difficulty
        difficulty = self._determine_difficulty(combined_text)
        
        # Generate tags
        tags = list(set(result.tags + self._extract_tags(combined_text)))
        
        # Update sample
        updated = sample.copy()
        
        if result.subcategory:
            updated['category'] = f"{result.primary_category}/{result.subcategory}"
        else:
            updated['category'] = result.primary_category
        
        updated['difficulty'] = difficulty
        
        # Merge existing tags with new ones
        existing_tags = sample.get('tags', [])
        if isinstance(existing_tags, list):
            tags = list(set(existing_tags + tags))
        updated['tags'] = tags[:10]  # Limit to 10 tags
        
        return updated
    
    def _determine_difficulty(self, text: str) -> str:
        """Determine difficulty level from text."""
        text_lower = text.lower()
        
        scores = {}
        for level, indicators in self.DIFFICULTY_INDICATORS.items():
            score = sum(1 for ind in indicators if ind in text_lower)
            scores[level] = score
        
        if not any(scores.values()):
            return "intermediate"  # Default
        
        return max(scores.items(), key=lambda x: x[1])[0]
    
    def _extract_tags(self, text: str) -> List[str]:
        """Extract additional tags from text."""
        tags = []
        text_lower = text.lower()
        
        # Extract tool names
        tools = [
            "nmap", "burp", "metasploit", "sqlmap", "nikto", "dirb",
            "gobuster", "hydra", "john", "hashcat", "wireshark",
            "volatility", "ghidra", "frida", "mimikatz"
        ]
        for tool in tools:
            if tool in text_lower:
                tags.append(tool)
        
        # Extract CVE references
        cve_pattern = r'cve-\d{4}-\d+' 
        cves = re.findall(cve_pattern, text_lower)
        tags.extend(cves)
        
        # Extract common acronyms
        acronyms = ["rce", "sqli", "xss", "lfi", "rfi", "xxe", "ssrf", "idor"]
        for acr in acronyms:
            if re.search(rf'\b{acr}\b', text_lower):
                tags.append(acr)
        
        return tags[:20]  # Limit extracted tags
    
    def get_category_stats(
        self,
        samples: List[Dict[str, Any]],
    ) -> Dict[str, int]:
        """Get category distribution statistics."""
        stats = defaultdict(int)
        
        for sample in samples:
            category = sample.get('category', 'uncategorized')
            stats[category] += 1
        
        return dict(sorted(stats.items(), key=lambda x: x[1], reverse=True))
