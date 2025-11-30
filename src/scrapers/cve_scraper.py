"""
CVE Database scraper - scrapes vulnerability information from NVD and other sources.
Target: NVD API, CVE Details, GitHub Advisory Database
"""

import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import json

from .base_scraper import BaseScraper, ScrapedItem
from ..utils.logger import get_logger

logger = get_logger(__name__)


class CVEScraper(BaseScraper):
    """
    Scraper for CVE databases.
    Uses NVD API and supplementary sources.
    """
    
    SOURCE_NAME = "cve"
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Alternative sources
    GITHUB_ADVISORY_API = "https://api.github.com/advisories"
    CVE_DETAILS_URL = "https://www.cvedetails.com"
    
    # CVSS severity thresholds
    SEVERITY_LEVELS = {
        'critical': (9.0, 10.0),
        'high': (7.0, 8.9),
        'medium': (4.0, 6.9),
        'low': (0.1, 3.9),
    }
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._discovered_cves: List[str] = []
    
    async def discover_urls(self) -> List[str]:
        """Discover CVE IDs to scrape."""
        if self._discovered_cves:
            return self._discovered_cves
        
        logger.info("Discovering CVEs from NVD...")
        
        cve_ids = []
        
        # Get recent high-severity CVEs
        cve_ids.extend(await self._discover_from_nvd())
        
        # Get security-relevant CVEs from GitHub
        github_cves = await self._discover_from_github()
        cve_ids.extend(github_cves)
        
        self._discovered_cves = list(set(cve_ids))
        logger.info(f"Discovered {len(self._discovered_cves)} CVEs")
        
        return self._discovered_cves
    
    async def _discover_from_nvd(self) -> List[str]:
        """Discover CVEs from NVD API."""
        cve_ids = []
        
        # Get minimum CVSS score from config
        min_cvss = 7.0
        if self.source_config and hasattr(self.source_config, 'min_cvss'):
            min_cvss = self.source_config.min_cvss
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=365)  # Last year
        
        # NVD API parameters
        params = {
            'cvssV3Severity': 'CRITICAL,HIGH' if min_cvss >= 7.0 else 'CRITICAL,HIGH,MEDIUM',
            'pubStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT23:59:59.999'),
            'resultsPerPage': 100,
        }
        
        try:
            # Build URL with params
            param_str = '&'.join(f'{k}={v}' for k, v in params.items())
            url = f"{self.BASE_URL}?{param_str}"
            
            response_text = await self.fetch_page(url)
            if response_text:
                data = json.loads(response_text)
                
                vulnerabilities = data.get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    cve_data = vuln.get('cve', {})
                    cve_id = cve_data.get('id', '')
                    if cve_id:
                        cve_ids.append(cve_id)
                
                logger.info(f"Found {len(cve_ids)} CVEs from NVD")
        
        except Exception as e:
            logger.error(f"Error fetching from NVD: {e}")
        
        return cve_ids
    
    async def _discover_from_github(self) -> List[str]:
        """Discover CVEs from GitHub Advisory Database."""
        cve_ids = []
        
        try:
            # GitHub API requires authentication for better rate limits
            headers = {}
            github_token = None
            
            # Try to get token from config
            if hasattr(self, 'config'):
                github_token = getattr(self.config, 'github_token', None)
            
            if github_token:
                headers['Authorization'] = f'token {github_token}'
            
            # Fetch advisories
            url = f"{self.GITHUB_ADVISORY_API}?type=reviewed&per_page=100"
            
            response_text = await self.fetch_page(url)
            if response_text:
                advisories = json.loads(response_text)
                
                for advisory in advisories:
                    cve_id = advisory.get('cve_id', '')
                    if cve_id and cve_id.startswith('CVE-'):
                        cve_ids.append(cve_id)
                
                logger.info(f"Found {len(cve_ids)} CVEs from GitHub")
        
        except Exception as e:
            logger.debug(f"Error fetching from GitHub: {e}")
        
        return cve_ids
    
    async def scrape_page(self, cve_id: str) -> Optional[ScrapedItem]:
        """Scrape details for a specific CVE."""
        try:
            # Fetch from NVD API
            url = f"{self.BASE_URL}?cveId={cve_id}"
            
            response_text = await self.fetch_page(url)
            if not response_text:
                return None
            
            data = json.loads(response_text)
            vulnerabilities = data.get('vulnerabilities', [])
            
            if not vulnerabilities:
                return None
            
            cve_data = vulnerabilities[0].get('cve', {})
            
            return self._parse_nvd_cve(cve_id, cve_data)
        
        except Exception as e:
            logger.error(f"Error scraping CVE {cve_id}: {e}")
            return None
    
    def _parse_nvd_cve(self, cve_id: str, cve_data: Dict) -> Optional[ScrapedItem]:
        """Parse CVE data from NVD response."""
        # Extract description
        descriptions = cve_data.get('descriptions', [])
        description = ""
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        
        if not description:
            return None
        
        # Extract CVSS scores
        metrics = cve_data.get('metrics', {})
        cvss_v3 = None
        cvss_score = 0.0
        severity = ""
        vector = ""
        
        if 'cvssMetricV31' in metrics:
            cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
            cvss_score = cvss_data.get('baseScore', 0.0)
            severity = cvss_data.get('baseSeverity', '')
            vector = cvss_data.get('vectorString', '')
        elif 'cvssMetricV30' in metrics:
            cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
            cvss_score = cvss_data.get('baseScore', 0.0)
            severity = cvss_data.get('baseSeverity', '')
            vector = cvss_data.get('vectorString', '')
        
        # Extract CWE
        weaknesses = cve_data.get('weaknesses', [])
        cwe_ids = []
        for weakness in weaknesses:
            for desc in weakness.get('description', []):
                if desc.get('lang') == 'en':
                    cwe_ids.append(desc.get('value', ''))
        
        # Extract affected products
        configurations = cve_data.get('configurations', [])
        affected_products = []
        
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe in cpe_matches:
                    if cpe.get('vulnerable'):
                        affected_products.append(cpe.get('criteria', ''))
        
        # Extract references (potential PoC links)
        references = cve_data.get('references', [])
        ref_urls = []
        poc_urls = []
        
        for ref in references:
            url = ref.get('url', '')
            tags = ref.get('tags', [])
            
            if 'Exploit' in tags or 'Third Party Advisory' in tags:
                poc_urls.append(url)
            ref_urls.append(url)
        
        # Build content
        content_parts = [
            f"# {cve_id}",
            f"\n## Description\n{description}",
        ]
        
        if cvss_score:
            content_parts.append(f"\n## CVSS Score\n- Score: {cvss_score}")
            content_parts.append(f"- Severity: {severity}")
            content_parts.append(f"- Vector: {vector}")
        
        if cwe_ids:
            content_parts.append(f"\n## Weaknesses\n- " + "\n- ".join(cwe_ids))
        
        if affected_products[:5]:  # Limit to 5
            content_parts.append(f"\n## Affected Products\n- " + "\n- ".join(affected_products[:5]))
        
        if poc_urls[:3]:  # Limit to 3
            content_parts.append(f"\n## References (Potential PoC)\n- " + "\n- ".join(poc_urls[:3]))
        
        content = '\n'.join(content_parts)
        
        # Determine category from CWE
        category = self._determine_category_from_cwe(cwe_ids, description)
        
        # Determine difficulty based on CVSS
        difficulty = self._determine_difficulty(cvss_score)
        
        return ScrapedItem(
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            title=f"{cve_id}: {description[:100]}...",
            content=content,
            code_blocks=[],
            headers=[],
            metadata={
                'category': category,
                'difficulty': difficulty,
                'source_type': 'nvd',
                'cve_id': cve_id,
                'cvss_score': cvss_score,
                'severity': severity,
                'cwe_ids': cwe_ids,
                'affected_products': affected_products[:10],
                'poc_urls': poc_urls,
            }
        )
    
    def _determine_category_from_cwe(self, cwe_ids: List[str], description: str) -> str:
        """Determine category from CWE and description."""
        text = ' '.join(cwe_ids + [description]).lower()
        
        # CWE to category mapping
        cwe_mappings = {
            'cwe-89': 'web_security/sql_injection',
            'cwe-79': 'web_security/xss',
            'cwe-94': 'exploitation/code_injection',
            'cwe-78': 'exploitation/command_injection',
            'cwe-22': 'web_security/path_traversal',
            'cwe-434': 'web_security/file_upload',
            'cwe-918': 'web_security/ssrf',
            'cwe-611': 'web_security/xxe',
            'cwe-502': 'web_security/deserialization',
            'cwe-287': 'credential_access/authentication',
            'cwe-798': 'credential_access/hardcoded_credentials',
            'cwe-120': 'exploitation/buffer_overflow',
            'cwe-416': 'exploitation/use_after_free',
            'cwe-190': 'exploitation/integer_overflow',
        }
        
        for cwe in cwe_ids:
            cwe_lower = cwe.lower()
            if cwe_lower in cwe_mappings:
                return cwe_mappings[cwe_lower]
        
        # Fallback to description analysis
        if 'sql injection' in text:
            return 'web_security/sql_injection'
        if 'cross-site scripting' in text or 'xss' in text:
            return 'web_security/xss'
        if 'remote code execution' in text:
            return 'exploitation/rce'
        if 'privilege escalation' in text:
            return 'privilege_escalation'
        if 'buffer overflow' in text:
            return 'exploitation/buffer_overflow'
        
        return 'security/vulnerability'
    
    def _determine_difficulty(self, cvss_score: float) -> str:
        """Determine difficulty based on CVSS score."""
        # Lower CVSS often means more complex exploitation
        if cvss_score >= 9.0:
            return 'beginner'  # Easy to exploit
        elif cvss_score >= 7.0:
            return 'intermediate'
        else:
            return 'advanced'  # Harder to exploit
    
    def generate_qa_from_item(self, item: ScrapedItem) -> List[Dict[str, Any]]:
        """Generate Q&A pairs from CVE item."""
        qa_pairs = []
        
        cve_id = item.metadata.get('cve_id', '')
        cvss_score = item.metadata.get('cvss_score', 0)
        cwe_ids = item.metadata.get('cwe_ids', [])
        
        # Understanding the vulnerability
        qa_pairs.append({
            'instruction': f"Explain the vulnerability {cve_id}. What is the impact and how severe is it?",
            'input': '',
            'output': item.content,
            'category': item.metadata.get('category', 'security/vulnerability'),
            'source': item.url,
            'difficulty': item.metadata.get('difficulty', 'intermediate'),
            'tags': [cve_id.lower(), item.metadata.get('severity', '').lower()] + [cwe.lower() for cwe in cwe_ids],
        })
        
        # Detection and mitigation
        if cvss_score >= 7.0:
            qa_pairs.append({
                'instruction': f"How can I detect and mitigate {cve_id}?",
                'input': f"CVSS Score: {cvss_score}",
                'output': f"To detect {cve_id}:\n1. Check if affected products are in use\n2. Use vulnerability scanners\n3. Review security advisories\n\nMitigation:\n1. Apply vendor patches\n2. Implement compensating controls\n3. Monitor for exploitation attempts",
                'category': 'defense/vulnerability_management',
                'source': item.url,
                'difficulty': 'intermediate',
                'tags': [cve_id.lower(), 'detection', 'mitigation'],
            })
        
        return qa_pairs
