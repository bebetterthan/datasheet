"""
MITRE ATT&CK Framework scraper.
Target: https://attack.mitre.org
HIGH PRIORITY for: Attack techniques, tactics, procedures (TTPs)
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from .base_scraper import BaseScraper, ScrapedItem
from ..utils.logger import get_logger

logger = get_logger(__name__)


class MitreAttackScraper(BaseScraper):
    """
    Scraper for MITRE ATT&CK Framework.
    Comprehensive adversary tactics and techniques.
    """
    
    SOURCE_NAME = "mitre_attack"
    BASE_URL = "https://attack.mitre.org"
    
    # ATT&CK Matrices
    MATRICES = {
        'enterprise': '/matrices/enterprise/',
        'mobile': '/matrices/mobile/',
        'ics': '/matrices/ics/',
    }
    
    # Tactic categories
    TACTICS = [
        'reconnaissance', 'resource-development', 'initial-access',
        'execution', 'persistence', 'privilege-escalation',
        'defense-evasion', 'credential-access', 'discovery',
        'lateral-movement', 'collection', 'command-and-control',
        'exfiltration', 'impact'
    ]
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._discovered_urls: List[Dict] = []
    
    async def discover_urls(self) -> List[str]:
        """Discover ATT&CK techniques."""
        if self._discovered_urls:
            return [d['url'] for d in self._discovered_urls]
        
        logger.info("Discovering MITRE ATT&CK techniques...")
        
        urls = []
        
        # Discover techniques from enterprise matrix (most comprehensive)
        techniques = await self._discover_techniques()
        urls.extend(techniques)
        
        # Discover tactics
        tactics = await self._discover_tactics()
        urls.extend(tactics)
        
        # Discover software/tools
        software = await self._discover_software()
        urls.extend(software)
        
        # Discover groups (threat actors)
        groups = await self._discover_groups()
        urls.extend(groups)
        
        self._discovered_urls = urls
        logger.info(f"Discovered {len(urls)} ATT&CK entries")
        
        return [d['url'] for d in urls]
    
    async def _discover_techniques(self) -> List[Dict]:
        """Discover all techniques."""
        urls = []
        
        techniques_url = f"{self.BASE_URL}/techniques/enterprise/"
        html = await self.fetch_page(techniques_url)
        
        if not html:
            return urls
        
        soup = BeautifulSoup(html, 'lxml')
        
        # Find technique links
        for link in soup.find_all('a', href=re.compile(r'/techniques/T\d+')):
            href = link.get('href', '')
            if href:
                full_url = urljoin(self.BASE_URL, href)
                technique_id = re.search(r'T\d+', href)
                
                urls.append({
                    'url': full_url,
                    'type': 'technique',
                    'id': technique_id.group() if technique_id else '',
                })
        
        return urls
    
    async def _discover_tactics(self) -> List[Dict]:
        """Discover all tactics."""
        urls = []
        
        for tactic in self.TACTICS:
            tactic_url = f"{self.BASE_URL}/tactics/TA{self.TACTICS.index(tactic) + 1:04d}/"
            urls.append({
                'url': tactic_url,
                'type': 'tactic',
                'name': tactic,
            })
        
        return urls
    
    async def _discover_software(self) -> List[Dict]:
        """Discover software/tools."""
        urls = []
        
        software_url = f"{self.BASE_URL}/software/"
        html = await self.fetch_page(software_url)
        
        if not html:
            return urls
        
        soup = BeautifulSoup(html, 'lxml')
        
        for link in soup.find_all('a', href=re.compile(r'/software/S\d+')):
            href = link.get('href', '')
            if href:
                full_url = urljoin(self.BASE_URL, href)
                urls.append({
                    'url': full_url,
                    'type': 'software',
                })
        
        return urls[:50]  # Limit to avoid too many
    
    async def _discover_groups(self) -> List[Dict]:
        """Discover threat actor groups."""
        urls = []
        
        groups_url = f"{self.BASE_URL}/groups/"
        html = await self.fetch_page(groups_url)
        
        if not html:
            return urls
        
        soup = BeautifulSoup(html, 'lxml')
        
        for link in soup.find_all('a', href=re.compile(r'/groups/G\d+')):
            href = link.get('href', '')
            if href:
                full_url = urljoin(self.BASE_URL, href)
                urls.append({
                    'url': full_url,
                    'type': 'group',
                })
        
        return urls[:30]  # Limit to major groups
    
    async def scrape_page(self, url: str) -> Optional[ScrapedItem]:
        """Scrape an ATT&CK entry."""
        html = await self.fetch_page(url)
        if not html:
            return None
        
        try:
            soup = BeautifulSoup(html, 'lxml')
            
            # Extract title
            title_tag = soup.find('h1')
            title = title_tag.get_text(strip=True) if title_tag else ""
            
            # Extract ID (T####, S####, G####)
            att_id = ""
            id_match = re.search(r'[TSG]\d{4}', url)
            if id_match:
                att_id = id_match.group()
            
            # Extract description
            description = self._extract_description(soup)
            
            # Extract procedure examples
            procedures = self._extract_procedures(soup)
            
            # Extract mitigations
            mitigations = self._extract_mitigations(soup)
            
            # Extract detection
            detection = self._extract_detection(soup)
            
            # Build content
            content_parts = [
                f"# {title}",
                f"\nATT&CK ID: {att_id}" if att_id else "",
                f"\n## Description\n{description}" if description else "",
                f"\n## Procedure Examples\n{procedures}" if procedures else "",
                f"\n## Mitigations\n{mitigations}" if mitigations else "",
                f"\n## Detection\n{detection}" if detection else "",
            ]
            
            content = '\n'.join(p for p in content_parts if p)
            
            if len(content) < 100:
                return None
            
            # Determine entry type and category
            entry_type = self._determine_type(url)
            category = self._determine_category(title, description)
            
            return ScrapedItem(
                url=url,
                title=f"MITRE ATT&CK: {title}",
                content=content,
                code_blocks=[],
                headers=self._extract_headers(soup),
                metadata={
                    'category': category,
                    'source_type': 'mitre_attack',
                    'att_id': att_id,
                    'entry_type': entry_type,
                    'difficulty': 'intermediate',
                }
            )
        
        except Exception as e:
            logger.error(f"Error scraping {url}: {e}")
            return None
    
    def _extract_description(self, soup) -> str:
        """Extract description section."""
        desc_div = soup.find('div', class_='description-body')
        if desc_div:
            return desc_div.get_text(separator='\n', strip=True)
        return ""
    
    def _extract_procedures(self, soup) -> str:
        """Extract procedure examples."""
        procedures = []
        
        proc_table = soup.find('table', class_='table-techniques')
        if proc_table:
            for row in proc_table.find_all('tr')[1:]:  # Skip header
                cells = row.find_all('td')
                if len(cells) >= 2:
                    name = cells[0].get_text(strip=True)
                    desc = cells[1].get_text(strip=True)
                    procedures.append(f"- **{name}**: {desc[:200]}...")
        
        return '\n'.join(procedures[:10])  # Limit examples
    
    def _extract_mitigations(self, soup) -> str:
        """Extract mitigations."""
        mitigations = []
        
        mit_section = soup.find('h2', string=re.compile('Mitigation'))
        if mit_section:
            table = mit_section.find_next('table')
            if table:
                for row in table.find_all('tr')[1:]:
                    cells = row.find_all('td')
                    if len(cells) >= 2:
                        name = cells[0].get_text(strip=True)
                        desc = cells[1].get_text(strip=True)
                        mitigations.append(f"- **{name}**: {desc[:150]}...")
        
        return '\n'.join(mitigations[:5])
    
    def _extract_detection(self, soup) -> str:
        """Extract detection information."""
        det_section = soup.find('h2', string=re.compile('Detection'))
        if det_section:
            next_elem = det_section.find_next_sibling()
            if next_elem:
                return next_elem.get_text(strip=True)[:500]
        return ""
    
    def _extract_headers(self, soup) -> List[Dict]:
        """Extract headers."""
        headers = []
        for h in soup.find_all(['h1', 'h2', 'h3']):
            headers.append({
                'level': int(h.name[1]),
                'text': h.get_text(strip=True),
            })
        return headers
    
    def _determine_type(self, url: str) -> str:
        """Determine ATT&CK entry type."""
        if '/techniques/' in url:
            return 'technique'
        if '/tactics/' in url:
            return 'tactic'
        if '/software/' in url:
            return 'software'
        if '/groups/' in url:
            return 'group'
        return 'other'
    
    def _determine_category(self, title: str, description: str) -> str:
        """Determine category based on content."""
        text = (title + ' ' + description).lower()
        
        category_keywords = {
            'web_security': ['web', 'browser', 'javascript', 'html', 'http'],
            'credential_access': ['credential', 'password', 'authentication', 'token'],
            'privilege_escalation': ['privilege', 'escalat', 'admin', 'root'],
            'defense_evasion': ['evasion', 'bypass', 'hide', 'obfuscat'],
            'lateral_movement': ['lateral', 'spread', 'pivot', 'remote'],
            'exfiltration': ['exfiltrat', 'data theft', 'steal', 'transfer'],
            'persistence': ['persist', 'backdoor', 'implant'],
            'execution': ['execut', 'run', 'script', 'command'],
        }
        
        for category, keywords in category_keywords.items():
            if any(kw in text for kw in keywords):
                return category
        
        return 'attack_technique'
