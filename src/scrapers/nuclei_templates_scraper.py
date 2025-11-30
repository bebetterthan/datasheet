"""
Nuclei Templates scraper - scrapes security templates from projectdiscovery/nuclei-templates.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from .base_scraper import BaseScraper, ScrapedItem
from ..utils.logger import get_logger

logger = get_logger(__name__)


class NucleiTemplatesScraper(BaseScraper):
    """
    Scraper for Nuclei security templates from GitHub.
    """
    
    SOURCE_NAME = "nuclei_templates"
    BASE_URL = "https://api.github.com/repos/projectdiscovery/nuclei-templates"
    RAW_URL = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main"
    
    # Template categories to scrape
    TEMPLATE_CATEGORIES = [
        'cves',
        'vulnerabilities',
        'exposures',
        'misconfiguration',
        'default-logins',
        'takeovers',
        'technologies',
    ]
    
    # Category mapping to our taxonomy
    CATEGORY_MAP = {
        'cves': 'exploitation/cve',
        'vulnerabilities': 'exploitation/vulnerability',
        'exposures': 'recon/exposure',
        'misconfiguration': 'web_security/misconfiguration',
        'default-logins': 'credential_access/default_credentials',
        'takeovers': 'web_security/subdomain_takeover',
        'technologies': 'recon/technology_detection',
        'sqli': 'web_security/sql_injection',
        'xss': 'web_security/xss',
        'lfi': 'web_security/lfi',
        'rce': 'exploitation/rce',
        'ssrf': 'web_security/ssrf',
        'xxe': 'web_security/xxe',
    }
    
    # Severity mapping
    SEVERITY_DIFFICULTY = {
        'critical': 'beginner',
        'high': 'intermediate',
        'medium': 'intermediate',
        'low': 'advanced',
        'info': 'beginner',
    }
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._discovered_templates: List[str] = []
    
    async def discover_urls(self) -> List[str]:
        """Discover template files from GitHub repo."""
        if self._discovered_templates:
            return self._discovered_templates
        
        logger.info("Discovering Nuclei templates from GitHub...")
        
        templates = []
        
        for category in self.TEMPLATE_CATEGORIES:
            category_templates = await self._discover_category_templates(category)
            templates.extend(category_templates)
            logger.info(f"Found {len(category_templates)} templates in {category}")
        
        self._discovered_templates = templates
        logger.info(f"Total discovered: {len(templates)} templates")
        
        return templates
    
    async def _discover_category_templates(self, category: str) -> List[str]:
        """Discover templates in a specific category."""
        templates = []
        
        # Use GitHub API to list contents
        url = f"{self.BASE_URL}/contents/{category}"
        
        try:
            response_text = await self.fetch_page(url)
            if not response_text:
                return templates
            
            import json
            items = json.loads(response_text)
            
            for item in items:
                if item.get('type') == 'file' and item.get('name', '').endswith('.yaml'):
                    # Store the raw URL path
                    templates.append(f"{category}/{item['name']}")
                elif item.get('type') == 'dir':
                    # Recurse into subdirectory
                    subdir = item.get('path', '')
                    sub_templates = await self._discover_subdir_templates(subdir)
                    templates.extend(sub_templates)
        
        except Exception as e:
            logger.debug(f"Error discovering {category}: {e}")
        
        return templates[:100]  # Limit per category
    
    async def _discover_subdir_templates(self, path: str) -> List[str]:
        """Discover templates in subdirectory."""
        templates = []
        
        url = f"{self.BASE_URL}/contents/{path}"
        
        try:
            response_text = await self.fetch_page(url)
            if not response_text:
                return templates
            
            import json
            items = json.loads(response_text)
            
            for item in items:
                if item.get('type') == 'file' and item.get('name', '').endswith('.yaml'):
                    templates.append(item.get('path', ''))
        
        except Exception as e:
            logger.debug(f"Error in subdir {path}: {e}")
        
        return templates[:50]  # Limit per subdir
    
    async def scrape_page(self, template_path: str) -> Optional[ScrapedItem]:
        """Scrape a specific Nuclei template."""
        try:
            # Fetch raw template content
            url = f"{self.RAW_URL}/{template_path}"
            
            content = await self.fetch_page(url)
            if not content:
                return None
            
            return self._parse_nuclei_template(template_path, content, url)
        
        except Exception as e:
            logger.error(f"Error scraping template {template_path}: {e}")
            return None
    
    def _parse_nuclei_template(self, path: str, content: str, url: str) -> Optional[ScrapedItem]:
        """Parse Nuclei YAML template."""
        try:
            template = yaml.safe_load(content)
        except yaml.YAMLError as e:
            logger.debug(f"YAML parse error for {path}: {e}")
            return None
        
        if not template:
            return None
        
        # Extract metadata
        info = template.get('info', {})
        template_id = template.get('id', path)
        name = info.get('name', template_id)
        author = info.get('author', 'unknown')
        severity = info.get('severity', 'info')
        description = info.get('description', '')
        tags = info.get('tags', '')
        reference = info.get('reference', [])
        
        # Convert tags string to list
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(',')]
        
        # Extract request details
        requests = []
        
        # HTTP requests
        http_requests = template.get('http', template.get('requests', []))
        if http_requests:
            for req in http_requests:
                req_info = self._extract_request_info(req, 'http')
                if req_info:
                    requests.append(req_info)
        
        # Network requests
        network = template.get('network', template.get('tcp', []))
        if network:
            for req in network:
                req_info = self._extract_request_info(req, 'network')
                if req_info:
                    requests.append(req_info)
        
        # Build formatted content
        content_parts = [
            f"# Nuclei Template: {name}",
            f"\n**ID:** {template_id}",
            f"**Author:** {author}",
            f"**Severity:** {severity}",
            f"**Tags:** {', '.join(tags)}",
        ]
        
        if description:
            content_parts.append(f"\n## Description\n{description}")
        
        if reference:
            refs = reference if isinstance(reference, list) else [reference]
            content_parts.append(f"\n## References\n- " + "\n- ".join(refs[:5]))
        
        content_parts.append(f"\n## Template\n```yaml\n{content}\n```")
        
        # Determine category
        category = self._determine_template_category(path, tags, name)
        
        # Build code blocks
        code_blocks = [{
            'language': 'yaml',
            'code': content,
        }]
        
        return ScrapedItem(
            url=url,
            title=f"Nuclei Template: {name}",
            content='\n'.join(content_parts),
            code_blocks=code_blocks,
            headers=[name],
            metadata={
                'category': category,
                'difficulty': self.SEVERITY_DIFFICULTY.get(severity.lower(), 'intermediate'),
                'source_type': 'nuclei_template',
                'template_id': template_id,
                'severity': severity,
                'author': author,
                'tags': tags,
                'requests': requests,
                'cve_ids': self._extract_cve_ids(tags, name, description),
            }
        )
    
    def _extract_request_info(self, request: Dict, req_type: str) -> Optional[Dict]:
        """Extract request information from template."""
        info = {'type': req_type}
        
        if req_type == 'http':
            info['method'] = request.get('method', 'GET')
            info['path'] = request.get('path', [])
            info['raw'] = request.get('raw', [])[:1]  # First raw request only
            info['matchers'] = self._extract_matchers(request)
        elif req_type == 'network':
            info['host'] = request.get('host', [])
            info['inputs'] = request.get('inputs', [])
            info['matchers'] = self._extract_matchers(request)
        
        return info
    
    def _extract_matchers(self, request: Dict) -> List[Dict]:
        """Extract matcher conditions."""
        matchers = []
        
        for matcher in request.get('matchers', []):
            matchers.append({
                'type': matcher.get('type', ''),
                'part': matcher.get('part', ''),
                'condition': matcher.get('condition', 'and'),
            })
        
        return matchers[:3]  # Limit
    
    def _extract_cve_ids(self, tags: List[str], name: str, description: str) -> List[str]:
        """Extract CVE IDs from template."""
        text = ' '.join(tags + [name, description])
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        return list(set(re.findall(cve_pattern, text, re.IGNORECASE)))
    
    def _determine_template_category(self, path: str, tags: List[str], name: str) -> str:
        """Determine category from template path and tags."""
        path_lower = path.lower()
        text = ' '.join(tags + [name, path]).lower()
        
        # Check path first
        for cat_key, cat_value in self.CATEGORY_MAP.items():
            if cat_key in path_lower:
                return cat_value
        
        # Check tags
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower in self.CATEGORY_MAP:
                return self.CATEGORY_MAP[tag_lower]
        
        # Keyword detection
        if 'sqli' in text or 'sql-injection' in text:
            return 'web_security/sql_injection'
        if 'xss' in text or 'cross-site' in text:
            return 'web_security/xss'
        if 'rce' in text or 'remote-code' in text:
            return 'exploitation/rce'
        if 'lfi' in text or 'local-file' in text:
            return 'web_security/lfi'
        if 'ssrf' in text:
            return 'web_security/ssrf'
        
        return 'security/detection'
    
    def generate_qa_from_item(self, item: ScrapedItem) -> List[Dict[str, Any]]:
        """Generate Q&A pairs from Nuclei template."""
        qa_pairs = []
        
        template_id = item.metadata.get('template_id', '')
        severity = item.metadata.get('severity', 'info')
        tags = item.metadata.get('tags', [])
        
        # Template explanation
        qa_pairs.append({
            'instruction': f"Explain the Nuclei template for detecting {item.title}",
            'input': '',
            'output': item.content,
            'category': item.metadata.get('category', 'security/detection'),
            'source': item.url,
            'difficulty': item.metadata.get('difficulty', 'intermediate'),
            'tags': ['nuclei', 'detection', severity.lower()] + [t.lower() for t in tags[:5]],
        })
        
        # Usage instruction
        code_block = item.code_blocks[0]['code'] if item.code_blocks else ''
        if code_block:
            qa_pairs.append({
                'instruction': f"How do I use Nuclei to scan for {template_id}?",
                'input': '',
                'output': f"Save the following template and run Nuclei:\n\n```yaml\n{code_block}\n```\n\nUsage:\n```bash\nnuclei -t {template_id}.yaml -u target.com\n```",
                'category': 'tools/nuclei',
                'source': item.url,
                'difficulty': 'beginner',
                'tags': ['nuclei', 'scanning', 'automation'],
            })
        
        return qa_pairs
