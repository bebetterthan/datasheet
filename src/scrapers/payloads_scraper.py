"""
PayloadsAllTheThings scraper - scrapes security payloads and techniques.
Target: https://github.com/swisskyrepo/PayloadsAllTheThings
"""

import os
import re
from typing import Any, Dict, List, Optional
import json

from .base_scraper import BaseScraper, ScrapedItem
from ..utils.logger import get_logger
from ..utils.github_helper import GitHubHelper, GitHubAPIError, GitHubRateLimitError

logger = get_logger(__name__)


class PayloadsScraper(BaseScraper):
    """
    Scraper for PayloadsAllTheThings repository.
    """
    
    SOURCE_NAME = "payloads"
    BASE_URL = "https://api.github.com/repos/swisskyrepo/PayloadsAllTheThings"
    RAW_URL = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master"
    
    # Category mappings
    CATEGORY_MAP = {
        'sql injection': 'web_security/sql_injection',
        'xss injection': 'web_security/xss',
        'xxe injection': 'web_security/xxe',
        'command injection': 'exploitation/command_injection',
        'file inclusion': 'web_security/lfi',
        'directory traversal': 'web_security/path_traversal',
        'ssrf': 'web_security/ssrf',
        'csrf': 'web_security/csrf',
        'ssti': 'web_security/ssti',
        'deserialization': 'web_security/deserialization',
        'ldap injection': 'web_security/ldap_injection',
        'nosql injection': 'web_security/nosql_injection',
        'crlf injection': 'web_security/crlf_injection',
        'open redirect': 'web_security/open_redirect',
        'cors misconfiguration': 'web_security/cors',
        'oauth': 'web_security/oauth',
        'jwt': 'credential_access/jwt',
        'graphql injection': 'web_security/graphql',
        'request smuggling': 'web_security/request_smuggling',
        'upload': 'web_security/file_upload',
        'linux privilege escalation': 'privilege_escalation/linux',
        'windows privilege escalation': 'privilege_escalation/windows',
        'active directory': 'lateral_movement/active_directory',
        'kerberos': 'credential_access/kerberos',
        'ldap': 'lateral_movement/ldap',
        'webdav': 'web_security/webdav',
        'reverse shell': 'execution/reverse_shell',
        'methodology': 'general/methodology',
    }
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._discovered_files: List[str] = []
        # Initialize GitHub helper with token from env
        self._github = GitHubHelper(token=os.environ.get("GITHUB_TOKEN", ""))
    
    async def __aenter__(self):
        """Async context manager entry."""
        await super().__aenter__()
        await self._github.__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self._github.__aexit__(exc_type, exc_val, exc_tb)
        await super().__aexit__(exc_type, exc_val, exc_tb)
    
    async def discover_urls(self) -> List[str]:
        """Discover markdown files from repo."""
        if self._discovered_files:
            return self._discovered_files
        
        logger.info("Discovering PayloadsAllTheThings content...")
        
        files = await self._discover_repo_contents('')
        
        # Filter for README.md files (main content)
        readme_files = [f for f in files if f.lower().endswith('readme.md')]
        
        self._discovered_files = readme_files
        logger.info(f"Discovered {len(readme_files)} payload documents")
        
        return readme_files
    
    async def _discover_repo_contents(self, path: str) -> List[str]:
        """Recursively discover contents using GitHub helper."""
        files = []
        
        try:
            items = await self._github.get_repo_contents(
                owner="swisskyrepo",
                repo="PayloadsAllTheThings",
                path=path,
                ref="master"
            )
            
            for item in items:
                name = item.get('name', '')
                item_type = item.get('type', '')
                item_path = item.get('path', '')
                
                # Skip non-payload directories
                skip_dirs = ['.github', 'assets', 'images', '_template', '_LEARNING_AND_SOCIALS']
                if item_type == 'dir' and name.lower() not in [s.lower() for s in skip_dirs]:
                    # Recurse into directory
                    sub_files = await self._discover_repo_contents(item_path)
                    files.extend(sub_files)
                elif item_type == 'file' and name.lower().endswith('.md'):
                    files.append(item_path)
        
        except GitHubRateLimitError as e:
            logger.error(f"GitHub rate limit exceeded: {e}")
            logger.info("Set GITHUB_TOKEN environment variable for higher rate limits")
        except GitHubAPIError as e:
            logger.error(f"GitHub API error for path {path}: {e}")
        except Exception as e:
            logger.error(f"Error discovering repo contents at {path}: {e}")
        
        return files
    
    async def scrape_page(self, file_path: str) -> Optional[ScrapedItem]:
        """Scrape a specific payload document."""
        try:
            url = f"{self.RAW_URL}/{file_path}"
            
            content = await self.fetch_page(url)
            if not content:
                return None
            
            return self._parse_payload_doc(file_path, content, url)
        
        except Exception as e:
            logger.error(f"Error scraping {file_path}: {e}")
            return None
    
    def _parse_payload_doc(self, path: str, content: str, url: str) -> Optional[ScrapedItem]:
        """Parse PayloadsAllTheThings markdown document."""
        # Extract title from path
        parts = path.split('/')
        title = parts[-2] if len(parts) > 1 else parts[0]
        title = title.replace('-', ' ').replace('_', ' ')
        
        # Extract headers
        headers = re.findall(r'^#+\s+(.+)$', content, re.MULTILINE)
        
        # Extract code blocks with language
        code_blocks = []
        code_pattern = r'```(\w*)\n(.*?)```'
        for match in re.finditer(code_pattern, content, re.DOTALL):
            lang = match.group(1) or 'text'
            code = match.group(2).strip()
            if code:
                code_blocks.append({
                    'language': lang,
                    'code': code,
                })
        
        # Extract payloads (often in code blocks or lists)
        payloads = self._extract_payloads(content)
        
        # Determine category
        category = self._determine_category(path, headers, content)
        
        # Determine difficulty
        difficulty = self._determine_difficulty(content, category)
        
        # Extract tags
        tags = self._extract_tags(path, headers, content)
        
        return ScrapedItem(
            url=url,
            title=f"PayloadsAllTheThings: {title}",
            content=content,
            code_blocks=code_blocks,
            headers=headers,
            metadata={
                'category': category,
                'difficulty': difficulty,
                'source_type': 'payloads',
                'topic': title,
                'payloads_count': len(payloads),
                'tags': tags,
            }
        )
    
    def _extract_payloads(self, content: str) -> List[str]:
        """Extract individual payloads from content."""
        payloads = []
        
        # Payloads in code blocks
        code_pattern = r'```\w*\n(.*?)```'
        for match in re.finditer(code_pattern, content, re.DOTALL):
            code = match.group(1).strip()
            # Split multi-line payloads
            for line in code.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    payloads.append(line)
        
        # Inline code payloads
        inline_pattern = r'`([^`]+)`'
        for match in re.finditer(inline_pattern, content):
            payload = match.group(1).strip()
            # Filter out simple words
            if len(payload) > 10 and any(c in payload for c in ['<', '>', ';', '|', '$', '{', '}']):
                payloads.append(payload)
        
        return payloads[:100]  # Limit
    
    def _determine_category(self, path: str, headers: List[str], content: str) -> str:
        """Determine category from path and content."""
        text = ' '.join([path.lower()] + [h.lower() for h in headers])
        
        for key, category in self.CATEGORY_MAP.items():
            if key in text:
                return category
        
        # Additional keyword detection
        if 'privilege' in text and 'linux' in text:
            return 'privilege_escalation/linux'
        if 'privilege' in text and 'windows' in text:
            return 'privilege_escalation/windows'
        if 'reverse shell' in text or 'revshell' in text:
            return 'execution/reverse_shell'
        if 'bypass' in text:
            return 'defense_evasion/bypass'
        
        return 'security/payloads'
    
    def _determine_difficulty(self, content: str, category: str) -> str:
        """Determine difficulty based on content complexity."""
        content_lower = content.lower()
        
        # Advanced topics
        advanced_keywords = ['race condition', 'heap spray', 'rop chain', 
                          'kernel', 'advanced', 'complex', 'sophisticated']
        if any(kw in content_lower for kw in advanced_keywords):
            return 'advanced'
        
        # Intermediate
        intermediate_keywords = ['bypass', 'filter evasion', 'waf bypass',
                               'obfuscation', 'encoding']
        if any(kw in content_lower for kw in intermediate_keywords):
            return 'intermediate'
        
        # Categories with typical difficulty
        if 'privilege_escalation' in category:
            return 'intermediate'
        if 'active_directory' in category:
            return 'advanced'
        
        return 'beginner'
    
    def _extract_tags(self, path: str, headers: List[str], content: str) -> List[str]:
        """Extract relevant tags from content."""
        tags = set()
        
        # From path
        parts = path.lower().replace('-', ' ').replace('_', ' ').split('/')
        for part in parts:
            if len(part) > 2 and part not in ['readme', 'md']:
                tags.add(part.replace(' ', '_'))
        
        # Common security terms
        security_terms = [
            'sqli', 'xss', 'xxe', 'ssrf', 'rce', 'lfi', 'rfi', 'csrf',
            'ssti', 'injection', 'bypass', 'payload', 'exploit',
            'shell', 'reverse', 'bind', 'upload', 'traversal',
        ]
        
        content_lower = content.lower()
        for term in security_terms:
            if term in content_lower:
                tags.add(term)
        
        return list(tags)[:10]
    
    def generate_qa_from_item(self, item: ScrapedItem) -> List[Dict[str, Any]]:
        """Generate Q&A pairs from payload document."""
        qa_pairs = []
        
        topic = item.metadata.get('topic', '')
        category = item.metadata.get('category', '')
        
        # Main explanation
        qa_pairs.append({
            'instruction': f"Explain {topic} attack techniques and provide examples of payloads",
            'input': '',
            'output': item.content[:4000],  # Truncate long content
            'category': category,
            'source': item.url,
            'difficulty': item.metadata.get('difficulty', 'intermediate'),
            'tags': item.metadata.get('tags', []),
        })
        
        # Code-specific Q&A
        for i, code_block in enumerate(item.code_blocks[:3]):
            lang = code_block['language']
            code = code_block['code']
            
            if len(code) > 50:
                qa_pairs.append({
                    'instruction': f"Show me a {topic} payload example in {lang}",
                    'input': '',
                    'output': f"Here's a {topic} payload:\n\n```{lang}\n{code}\n```",
                    'category': category,
                    'source': item.url,
                    'difficulty': item.metadata.get('difficulty', 'intermediate'),
                    'tags': item.metadata.get('tags', []) + [lang],
                })
        
        return qa_pairs
