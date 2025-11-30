"""
HackTricks scraper - scrapes the HackTricks security knowledge base.
Target: https://book.hacktricks.xyz
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .base_scraper import BaseScraper, ScrapedItem
from ..utils.logger import get_logger

logger = get_logger(__name__)


class HackTricksScraper(BaseScraper):
    """
    Scraper for HackTricks security documentation.
    Extracts pentesting methodologies, techniques, and code examples.
    """
    
    SOURCE_NAME = "hacktricks"
    BASE_URL = "https://book.hacktricks.xyz"
    
    # Category mappings for HackTricks sections
    CATEGORY_MAPPINGS = {
        "pentesting-web": "web_security",
        "linux-hardening": "privilege_escalation/linux",
        "windows-hardening": "privilege_escalation/windows",
        "network-services-pentesting": "network_security",
        "mobile-pentesting": "mobile_security",
        "cloud-security": "cloud_security",
        "forensics": "forensics",
        "crypto-and-stego": "cryptography",
        "exploiting": "exploitation",
        "reversing": "forensics/reverse_engineering",
        "backdoors": "persistence",
        "phishing": "social_engineering",
    }
    
    # URLs to skip (non-content pages)
    SKIP_PATTERNS = [
        r'/welcome$',
        r'/SUMMARY',
        r'/todo',
        r'\.md$',
        r'#',  # Anchor links
    ]
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._discovered_urls: List[str] = []
        self._sitemap_cache: Optional[Dict] = None
    
    async def discover_urls(self) -> List[str]:
        """Discover all content URLs from HackTricks."""
        if self._discovered_urls:
            return self._discovered_urls
        
        logger.info("Discovering URLs from HackTricks...")
        
        # Try to get URLs from SUMMARY.md or sitemap
        urls = await self._discover_from_gitbook()
        
        if not urls:
            # Fallback to crawling
            urls = await self._crawl_for_urls()
        
        # Filter URLs based on configuration
        if self.source_config and self.source_config.categories:
            urls = self._filter_by_categories(urls)
        
        # Filter out non-content URLs
        urls = [url for url in urls if self._is_content_url(url)]
        
        self._discovered_urls = list(set(urls))
        logger.info(f"Discovered {len(self._discovered_urls)} URLs")
        
        return self._discovered_urls
    
    async def _discover_from_gitbook(self) -> List[str]:
        """Discover URLs from GitBook structure."""
        urls = []
        
        # HackTricks uses GitBook, try to get the sidebar/navigation
        try:
            html = await self.fetch_page(self.BASE_URL)
            if not html:
                return urls
            
            soup = BeautifulSoup(html, 'lxml')
            
            # Find all navigation links
            nav_links = soup.find_all('a', href=True)
            
            for link in nav_links:
                href = link['href']
                
                # Build absolute URL
                if href.startswith('/'):
                    full_url = urljoin(self.BASE_URL, href)
                elif href.startswith('http'):
                    full_url = href
                else:
                    continue
                
                # Only include URLs from the same domain
                if self.BASE_URL in full_url:
                    urls.append(full_url.split('#')[0])  # Remove anchors
            
        except Exception as e:
            logger.error(f"Error discovering from GitBook: {e}")
        
        return urls
    
    async def _crawl_for_urls(self) -> List[str]:
        """Crawl the site to discover URLs."""
        discovered = set()
        to_visit = [self.BASE_URL]
        visited = set()
        
        max_crawl = 100  # Limit initial crawl
        
        while to_visit and len(visited) < max_crawl:
            url = to_visit.pop(0)
            
            if url in visited:
                continue
            
            visited.add(url)
            
            try:
                html = await self.fetch_page(url)
                if not html:
                    continue
                
                soup = BeautifulSoup(html, 'lxml')
                
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href).split('#')[0]
                    
                    if self.BASE_URL in full_url and full_url not in visited:
                        discovered.add(full_url)
                        if len(to_visit) < 1000:
                            to_visit.append(full_url)
            
            except Exception as e:
                logger.debug(f"Error crawling {url}: {e}")
        
        return list(discovered)
    
    def _filter_by_categories(self, urls: List[str]) -> List[str]:
        """Filter URLs by configured categories."""
        if not self.source_config or not self.source_config.categories:
            return urls
        
        filtered = []
        categories = self.source_config.categories
        
        for url in urls:
            url_lower = url.lower()
            if any(cat.lower() in url_lower for cat in categories):
                filtered.append(url)
        
        return filtered
    
    def _is_content_url(self, url: str) -> bool:
        """Check if URL is a content page."""
        for pattern in self.SKIP_PATTERNS:
            if re.search(pattern, url):
                return False
        return True
    
    def _determine_category(self, url: str) -> str:
        """Determine category from URL."""
        url_lower = url.lower()
        
        for url_pattern, category in self.CATEGORY_MAPPINGS.items():
            if url_pattern in url_lower:
                return category
        
        return "security"
    
    def _determine_difficulty(self, content: str, title: str) -> str:
        """Determine difficulty level from content."""
        text = (content + ' ' + title).lower()
        
        # Advanced indicators
        advanced_terms = [
            'advanced', 'expert', 'deep dive', 'complex',
            'kernel', 'heap', 'rop chain', 'shellcode',
        ]
        if any(term in text for term in advanced_terms):
            return 'advanced'
        
        # Beginner indicators
        beginner_terms = [
            'basic', 'introduction', 'beginner', 'simple',
            'getting started', 'fundamentals', '101',
        ]
        if any(term in text for term in beginner_terms):
            return 'beginner'
        
        return 'intermediate'
    
    async def scrape_page(self, url: str) -> Optional[ScrapedItem]:
        """Scrape a single HackTricks page."""
        html = await self.fetch_page(url)
        
        if not html:
            return None
        
        try:
            soup = BeautifulSoup(html, 'lxml')
            
            # Extract title
            title = ""
            title_tag = soup.find('h1')
            if title_tag:
                title = title_tag.get_text(strip=True)
            else:
                # Fallback to page title
                page_title = soup.find('title')
                if page_title:
                    title = page_title.get_text(strip=True)
            
            # Find main content area
            main_content = (
                soup.find('main') or 
                soup.find('article') or 
                soup.find('div', class_=re.compile(r'content|markdown|page'))
            )
            
            if not main_content:
                main_content = soup.find('body')
            
            if not main_content:
                return None
            
            # Remove navigation, headers, footers
            for unwanted in main_content.find_all(['nav', 'header', 'footer', 'aside']):
                unwanted.decompose()
            
            # Extract code blocks
            code_blocks = self._extract_code_blocks(main_content)
            
            # Extract headers for structure
            headers = self._extract_headers(main_content)
            
            # Get clean text content
            content = self._extract_text_content(main_content)
            
            if len(content) < 100:
                logger.debug(f"Skipping {url} - content too short")
                return None
            
            # Determine category and difficulty
            category = self._determine_category(url)
            difficulty = self._determine_difficulty(content, title)
            
            return ScrapedItem(
                url=url,
                title=title,
                content=content,
                code_blocks=code_blocks,
                headers=headers,
                metadata={
                    'category': category,
                    'difficulty': difficulty,
                    'source_type': 'hacktricks',
                }
            )
        
        except Exception as e:
            logger.error(f"Error parsing {url}: {e}")
            return None
    
    def _extract_code_blocks(self, soup) -> List[Dict[str, str]]:
        """Extract code blocks from content."""
        code_blocks = []
        
        for pre in soup.find_all('pre'):
            code_tag = pre.find('code')
            
            code_text = ""
            language = ""
            
            if code_tag:
                code_text = code_tag.get_text()
                
                # Try to detect language
                classes = code_tag.get('class', [])
                for cls in classes:
                    if 'language-' in cls:
                        language = cls.replace('language-', '')
                        break
                    elif 'lang-' in cls:
                        language = cls.replace('lang-', '')
                        break
            else:
                code_text = pre.get_text()
            
            # Detect language from content if not found
            if not language:
                language = self._detect_language(code_text)
            
            if code_text.strip():
                code_blocks.append({
                    'code': code_text.strip(),
                    'language': language,
                })
        
        return code_blocks
    
    def _detect_language(self, code: str) -> str:
        """Detect programming language from code content."""
        code_lower = code.lower().strip()
        
        # Shell/Bash indicators
        if code_lower.startswith(('$', '#!', 'sudo ', 'cd ', 'ls ', 'cat ', 'echo ')):
            return 'bash'
        if any(cmd in code_lower for cmd in ['nmap ', 'curl ', 'wget ', 'nc ', 'netcat']):
            return 'bash'
        
        # Python indicators
        if 'import ' in code_lower or 'def ' in code_lower or 'print(' in code_lower:
            return 'python'
        
        # PowerShell indicators
        if any(ps in code_lower for ps in ['$env:', 'get-', 'set-', 'invoke-', 'new-object']):
            return 'powershell'
        
        # SQL indicators
        if any(sql in code_lower for sql in ['select ', 'union ', 'insert ', 'update ', 'delete ']):
            return 'sql'
        
        # PHP indicators
        if '<?php' in code_lower or '$_' in code_lower:
            return 'php'
        
        return ''
    
    def _extract_headers(self, soup) -> List[Dict[str, Any]]:
        """Extract headers for content structure."""
        headers = []
        
        for level in range(1, 5):
            for header in soup.find_all(f'h{level}'):
                text = header.get_text(strip=True)
                if text:
                    headers.append({
                        'level': level,
                        'text': text,
                        'id': header.get('id', ''),
                    })
        
        return headers
    
    def _extract_text_content(self, soup) -> str:
        """Extract clean text content from soup."""
        # Clone to avoid modifying original
        content_soup = BeautifulSoup(str(soup), 'lxml')
        
        # Remove code blocks (we extract them separately)
        for pre in content_soup.find_all('pre'):
            pre.replace_with('[CODE_BLOCK]')
        
        # Get text
        text = content_soup.get_text(separator='\n')
        
        # Clean up whitespace
        lines = [line.strip() for line in text.split('\n')]
        text = '\n'.join(line for line in lines if line)
        
        # Replace multiple newlines with double newline
        text = re.sub(r'\n{3,}', '\n\n', text)
        
        return text
    
    def generate_qa_from_item(
        self,
        item: ScrapedItem,
    ) -> List[Dict[str, Any]]:
        """Generate Alpaca format Q&A pairs from scraped item."""
        qa_pairs = []
        
        category = item.metadata.get('category', 'security')
        difficulty = item.metadata.get('difficulty', 'intermediate')
        
        # Generate main Q&A from title and content
        if item.title:
            # Determine question type from title
            title_lower = item.title.lower()
            
            if any(kw in title_lower for kw in ['how to', 'walkthrough', 'guide']):
                instruction = f"How do I {self._extract_action(item.title)}?"
            elif any(kw in title_lower for kw in ['bypass', 'exploit', 'attack']):
                instruction = f"Explain the technique: {item.title}"
            elif any(kw in title_lower for kw in ['enumeration', 'discovery', 'scanning']):
                instruction = f"How do I perform {item.title}?"
            else:
                instruction = f"Explain {item.title} in the context of security testing."
            
            # Build output with content and code examples
            output = item.content
            
            # Add code blocks
            for i, block in enumerate(item.code_blocks[:5]):  # Limit to 5 blocks
                lang = block.get('language', '')
                code = block.get('code', '')
                if code:
                    output += f"\n\n```{lang}\n{code}\n```"
            
            qa_pairs.append({
                'instruction': instruction,
                'input': '',
                'output': output[:4000],  # Limit length
                'category': category,
                'source': item.url,
                'difficulty': difficulty,
                'tags': self._generate_tags(item),
            })
        
        # Generate additional Q&A for each major section
        for header in item.headers:
            if header['level'] <= 2:  # Only top-level headers
                header_text = header['text']
                
                # Skip generic headers
                if header_text.lower() in ['overview', 'introduction', 'references', 'links']:
                    continue
                
                section_qa = {
                    'instruction': f"What is {header_text} and how is it used in penetration testing?",
                    'input': f"Context: {item.title}",
                    'output': f"In the context of {item.title}, {header_text} refers to...",
                    'category': category,
                    'source': item.url,
                    'difficulty': difficulty,
                    'tags': self._generate_tags(item),
                }
                # Note: This is a placeholder - actual content extraction would need section mapping
        
        return qa_pairs
    
    def _extract_action(self, title: str) -> str:
        """Extract action from title."""
        # Remove common prefixes
        action = re.sub(r'^(how to|guide to|tutorial:?)\s*', '', title, flags=re.I)
        return action.lower().strip()
    
    def _generate_tags(self, item: ScrapedItem) -> List[str]:
        """Generate tags for the item."""
        tags = []
        
        text = (item.title + ' ' + item.content).lower()
        
        # Tool tags
        tools = ['nmap', 'burp', 'sqlmap', 'metasploit', 'hydra', 'gobuster', 'nikto', 'wfuzz']
        for tool in tools:
            if tool in text:
                tags.append(tool)
        
        # Technique tags
        techniques = ['sqli', 'xss', 'lfi', 'rfi', 'ssrf', 'xxe', 'rce', 'privesc']
        for tech in techniques:
            if tech in text:
                tags.append(tech)
        
        # Platform tags
        if 'linux' in text:
            tags.append('linux')
        if 'windows' in text:
            tags.append('windows')
        if 'web' in text or 'http' in text:
            tags.append('web')
        
        return tags[:10]  # Limit to 10 tags
