"""
PortSwigger Web Security Academy scraper.
Target: https://portswigger.net/web-security
CRITICAL for: XSS, SQLi, CSRF, and all web vulnerabilities
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from .base_scraper import BaseScraper, ScrapedItem
from ..utils.logger import get_logger

logger = get_logger(__name__)


class PortSwiggerScraper(BaseScraper):
    """
    Scraper for PortSwigger Web Security Academy.
    High-quality web security learning resources.
    """
    
    SOURCE_NAME = "portswigger"
    BASE_URL = "https://portswigger.net/web-security"
    
    # Topic categories mapping
    CATEGORIES = {
        'sql-injection': 'web_security/sql_injection',
        'cross-site-scripting': 'web_security/xss',
        'csrf': 'web_security/csrf',
        'clickjacking': 'web_security/clickjacking',
        'dom-based': 'web_security/dom_vulnerabilities',
        'cors': 'web_security/cors',
        'xxe': 'web_security/xxe',
        'ssrf': 'web_security/ssrf',
        'request-smuggling': 'web_security/request_smuggling',
        'os-command-injection': 'exploitation/command_injection',
        'server-side-template-injection': 'web_security/ssti',
        'path-traversal': 'web_security/path_traversal',
        'access-control': 'web_security/access_control',
        'authentication': 'credential_access/authentication',
        'websockets': 'web_security/websockets',
        'web-cache-poisoning': 'web_security/cache_poisoning',
        'insecure-deserialization': 'web_security/deserialization',
        'information-disclosure': 'reconnaissance/information_disclosure',
        'business-logic-vulnerabilities': 'web_security/business_logic',
        'http-host-header-attacks': 'web_security/host_header',
        'oauth-authentication': 'web_security/oauth',
        'file-upload-vulnerabilities': 'web_security/file_upload',
        'jwt': 'credential_access/jwt',
        'prototype-pollution': 'web_security/prototype_pollution',
        'graphql': 'web_security/graphql',
        'race-conditions': 'web_security/race_conditions',
        'nosql-injection': 'web_security/nosql_injection',
        'api-testing': 'web_security/api',
        'web-llm-attacks': 'web_security/llm_attacks',
    }
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._discovered_urls: List[Dict] = []
    
    async def discover_urls(self) -> List[str]:
        """Discover all PortSwigger learning paths and articles."""
        if self._discovered_urls:
            return [d['url'] for d in self._discovered_urls]
        
        logger.info("Discovering PortSwigger Web Security Academy content...")
        
        # Get main learning paths
        html = await self.fetch_page(self.BASE_URL)
        if not html:
            return []
        
        soup = BeautifulSoup(html, 'lxml')
        urls = []
        
        # Find all topic links
        topic_links = soup.find_all('a', href=re.compile(r'/web-security/[a-z-]+$'))
        
        for link in topic_links:
            href = link.get('href', '')
            if href and not href.endswith('/all-labs'):
                full_url = urljoin('https://portswigger.net', href)
                topic = href.split('/')[-1]
                
                urls.append({
                    'url': full_url,
                    'topic': topic,
                    'category': self.CATEGORIES.get(topic, 'web_security'),
                })
                
                # Also discover sub-pages
                sub_urls = await self._discover_topic_pages(full_url, topic)
                urls.extend(sub_urls)
        
        self._discovered_urls = urls
        logger.info(f"Discovered {len(urls)} PortSwigger pages")
        
        return [d['url'] for d in urls]
    
    async def _discover_topic_pages(self, topic_url: str, topic: str) -> List[Dict]:
        """Discover sub-pages for a topic."""
        pages = []
        
        try:
            html = await self.fetch_page(topic_url)
            if not html:
                return pages
            
            soup = BeautifulSoup(html, 'lxml')
            
            # Find sub-topic links
            content_links = soup.find_all('a', href=re.compile(rf'/web-security/{topic}/'))
            
            for link in content_links:
                href = link.get('href', '')
                if href and '/all-labs' not in href and '/all-materials' not in href:
                    full_url = urljoin('https://portswigger.net', href)
                    if full_url not in [p['url'] for p in pages]:
                        pages.append({
                            'url': full_url,
                            'topic': topic,
                            'category': self.CATEGORIES.get(topic, 'web_security'),
                        })
        
        except Exception as e:
            logger.debug(f"Error discovering {topic_url}: {e}")
        
        return pages
    
    async def scrape_page(self, url: str) -> Optional[ScrapedItem]:
        """Scrape a PortSwigger article."""
        html = await self.fetch_page(url)
        if not html:
            return None
        
        try:
            soup = BeautifulSoup(html, 'lxml')
            
            # Extract title
            title_tag = soup.find('h1')
            title = title_tag.get_text(strip=True) if title_tag else ""
            
            # Remove unwanted elements first
            for elem in soup.find_all(['script', 'style', 'nav', 'footer', 'header', 'aside']):
                elem.decompose()
            
            # PortSwigger uses main or body for content - try multiple selectors
            content_div = soup.find('main') or \
                         soup.find('div', class_=re.compile(r'content|article|page')) or \
                         soup.find('article') or \
                         soup.find('body')
            
            if not content_div:
                return None
            
            # Extract text content
            content = self._extract_content(content_div)
            
            # Extract code blocks
            code_blocks = self._extract_code_blocks(content_div)
            
            # Extract headers for structure
            headers = self._extract_headers(content_div)
            
            if len(content) < 100:
                logger.debug(f"Content too short for {url}: {len(content)} chars")
                return None
            
            # Determine category from URL
            category = 'web_security'
            for topic, cat in self.CATEGORIES.items():
                if topic in url:
                    category = cat
                    break
            
            return ScrapedItem(
                url=url,
                title=f"PortSwigger: {title}",
                content=content,
                code_blocks=code_blocks,
                headers=headers,
                metadata={
                    'category': category,
                    'source_type': 'portswigger',
                    'difficulty': self._determine_difficulty(content, headers),
                }
            )
        
        except Exception as e:
            logger.error(f"Error scraping {url}: {e}")
            return None
    
    def _extract_content(self, soup) -> str:
        """Extract clean text content."""
        # Remove script and style elements
        for elem in soup.find_all(['script', 'style', 'nav', 'footer']):
            elem.decompose()
        
        # Get text
        text = soup.get_text(separator='\n', strip=True)
        
        # Clean up whitespace
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        return '\n'.join(lines)
    
    def _extract_code_blocks(self, soup) -> List[Dict]:
        """Extract code blocks."""
        blocks = []
        
        for code in soup.find_all(['code', 'pre']):
            code_text = code.get_text(strip=True)
            if len(code_text) > 20:
                # Try to detect language
                lang = self._detect_language(code_text)
                blocks.append({
                    'code': code_text,
                    'language': lang,
                })
        
        return blocks
    
    def _extract_headers(self, soup) -> List[Dict]:
        """Extract headers for structure."""
        headers = []
        for h in soup.find_all(['h1', 'h2', 'h3', 'h4']):
            headers.append({
                'level': int(h.name[1]),
                'text': h.get_text(strip=True),
            })
        return headers
    
    def _detect_language(self, code: str) -> str:
        """Detect code language."""
        code_lower = code.lower()[:200]
        
        if 'select' in code_lower and 'from' in code_lower:
            return 'sql'
        if '<script' in code_lower or 'document.' in code_lower:
            return 'javascript'
        if '<?php' in code_lower:
            return 'php'
        if 'http/' in code_lower or 'host:' in code_lower:
            return 'http'
        if 'import ' in code_lower or 'def ' in code_lower:
            return 'python'
        if '<' in code_lower and '>' in code_lower:
            return 'html'
        
        return ''
    
    def _determine_difficulty(self, content: str, headers: List[Dict]) -> str:
        """Determine content difficulty."""
        content_lower = content.lower()
        
        # Expert indicators
        expert_keywords = ['advanced', 'complex', 'edge case', 'bypass', 'evasion']
        if any(kw in content_lower for kw in expert_keywords):
            return 'advanced'
        
        # Beginner indicators  
        beginner_keywords = ['introduction', 'what is', 'basic', 'getting started']
        if any(kw in content_lower for kw in beginner_keywords):
            return 'beginner'
        
        return 'intermediate'
