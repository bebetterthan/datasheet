"""
Sansec Magecart Research scraper.
Target: https://sansec.io/research
CRITICAL for: Magecart skimmers, e-commerce attacks, payment security
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from .base_scraper import BaseScraper, ScrapedItem
from ..utils.logger import get_logger

logger = get_logger(__name__)


class SansecScraper(BaseScraper):
    """
    Scraper for Sansec research blog.
    Primary source for Magecart and e-commerce security research.
    """
    
    SOURCE_NAME = "sansec"
    BASE_URL = "https://sansec.io"
    RESEARCH_URL = "https://sansec.io/research"
    
    # Magecart-specific categories
    MAGECART_KEYWORDS = [
        'magecart', 'skimmer', 'skimming', 'payment', 'checkout',
        'credit card', 'card data', 'exfiltration', 'formjacking',
        'web skimmer', 'digital skimmer', 'e-commerce', 'ecommerce',
        'magento', 'woocommerce', 'shopify', 'opencart', 'prestashop'
    ]
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._discovered_urls: List[str] = []
    
    async def discover_urls(self) -> List[str]:
        """Discover Sansec research articles."""
        if self._discovered_urls:
            return self._discovered_urls
        
        logger.info("Discovering Sansec research articles...")
        
        urls = []
        
        # Scrape main research page - all articles are listed here
        research_urls = await self._discover_from_page(self.RESEARCH_URL)
        urls.extend(research_urls)
        
        # Also check malware library
        malware_urls = await self._discover_from_page(f"{self.BASE_URL}/malware")
        urls.extend(malware_urls)
        
        # Magecart info page
        magecart_urls = await self._discover_from_page(f"{self.BASE_URL}/what-is-magecart")
        urls.extend(magecart_urls)
        
        self._discovered_urls = list(set(urls))
        logger.info(f"Discovered {len(self._discovered_urls)} Sansec articles")
        
        return self._discovered_urls
    
    async def _discover_from_page(self, page_url: str) -> List[str]:
        """Discover article URLs from a page."""
        urls = []
        
        try:
            html = await self.fetch_page(page_url)
            if not html:
                return urls
            
            soup = BeautifulSoup(html, 'lxml')
            
            # Find article links
            article_links = soup.find_all('a', href=re.compile(r'/(research|labs|blog)/[a-z0-9-]+'))
            
            for link in article_links:
                href = link.get('href', '')
                if href:
                    full_url = urljoin(self.BASE_URL, href)
                    if full_url not in urls and self._is_article_url(full_url):
                        urls.append(full_url)
        
        except Exception as e:
            logger.debug(f"Error discovering {page_url}: {e}")
        
        return urls
    
    def _is_article_url(self, url: str) -> bool:
        """Check if URL is an article (not category/tag page)."""
        skip_patterns = ['/page/', '/tag/', '/category/', '/author/']
        return not any(p in url for p in skip_patterns)
    
    async def scrape_page(self, url: str) -> Optional[ScrapedItem]:
        """Scrape a Sansec article."""
        html = await self.fetch_page(url)
        if not html:
            return None
        
        try:
            soup = BeautifulSoup(html, 'lxml')
            
            # Extract title - h1 is the main title
            title_tag = soup.find('h1')
            title = title_tag.get_text(strip=True) if title_tag else ""
            
            # Sansec uses main content in body directly
            # Remove navigation, header, footer first
            for elem in soup.find_all(['script', 'style', 'nav', 'header', 'footer', 'aside', 'form']):
                elem.decompose()
            
            # Try multiple selectors for content
            content_div = soup.find('article') or \
                         soup.find('main') or \
                         soup.find('div', class_=re.compile(r'content|post|article')) or \
                         soup.find('body')
            
            if not content_div:
                return None
            
            content = self._extract_content(content_div)
            code_blocks = self._extract_code_blocks(content_div)
            headers = self._extract_headers(content_div)
            
            if len(content) < 200:
                logger.debug(f"Content too short for {url}: {len(content)} chars")
                return None
            
            # Determine if Magecart-related
            is_magecart = self._is_magecart_related(title + ' ' + content)
            
            # Categorize
            category = self._categorize_content(title, content)
            
            return ScrapedItem(
                url=url,
                title=f"Sansec: {title}",
                content=content,
                code_blocks=code_blocks,
                headers=headers,
                metadata={
                    'category': category,
                    'source_type': 'sansec',
                    'is_magecart_related': is_magecart,
                    'difficulty': 'advanced',  # Sansec content is generally advanced
                    'tags': self._extract_tags(title, content),
                }
            )
        
        except Exception as e:
            logger.error(f"Error scraping {url}: {e}")
            return None
    
    def _extract_content(self, soup) -> str:
        """Extract clean text content."""
        for elem in soup.find_all(['script', 'style', 'nav', 'footer', 'aside']):
            elem.decompose()
        
        text = soup.get_text(separator='\n', strip=True)
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        return '\n'.join(lines)
    
    def _extract_code_blocks(self, soup) -> List[Dict]:
        """Extract code blocks including skimmer samples."""
        blocks = []
        
        for code in soup.find_all(['code', 'pre']):
            code_text = code.get_text(strip=True)
            if len(code_text) > 20:
                lang = self._detect_language(code_text)
                code_type = 'skimmer' if self._is_skimmer_code(code_text) else 'example'
                
                blocks.append({
                    'code': code_text,
                    'language': lang,
                    'type': code_type,
                })
        
        return blocks
    
    def _extract_headers(self, soup) -> List[Dict]:
        """Extract headers."""
        headers = []
        for h in soup.find_all(['h1', 'h2', 'h3', 'h4']):
            headers.append({
                'level': int(h.name[1]),
                'text': h.get_text(strip=True),
            })
        return headers
    
    def _is_magecart_related(self, text: str) -> bool:
        """Check if content is Magecart-related."""
        text_lower = text.lower()
        return any(kw in text_lower for kw in self.MAGECART_KEYWORDS)
    
    def _is_skimmer_code(self, code: str) -> bool:
        """Detect if code is a skimmer sample."""
        skimmer_patterns = [
            r'payment|checkout|billing',
            r'credit.?card|card.?number|cvv|expir',
            r'exfiltrat|senddata|postdata',
            r'form.?grab|key.?log|intercept',
            r'atob|btoa|eval\(|new Function',
        ]
        code_lower = code.lower()
        return any(re.search(p, code_lower) for p in skimmer_patterns)
    
    def _detect_language(self, code: str) -> str:
        """Detect code language."""
        code_lower = code.lower()[:300]
        
        if 'document.' in code_lower or 'window.' in code_lower:
            return 'javascript'
        if '<?php' in code_lower:
            return 'php'
        if 'select' in code_lower and 'from' in code_lower:
            return 'sql'
        if '<' in code_lower and '>' in code_lower and '/' in code_lower:
            return 'html'
        if 'bash' in code_lower or '#!/' in code_lower:
            return 'bash'
        
        return 'javascript'  # Default for skimmer analysis
    
    def _categorize_content(self, title: str, content: str) -> str:
        """Categorize the content."""
        text = (title + ' ' + content).lower()
        
        if any(kw in text for kw in ['skimmer', 'skimming', 'formjacking']):
            return 'magecart/skimmer_analysis'
        if any(kw in text for kw in ['magento', 'woocommerce', 'opencart']):
            return 'magecart/platform_specific'
        if any(kw in text for kw in ['exfiltrat', 'data theft', 'steal']):
            return 'magecart/exfiltration'
        if any(kw in text for kw in ['obfuscat', 'encod', 'encrypt']):
            return 'magecart/obfuscation'
        if any(kw in text for kw in ['detect', 'defense', 'protect']):
            return 'magecart/detection'
        if any(kw in text for kw in ['supply chain', 'third-party']):
            return 'magecart/supply_chain'
        
        return 'magecart/general'
    
    def _extract_tags(self, title: str, content: str) -> List[str]:
        """Extract relevant tags."""
        tags = ['magecart', 'ecommerce-security']
        text = (title + ' ' + content).lower()
        
        tag_keywords = {
            'magento': 'magento',
            'woocommerce': 'woocommerce',
            'shopify': 'shopify',
            'skimmer': 'skimmer',
            'javascript': 'javascript',
            'obfuscat': 'obfuscation',
            'exfiltrat': 'data-exfiltration',
            'supply chain': 'supply-chain',
            'credit card': 'payment-data',
        }
        
        for keyword, tag in tag_keywords.items():
            if keyword in text and tag not in tags:
                tags.append(tag)
        
        return tags[:10]
