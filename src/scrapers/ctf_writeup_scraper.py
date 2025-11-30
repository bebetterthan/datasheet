"""
CTF Writeup scraper - scrapes CTF writeups from multiple sources.
Targets: CTFTime, 0xdf, GitHub repositories, etc.
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

from .base_scraper import BaseScraper, ScrapedItem
from ..utils.logger import get_logger

logger = get_logger(__name__)


class CTFWriteupScraper(BaseScraper):
    """
    Scraper for CTF writeups from various sources.
    """
    
    SOURCE_NAME = "ctf_writeups"
    BASE_URL = "https://ctftime.org"
    
    # Additional writeup sources
    ADDITIONAL_SOURCES = {
        "0xdf": "https://0xdf.gitlab.io/",
        "ippsec": "https://ippsec.rocks/",
    }
    
    # CTF categories
    CTF_CATEGORIES = {
        "web": "web_security",
        "crypto": "cryptography",
        "pwn": "exploitation/binary",
        "reverse": "forensics/reverse_engineering",
        "forensics": "forensics",
        "misc": "security",
        "osint": "reconnaissance/osint",
        "stego": "cryptography/steganography",
        "mobile": "mobile_security",
        "blockchain": "cryptography/blockchain",
    }
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._discovered_urls: List[str] = []
    
    async def discover_urls(self) -> List[str]:
        """Discover writeup URLs from CTFTime and other sources."""
        if self._discovered_urls:
            return self._discovered_urls
        
        logger.info("Discovering CTF writeup URLs...")
        
        urls = []
        
        # Get writeups from CTFTime
        ctftime_urls = await self._discover_ctftime_writeups()
        urls.extend(ctftime_urls)
        
        # Get writeups from 0xdf
        oxdf_urls = await self._discover_0xdf_writeups()
        urls.extend(oxdf_urls)
        
        self._discovered_urls = list(set(urls))
        logger.info(f"Discovered {len(self._discovered_urls)} writeup URLs")
        
        return self._discovered_urls
    
    async def _discover_ctftime_writeups(self) -> List[str]:
        """Discover writeups from CTFTime."""
        urls = []
        
        # Get year range from config
        start_year = 2020
        end_year = datetime.now().year
        
        if self.source_config and self.source_config.year_range:
            start_year = self.source_config.year_range[0]
            end_year = self.source_config.year_range[1]
        
        # CTFTime writeups page
        writeups_url = f"{self.BASE_URL}/writeups/"
        
        try:
            html = await self.fetch_page(writeups_url)
            if html:
                soup = BeautifulSoup(html, 'lxml')
                
                # Find writeup links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if '/writeup/' in href:
                        full_url = urljoin(self.BASE_URL, href)
                        urls.append(full_url)
                
                logger.info(f"Found {len(urls)} writeups from CTFTime main page")
                
                # Try to get more pages
                for page in range(2, 11):  # Get first 10 pages
                    page_url = f"{writeups_url}?page={page}"
                    page_html = await self.fetch_page(page_url)
                    
                    if page_html:
                        page_soup = BeautifulSoup(page_html, 'lxml')
                        for link in page_soup.find_all('a', href=True):
                            href = link['href']
                            if '/writeup/' in href:
                                full_url = urljoin(self.BASE_URL, href)
                                urls.append(full_url)
        
        except Exception as e:
            logger.error(f"Error discovering CTFTime writeups: {e}")
        
        return urls
    
    async def _discover_0xdf_writeups(self) -> List[str]:
        """Discover writeups from 0xdf's blog."""
        urls = []
        base_url = self.ADDITIONAL_SOURCES["0xdf"]
        
        try:
            html = await self.fetch_page(base_url)
            if html:
                soup = BeautifulSoup(html, 'lxml')
                
                # 0xdf uses Jekyll, look for post links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    
                    # HTB and other writeup patterns
                    if any(pattern in href.lower() for pattern in ['htb-', 'thm-', 'hackthebox', 'tryhackme']):
                        if href.startswith('/'):
                            full_url = urljoin(base_url, href)
                        elif href.startswith('http'):
                            full_url = href
                        else:
                            continue
                        
                        urls.append(full_url)
                
                logger.info(f"Found {len(urls)} writeups from 0xdf")
        
        except Exception as e:
            logger.error(f"Error discovering 0xdf writeups: {e}")
        
        return urls
    
    async def scrape_page(self, url: str) -> Optional[ScrapedItem]:
        """Scrape a single writeup page."""
        html = await self.fetch_page(url)
        
        if not html:
            return None
        
        try:
            # Determine source type and use appropriate parser
            if 'ctftime.org' in url:
                return await self._parse_ctftime_writeup(url, html)
            elif '0xdf' in url:
                return await self._parse_0xdf_writeup(url, html)
            else:
                return await self._parse_generic_writeup(url, html)
        
        except Exception as e:
            logger.error(f"Error parsing writeup {url}: {e}")
            return None
    
    async def _parse_ctftime_writeup(self, url: str, html: str) -> Optional[ScrapedItem]:
        """Parse CTFTime writeup."""
        soup = BeautifulSoup(html, 'lxml')
        
        # Extract title
        title = ""
        title_tag = soup.find('h2')  # CTFTime uses h2 for writeup titles
        if title_tag:
            title = title_tag.get_text(strip=True)
        
        # Extract CTF name and challenge info
        ctf_name = ""
        challenge_name = ""
        category = ""
        
        # Look for task info
        task_info = soup.find('div', class_='task-info')
        if task_info:
            # Extract category
            for tag in task_info.find_all('span', class_='tag'):
                tag_text = tag.get_text(strip=True).lower()
                if tag_text in self.CTF_CATEGORIES:
                    category = self.CTF_CATEGORIES[tag_text]
                    break
        
        # Extract writeup content
        content_div = soup.find('div', class_='writeup-content') or soup.find('article')
        
        if not content_div:
            # Fallback to main content
            content_div = soup.find('div', class_='container')
        
        if not content_div:
            return None
        
        # Extract code blocks
        code_blocks = []
        for pre in content_div.find_all('pre'):
            code = pre.get_text()
            if code.strip():
                code_blocks.append({
                    'code': code.strip(),
                    'language': self._detect_language(code),
                })
        
        # Get content
        content = content_div.get_text(separator='\n')
        content = self._clean_content(content)
        
        if len(content) < 200:
            return None
        
        # Determine difficulty based on CTF rating if available
        difficulty = self._estimate_difficulty(content, title)
        
        return ScrapedItem(
            url=url,
            title=title or "CTF Writeup",
            content=content,
            code_blocks=code_blocks,
            headers=[],
            metadata={
                'category': category or 'security/ctf',
                'difficulty': difficulty,
                'source_type': 'ctftime',
                'ctf_name': ctf_name,
                'challenge_name': challenge_name,
            }
        )
    
    async def _parse_0xdf_writeup(self, url: str, html: str) -> Optional[ScrapedItem]:
        """Parse 0xdf writeup (Jekyll blog)."""
        soup = BeautifulSoup(html, 'lxml')
        
        # Extract title
        title = ""
        title_tag = soup.find('h1', class_='post-title') or soup.find('h1')
        if title_tag:
            title = title_tag.get_text(strip=True)
        
        # Extract content
        article = soup.find('article') or soup.find('div', class_='post-content')
        
        if not article:
            return None
        
        # Extract code blocks
        code_blocks = []
        for pre in article.find_all('pre'):
            code_tag = pre.find('code')
            if code_tag:
                code = code_tag.get_text()
                
                # Get language from class
                lang = ""
                classes = code_tag.get('class', [])
                for cls in classes:
                    if 'language-' in cls:
                        lang = cls.replace('language-', '')
                        break
                
                if code.strip():
                    code_blocks.append({
                        'code': code.strip(),
                        'language': lang or self._detect_language(code),
                    })
            else:
                code = pre.get_text()
                if code.strip():
                    code_blocks.append({
                        'code': code.strip(),
                        'language': self._detect_language(code),
                    })
        
        # Extract headers
        headers = []
        for level in range(1, 5):
            for header in article.find_all(f'h{level}'):
                text = header.get_text(strip=True)
                if text:
                    headers.append({'level': level, 'text': text})
        
        # Get clean content
        content = article.get_text(separator='\n')
        content = self._clean_content(content)
        
        if len(content) < 200:
            return None
        
        # Determine category from title/content
        category = self._determine_category(title, content)
        difficulty = self._estimate_difficulty(content, title)
        
        return ScrapedItem(
            url=url,
            title=title,
            content=content,
            code_blocks=code_blocks,
            headers=headers,
            metadata={
                'category': category,
                'difficulty': difficulty,
                'source_type': '0xdf',
                'platform': self._detect_platform(title, url),
            }
        )
    
    async def _parse_generic_writeup(self, url: str, html: str) -> Optional[ScrapedItem]:
        """Parse generic writeup page."""
        soup = BeautifulSoup(html, 'lxml')
        
        # Extract title
        title = ""
        for tag in ['h1', 'title']:
            title_tag = soup.find(tag)
            if title_tag:
                title = title_tag.get_text(strip=True)
                break
        
        # Find main content
        main_content = (
            soup.find('article') or
            soup.find('main') or
            soup.find('div', class_=re.compile(r'content|post|article'))
        )
        
        if not main_content:
            main_content = soup.find('body')
        
        if not main_content:
            return None
        
        # Remove unwanted elements
        for unwanted in main_content.find_all(['nav', 'header', 'footer', 'aside', 'script', 'style']):
            unwanted.decompose()
        
        # Extract code blocks
        code_blocks = []
        for pre in main_content.find_all('pre'):
            code = pre.get_text()
            if code.strip():
                code_blocks.append({
                    'code': code.strip(),
                    'language': self._detect_language(code),
                })
        
        content = main_content.get_text(separator='\n')
        content = self._clean_content(content)
        
        if len(content) < 200:
            return None
        
        return ScrapedItem(
            url=url,
            title=title,
            content=content,
            code_blocks=code_blocks,
            headers=[],
            metadata={
                'category': 'security/ctf',
                'difficulty': self._estimate_difficulty(content, title),
                'source_type': 'generic',
            }
        )
    
    def _clean_content(self, content: str) -> str:
        """Clean and normalize content."""
        # Remove excessive whitespace
        lines = [line.strip() for line in content.split('\n')]
        content = '\n'.join(line for line in lines if line)
        content = re.sub(r'\n{3,}', '\n\n', content)
        return content.strip()
    
    def _detect_language(self, code: str) -> str:
        """Detect programming language from code."""
        code_lower = code.lower().strip()
        
        if code_lower.startswith(('$', '#!', 'sudo ', 'cd ', 'ls ')):
            return 'bash'
        if any(cmd in code_lower for cmd in ['nmap ', 'curl ', 'wget ', 'nc ']):
            return 'bash'
        if 'import ' in code_lower or 'def ' in code_lower:
            return 'python'
        if '$_' in code_lower or '<?php' in code_lower:
            return 'php'
        if 'select ' in code_lower and 'from ' in code_lower:
            return 'sql'
        
        return ''
    
    def _determine_category(self, title: str, content: str) -> str:
        """Determine category from title and content."""
        text = (title + ' ' + content[:1000]).lower()
        
        for keyword, category in self.CTF_CATEGORIES.items():
            if keyword in text:
                return category
        
        # Check for specific technique mentions
        if any(kw in text for kw in ['sql injection', 'sqli']):
            return 'web_security/sql_injection'
        if any(kw in text for kw in ['xss', 'cross-site scripting']):
            return 'web_security/xss'
        if any(kw in text for kw in ['buffer overflow', 'bof', 'stack']):
            return 'exploitation/binary'
        if any(kw in text for kw in ['privilege escalation', 'privesc', 'root']):
            return 'privilege_escalation'
        
        return 'security/ctf'
    
    def _detect_platform(self, title: str, url: str) -> str:
        """Detect CTF platform from title or URL."""
        text = (title + ' ' + url).lower()
        
        if 'htb' in text or 'hackthebox' in text:
            return 'HackTheBox'
        if 'thm' in text or 'tryhackme' in text:
            return 'TryHackMe'
        if 'picoctf' in text:
            return 'PicoCTF'
        if 'vulnhub' in text:
            return 'VulnHub'
        
        return 'Unknown'
    
    def _estimate_difficulty(self, content: str, title: str) -> str:
        """Estimate difficulty from content."""
        text = (title + ' ' + content).lower()
        
        # Look for explicit difficulty mentions
        if any(kw in text for kw in ['easy', 'beginner', 'simple', 'basic']):
            return 'beginner'
        if any(kw in text for kw in ['hard', 'difficult', 'advanced', 'insane']):
            return 'advanced'
        if any(kw in text for kw in ['medium', 'intermediate', 'moderate']):
            return 'intermediate'
        
        # Estimate based on content complexity
        complex_terms = ['heap', 'kernel', 'rop', 'ret2', 'format string', 'race condition']
        if any(term in text for term in complex_terms):
            return 'advanced'
        
        return 'intermediate'
