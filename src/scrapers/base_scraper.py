"""
Base scraper class that all scrapers inherit from.
Provides common functionality for web scraping.
"""

import asyncio
import hashlib
import json
import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import httpx
import aiofiles

from ..utils.rate_limiter import RateLimiter, AdaptiveRateLimiter
from ..utils.proxy_manager import ProxyManager, get_httpx_proxy_config
from ..utils.logger import get_logger, ScrapingProgressTracker
from ..utils.config import ScrapingConfig, SourceConfig
from ..processors.content_cleaner import ContentCleaner, ExtractedContent
from ..generators.qa_generator import QAGenerator, QAPair


logger = get_logger(__name__)


class ScrapedItem:
    """Represents a scraped item."""
    
    def __init__(
        self,
        url: str,
        title: str,
        content: str,
        code_blocks: Optional[List[Dict]] = None,
        headers: Optional[List[Dict]] = None,
        metadata: Optional[Dict] = None,
    ):
        self.url = url
        self.title = title
        self.content = content
        self.code_blocks = code_blocks or []
        self.headers = headers or []
        self.metadata = metadata or {}
        self.scraped_at = datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'url': self.url,
            'title': self.title,
            'content': self.content,
            'code_blocks': self.code_blocks,
            'headers': self.headers,
            'metadata': self.metadata,
            'scraped_at': self.scraped_at,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScrapedItem':
        item = cls(
            url=data['url'],
            title=data['title'],
            content=data['content'],
            code_blocks=data.get('code_blocks', []),
            headers=data.get('headers', []),
            metadata=data.get('metadata', {}),
        )
        item.scraped_at = data.get('scraped_at', datetime.utcnow().isoformat())
        return item


class ProgressTracker:
    """Tracks scraping progress with SQLite for resume capability."""
    
    def __init__(self, db_path: str = "data/progress.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self):
        """Initialize SQLite database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scraped_urls (
                    url TEXT PRIMARY KEY,
                    source TEXT,
                    status TEXT,
                    scraped_at TIMESTAMP,
                    error_message TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scrape_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    total_urls INTEGER,
                    success_count INTEGER,
                    error_count INTEGER
                )
            """)
            conn.commit()
    
    def is_scraped(self, url: str) -> bool:
        """Check if URL has been scraped."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT 1 FROM scraped_urls WHERE url = ? AND status = 'success'",
                (url,)
            )
            return cursor.fetchone() is not None
    
    def mark_scraped(
        self,
        url: str,
        source: str,
        status: str = "success",
        error_message: str = "",
    ):
        """Mark URL as scraped."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO scraped_urls (url, source, status, scraped_at, error_message)
                VALUES (?, ?, ?, ?, ?)
            """, (url, source, status, datetime.utcnow().isoformat(), error_message))
            conn.commit()
    
    def get_scraped_count(self, source: str) -> Dict[str, int]:
        """Get count of scraped URLs for a source."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT status, COUNT(*) FROM scraped_urls 
                WHERE source = ? GROUP BY status
            """, (source,))
            return dict(cursor.fetchall())
    
    def clear_source(self, source: str):
        """Clear all records for a source."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM scraped_urls WHERE source = ?", (source,))
            conn.commit()


class BaseScraper(ABC):
    """
    Abstract base class for all scrapers.
    Provides common scraping functionality.
    """
    
    # Override in subclasses
    SOURCE_NAME = "base"
    BASE_URL = ""
    
    def __init__(
        self,
        config: Optional[ScrapingConfig] = None,
        source_config: Optional[SourceConfig] = None,
        rate_limiter: Optional[RateLimiter] = None,
        proxy_manager: Optional[ProxyManager] = None,
        output_dir: str = "data/raw",
        use_playwright: bool = False,
        resume: bool = True,
    ):
        """
        Initialize base scraper.
        
        Args:
            config: Scraping configuration
            source_config: Source-specific configuration
            rate_limiter: Rate limiter instance
            proxy_manager: Proxy manager instance
            output_dir: Directory for raw output
            use_playwright: Use Playwright for JS rendering
            resume: Enable resume capability
        """
        self.config = config or ScrapingConfig()
        self.source_config = source_config
        self.output_dir = Path(output_dir) / self.SOURCE_NAME
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.use_playwright = use_playwright
        self.resume = resume
        
        # Initialize components
        self.rate_limiter = rate_limiter or AdaptiveRateLimiter(
            initial_rate=1.0 / self.config.delay_between_requests,
            min_rate=0.1,
            max_rate=self.config.concurrent_requests,
        )
        self.proxy_manager = proxy_manager
        self.content_cleaner = ContentCleaner()
        self.qa_generator = QAGenerator()
        self.progress_tracker = ProgressTracker() if resume else None
        
        # Robot parser
        self._robots_parser: Optional[RobotFileParser] = None
        self._robots_checked = False
        
        # HTTP client
        self._client: Optional[httpx.AsyncClient] = None
        
        # Playwright browser
        self._browser = None
        self._playwright = None
        
        # Statistics
        self.stats = {
            'urls_discovered': 0,
            'urls_scraped': 0,
            'urls_skipped': 0,
            'urls_failed': 0,
            'items_extracted': 0,
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self._init_client()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self._close_client()
    
    async def _init_client(self):
        """Initialize HTTP client."""
        proxy_url = None
        if self.proxy_manager and self.proxy_manager.has_proxies:
            proxy_url = await self.proxy_manager.get_proxy()
        
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.timeout),
            follow_redirects=True,
            headers={
                'User-Agent': self.config.user_agent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            },
            proxy=proxy_url,  # httpx uses 'proxy' not 'proxies'
        )
        
        # Initialize Playwright if needed
        if self.use_playwright:
            await self._init_playwright()
    
    async def _init_playwright(self):
        """Initialize Playwright browser."""
        try:
            from playwright.async_api import async_playwright
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=self.config.headless
            )
        except ImportError:
            logger.warning("Playwright not installed, falling back to httpx")
            self.use_playwright = False
    
    async def _close_client(self):
        """Close HTTP client and browser."""
        if self._client:
            await self._client.aclose()
            self._client = None
        
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
    
    async def _check_robots(self) -> bool:
        """Check robots.txt for permission."""
        if self._robots_checked:
            return True
        
        if not self.config.respect_robots_txt:
            self._robots_checked = True
            return True
        
        try:
            robots_url = urljoin(self.BASE_URL, '/robots.txt')
            response = await self._client.get(robots_url)
            
            if response.status_code == 200:
                self._robots_parser = RobotFileParser()
                self._robots_parser.parse(response.text.split('\n'))
        except Exception as e:
            logger.warning(f"Could not fetch robots.txt: {e}")
        
        self._robots_checked = True
        return True
    
    def _can_fetch(self, url: str) -> bool:
        """Check if URL can be fetched according to robots.txt."""
        if not self.config.respect_robots_txt:
            return True
        
        if self._robots_parser is None:
            return True
        
        return self._robots_parser.can_fetch(self.config.user_agent, url)
    
    async def fetch_page(self, url: str) -> Optional[str]:
        """
        Fetch a page with rate limiting and error handling.
        
        Args:
            url: URL to fetch
            
        Returns:
            HTML content or None on failure
        """
        # Check robots.txt
        await self._check_robots()
        if not self._can_fetch(url):
            logger.warning(f"Blocked by robots.txt: {url}")
            return None
        
        # Check if already scraped
        if self.resume and self.progress_tracker and self.progress_tracker.is_scraped(url):
            logger.debug(f"Skipping already scraped: {url}")
            self.stats['urls_skipped'] += 1
            return None
        
        # Rate limiting
        await self.rate_limiter.acquire(url)
        
        try:
            if self.use_playwright and self._browser:
                return await self._fetch_with_playwright(url)
            else:
                return await self._fetch_with_httpx(url)
        
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error {e.response.status_code} for {url}")
            await self.rate_limiter.handle_response(url, e.response)
            self._mark_failed(url, str(e))
            return None
        
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            self._mark_failed(url, str(e))
            return None
    
    async def _fetch_with_httpx(self, url: str) -> Optional[str]:
        """Fetch page using httpx."""
        response = await self._client.get(url)
        response.raise_for_status()
        
        await self.rate_limiter.handle_response(url, response)
        self.stats['urls_scraped'] += 1
        
        return response.text
    
    async def _fetch_with_playwright(self, url: str) -> Optional[str]:
        """Fetch page using Playwright for JS rendering."""
        page = await self._browser.new_page()
        try:
            await page.goto(url, wait_until='networkidle')
            content = await page.content()
            self.stats['urls_scraped'] += 1
            return content
        finally:
            await page.close()
    
    def _mark_failed(self, url: str, error: str):
        """Mark URL as failed."""
        self.stats['urls_failed'] += 1
        if self.progress_tracker:
            self.progress_tracker.mark_scraped(url, self.SOURCE_NAME, 'failed', error)
    
    def _mark_success(self, url: str):
        """Mark URL as successfully scraped."""
        if self.progress_tracker:
            self.progress_tracker.mark_scraped(url, self.SOURCE_NAME, 'success')
    
    async def save_raw(self, item: ScrapedItem) -> Path:
        """Save raw scraped item to file."""
        # Create filename from URL hash
        url_hash = hashlib.md5(item.url.encode()).hexdigest()[:12]
        filename = f"{url_hash}.json"
        filepath = self.output_dir / filename
        
        async with aiofiles.open(filepath, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(item.to_dict(), ensure_ascii=False, indent=2))
        
        return filepath
    
    def parse_content(self, html: str, url: str) -> ExtractedContent:
        """Parse HTML content using content cleaner."""
        return self.content_cleaner.clean_html(html)
    
    def generate_qa_pairs(
        self,
        item: ScrapedItem,
        category: str = "",
    ) -> List[QAPair]:
        """Generate Q&A pairs from scraped item."""
        return self.qa_generator.generate_from_content(
            title=item.title,
            content=item.content,
            source=item.url,
            category=category,
            code_blocks=item.code_blocks,
        )
    
    @abstractmethod
    async def discover_urls(self) -> List[str]:
        """
        Discover URLs to scrape.
        Must be implemented by subclasses.
        """
        pass
    
    @abstractmethod
    async def scrape_page(self, url: str) -> Optional[ScrapedItem]:
        """
        Scrape a single page.
        Must be implemented by subclasses.
        """
        pass
    
    async def scrape_all(
        self,
        max_pages: Optional[int] = None,
        progress_callback=None,
    ) -> AsyncIterator[ScrapedItem]:
        """
        Scrape all discovered URLs.
        
        Args:
            max_pages: Maximum pages to scrape
            progress_callback: Progress callback function
            
        Yields:
            ScrapedItem for each successfully scraped page
        """
        urls = await self.discover_urls()
        self.stats['urls_discovered'] = len(urls)
        
        if max_pages:
            urls = urls[:max_pages]
        
        logger.info(f"Starting scrape of {len(urls)} URLs from {self.SOURCE_NAME}")
        
        # Use semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.config.concurrent_requests)
        
        async def scrape_with_semaphore(url: str) -> Optional[ScrapedItem]:
            async with semaphore:
                return await self.scrape_page(url)
        
        # Process URLs
        for i, url in enumerate(urls):
            item = await scrape_with_semaphore(url)
            
            if item:
                self._mark_success(url)
                self.stats['items_extracted'] += 1
                
                # Save raw data
                await self.save_raw(item)
                
                yield item
            
            if progress_callback:
                progress_callback(i + 1, len(urls))
        
        logger.info(f"Scraping complete. Stats: {self.stats}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scraping statistics."""
        return {
            'source': self.SOURCE_NAME,
            'base_url': self.BASE_URL,
            **self.stats,
        }
