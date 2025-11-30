"""
Tests for scrapers module.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from src.scrapers.base_scraper import BaseScraper, ScrapedItem
from src.scrapers import SCRAPER_REGISTRY, list_scrapers, get_scraper


class TestScraperRegistry:
    """Tests for scraper registry."""
    
    def test_list_scrapers(self):
        scrapers = list_scrapers()
        assert len(scrapers) > 0
        assert 'hacktricks' in scrapers
        assert 'owasp' in scrapers
    
    def test_get_scraper(self):
        scraper_class = get_scraper('hacktricks')
        assert scraper_class is not None
        assert scraper_class.__name__ == 'HackTricksScraper'
    
    def test_get_invalid_scraper(self):
        scraper_class = get_scraper('nonexistent')
        assert scraper_class is None
    
    def test_all_scrapers_have_source_name(self):
        for name, scraper_class in SCRAPER_REGISTRY.items():
            assert hasattr(scraper_class, 'SOURCE_NAME')


class TestScrapedItem:
    """Tests for ScrapedItem dataclass."""
    
    def test_create_scraped_item(self):
        item = ScrapedItem(
            url="https://example.com/test",
            title="Test Title",
            content="Test content",
            code_blocks=[],
            headers=["Header 1"],
            metadata={"category": "test"}
        )
        
        assert item.url == "https://example.com/test"
        assert item.title == "Test Title"
        assert item.content == "Test content"
        assert item.metadata['category'] == 'test'
    
    def test_scraped_item_with_code_blocks(self):
        item = ScrapedItem(
            url="https://example.com",
            title="Test",
            content="Content",
            code_blocks=[
                {"language": "python", "code": "print('hello')"},
                {"language": "bash", "code": "ls -la"}
            ],
            headers=[],
            metadata={}
        )
        
        assert len(item.code_blocks) == 2
        assert item.code_blocks[0]['language'] == 'python'


class TestBaseScraper:
    """Tests for BaseScraper base class."""
    
    def test_base_scraper_is_abstract(self):
        # BaseScraper should not be instantiable directly
        # because it has abstract methods
        with pytest.raises(TypeError):
            BaseScraper()
    
    def test_scraper_registry_completeness(self):
        expected_scrapers = [
            'hacktricks', 'ctf_writeups', 'exploit_db',
            'cve', 'nuclei_templates', 'payloads', 'owasp'
        ]
        
        for scraper_name in expected_scrapers:
            assert scraper_name in SCRAPER_REGISTRY, f"Missing scraper: {scraper_name}"


class MockScraper(BaseScraper):
    """Mock scraper for testing."""
    
    SOURCE_NAME = "mock"
    
    async def discover_urls(self):
        return ["https://example.com/1", "https://example.com/2"]
    
    async def scrape_page(self, url):
        return ScrapedItem(
            url=url,
            title=f"Mock Title for {url}",
            content="Mock content",
            code_blocks=[],
            headers=[],
            metadata={"category": "test"}
        )


class TestMockScraper:
    """Tests using mock scraper."""
    
    @pytest.mark.asyncio
    async def test_discover_urls(self):
        scraper = MockScraper()
        urls = await scraper.discover_urls()
        assert len(urls) == 2
        assert "https://example.com/1" in urls
    
    @pytest.mark.asyncio
    async def test_scrape_page(self):
        scraper = MockScraper()
        item = await scraper.scrape_page("https://example.com/test")
        assert item is not None
        assert item.url == "https://example.com/test"
        assert "Mock" in item.title


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
