"""
Tests for utilities module.
"""

import pytest
import asyncio
import time
from src.utils.rate_limiter import RateLimiter, AdaptiveRateLimiter
from src.utils.config import ScrapingConfig, SourceConfig


class TestRateLimiter:
    """Tests for RateLimiter."""
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self):
        limiter = RateLimiter(rate=10.0, burst=1)  # 10 requests per second
        
        start = time.time()
        
        # Make 3 requests
        for _ in range(3):
            await limiter.acquire()
        
        elapsed = time.time() - start
        
        # Should take at least 0.2 seconds (2 intervals of 0.1s)
        assert elapsed >= 0.15  # Allow some tolerance
    
    @pytest.mark.asyncio
    async def test_burst_capacity(self):
        limiter = RateLimiter(rate=1.0, burst=5)  # 1 request per second, burst of 5
        
        start = time.time()
        
        # Burst 5 requests should be near-instant
        for _ in range(5):
            await limiter.acquire()
        
        elapsed = time.time() - start
        
        # Burst should be fast
        assert elapsed < 1.0


class TestAdaptiveRateLimiter:
    """Tests for AdaptiveRateLimiter."""
    
    def test_rate_increase_on_success(self):
        limiter = AdaptiveRateLimiter(initial_rate=1.0)
        initial_rate = limiter.current_rate
        
        # Simulate successful requests
        for _ in range(5):
            limiter.record_success()
        
        assert limiter.current_rate >= initial_rate
    
    def test_rate_decrease_on_error(self):
        limiter = AdaptiveRateLimiter(initial_rate=5.0)
        initial_rate = limiter.current_rate
        
        # Simulate error
        limiter.record_error()
        
        assert limiter.current_rate <= initial_rate


class TestConfig:
    """Tests for configuration classes."""
    
    def test_default_scraping_config(self):
        config = ScrapingConfig()
        
        assert config.timeout > 0
        assert config.max_retries > 0
        assert config.concurrent_requests > 0
    
    def test_source_config(self):
        config = SourceConfig(
            name="test",
            base_url="https://example.com",
            enabled=True,
            rate_limit=2.0
        )
        
        assert config.name == "test"
        assert config.enabled is True
        assert config.rate_limit == 2.0
    
    def test_config_with_custom_values(self):
        config = ScrapingConfig(
            timeout=60,
            max_retries=5,
            concurrent_requests=20
        )
        
        assert config.timeout == 60
        assert config.max_retries == 5
        assert config.concurrent_requests == 20


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
