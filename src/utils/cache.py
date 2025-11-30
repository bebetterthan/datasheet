"""
Caching module for efficient scraping.
Provides disk-based caching with TTL support.
"""

import json
import hashlib
import time
from pathlib import Path
from typing import Any, Optional, Dict
from datetime import datetime, timedelta
import asyncio
import aiofiles

try:
    import diskcache
    HAS_DISKCACHE = True
except ImportError:
    HAS_DISKCACHE = False


class ScraperCache:
    """
    Disk-based cache for scraped content.
    Reduces redundant network requests.
    """
    
    def __init__(
        self,
        cache_dir: str = ".cache/scraper",
        default_ttl: int = 86400 * 7,  # 7 days
        max_size: int = 1024 * 1024 * 500,  # 500MB
    ):
        """
        Initialize cache.
        
        Args:
            cache_dir: Directory for cache storage
            default_ttl: Default time-to-live in seconds
            max_size: Maximum cache size in bytes
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.default_ttl = default_ttl
        self.max_size = max_size
        
        if HAS_DISKCACHE:
            self._cache = diskcache.Cache(
                str(self.cache_dir),
                size_limit=max_size,
            )
        else:
            self._cache = None
            self._simple_cache_dir = self.cache_dir / "simple"
            self._simple_cache_dir.mkdir(exist_ok=True)
    
    def _url_to_key(self, url: str) -> str:
        """Convert URL to cache key."""
        return hashlib.md5(url.encode()).hexdigest()
    
    def get(self, url: str) -> Optional[str]:
        """
        Get cached content for URL.
        
        Args:
            url: URL to look up
            
        Returns:
            Cached content or None if not found/expired
        """
        key = self._url_to_key(url)
        
        if self._cache:
            return self._cache.get(key)
        else:
            return self._simple_get(key)
    
    def set(self, url: str, content: str, ttl: Optional[int] = None):
        """
        Cache content for URL.
        
        Args:
            url: URL to cache
            content: Content to store
            ttl: Time-to-live in seconds
        """
        key = self._url_to_key(url)
        ttl = ttl or self.default_ttl
        
        if self._cache:
            self._cache.set(key, content, expire=ttl)
        else:
            self._simple_set(key, content, ttl)
    
    def _simple_get(self, key: str) -> Optional[str]:
        """Simple file-based cache get."""
        cache_file = self._simple_cache_dir / f"{key}.json"
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if data['expires_at'] < time.time():
                cache_file.unlink()
                return None
            
            return data['content']
        except (json.JSONDecodeError, KeyError):
            return None
    
    def _simple_set(self, key: str, content: str, ttl: int):
        """Simple file-based cache set."""
        cache_file = self._simple_cache_dir / f"{key}.json"
        
        data = {
            'content': content,
            'expires_at': time.time() + ttl,
            'cached_at': datetime.utcnow().isoformat(),
        }
        
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(data, f)
    
    async def get_async(self, url: str) -> Optional[str]:
        """Async version of get."""
        key = self._url_to_key(url)
        
        if self._cache:
            return self._cache.get(key)
        
        cache_file = self._simple_cache_dir / f"{key}.json"
        
        if not cache_file.exists():
            return None
        
        try:
            async with aiofiles.open(cache_file, 'r', encoding='utf-8') as f:
                data = json.loads(await f.read())
            
            if data['expires_at'] < time.time():
                cache_file.unlink()
                return None
            
            return data['content']
        except (json.JSONDecodeError, KeyError):
            return None
    
    async def set_async(self, url: str, content: str, ttl: Optional[int] = None):
        """Async version of set."""
        key = self._url_to_key(url)
        ttl = ttl or self.default_ttl
        
        if self._cache:
            self._cache.set(key, content, expire=ttl)
            return
        
        cache_file = self._simple_cache_dir / f"{key}.json"
        
        data = {
            'content': content,
            'expires_at': time.time() + ttl,
            'cached_at': datetime.utcnow().isoformat(),
        }
        
        async with aiofiles.open(cache_file, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(data))
    
    def clear(self):
        """Clear all cached content."""
        if self._cache:
            self._cache.clear()
        else:
            for f in self._simple_cache_dir.glob("*.json"):
                f.unlink()
    
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        if self._cache:
            return {
                'size': self._cache.volume(),
                'count': len(self._cache),
            }
        else:
            files = list(self._simple_cache_dir.glob("*.json"))
            total_size = sum(f.stat().st_size for f in files)
            return {
                'size': total_size,
                'count': len(files),
            }


class ResponseCache:
    """
    In-memory LRU cache for HTTP responses.
    For frequently accessed resources during a session.
    """
    
    def __init__(self, maxsize: int = 1000):
        self.maxsize = maxsize
        self._cache: Dict[str, tuple] = {}
        self._access_order: list = []
    
    def get(self, key: str) -> Optional[Any]:
        """Get cached value."""
        if key in self._cache:
            value, timestamp = self._cache[key]
            # Move to end (most recent)
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)
            return value
        return None
    
    def set(self, key: str, value: Any):
        """Set cached value."""
        if key in self._cache:
            self._access_order.remove(key)
        elif len(self._cache) >= self.maxsize:
            # Remove oldest
            oldest = self._access_order.pop(0)
            del self._cache[oldest]
        
        self._cache[key] = (value, time.time())
        self._access_order.append(key)
    
    def clear(self):
        """Clear cache."""
        self._cache.clear()
        self._access_order.clear()
