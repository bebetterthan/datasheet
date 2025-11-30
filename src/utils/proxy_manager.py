"""
Proxy management module for handling proxy rotation and health checking.
"""

import asyncio
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx

from .logger import get_logger

logger = get_logger(__name__)


@dataclass
class ProxyHealth:
    """Health status of a proxy."""
    url: str
    success_count: int = 0
    failure_count: int = 0
    total_response_time: float = 0.0
    last_used: float = 0.0
    last_success: float = 0.0
    last_failure: float = 0.0
    consecutive_failures: int = 0
    is_banned: bool = False
    banned_until: Optional[float] = None
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        total = self.success_count + self.failure_count
        return self.success_count / total if total > 0 else 0.0
    
    @property
    def avg_response_time(self) -> float:
        """Calculate average response time."""
        return self.total_response_time / self.success_count if self.success_count > 0 else float('inf')
    
    @property
    def score(self) -> float:
        """Calculate proxy score for selection (higher is better)."""
        if self.is_banned:
            return -1
        
        # Base score from success rate
        score = self.success_rate * 100
        
        # Penalty for slow response
        if self.avg_response_time > 0:
            score -= min(50, self.avg_response_time * 5)
        
        # Penalty for recent failures
        score -= self.consecutive_failures * 10
        
        # Bonus for being less recently used (load balancing)
        if self.last_used > 0:
            time_since_use = time.time() - self.last_used
            score += min(10, time_since_use / 10)
        
        return max(0, score)


class ProxyManager:
    """
    Manages a pool of proxies with health checking and rotation.
    """
    
    def __init__(
        self,
        proxies: Optional[List[str]] = None,
        proxy_file: Optional[str] = None,
        rotation_strategy: str = "weighted_random",  # "round_robin", "random", "weighted_random"
        health_check_interval: int = 300,  # seconds
        max_consecutive_failures: int = 5,
        ban_duration: int = 600,  # seconds
        test_url: str = "https://httpbin.org/ip",
    ):
        """
        Initialize the proxy manager.
        
        Args:
            proxies: List of proxy URLs
            proxy_file: Path to file containing proxy URLs (one per line)
            rotation_strategy: Strategy for proxy rotation
            health_check_interval: Interval for health checks in seconds
            max_consecutive_failures: Max failures before banning proxy
            ban_duration: Duration of ban in seconds
            test_url: URL for health check tests
        """
        self.rotation_strategy = rotation_strategy
        self.health_check_interval = health_check_interval
        self.max_consecutive_failures = max_consecutive_failures
        self.ban_duration = ban_duration
        self.test_url = test_url
        
        self._proxies: Dict[str, ProxyHealth] = {}
        self._rotation_index = 0
        self._lock = asyncio.Lock()
        self._health_check_task: Optional[asyncio.Task] = None
        
        # Load proxies
        if proxies:
            for proxy in proxies:
                self._add_proxy(proxy)
        
        if proxy_file:
            self._load_from_file(proxy_file)
    
    def _add_proxy(self, proxy_url: str) -> None:
        """Add a proxy to the pool."""
        # Normalize proxy URL
        if not proxy_url.startswith(('http://', 'https://', 'socks5://', 'socks4://')):
            proxy_url = f"http://{proxy_url}"
        
        if proxy_url not in self._proxies:
            self._proxies[proxy_url] = ProxyHealth(url=proxy_url)
            logger.debug(f"Added proxy: {proxy_url}")
    
    def _load_from_file(self, filepath: str) -> None:
        """Load proxies from a file."""
        path = Path(filepath)
        if not path.exists():
            logger.warning(f"Proxy file not found: {filepath}")
            return
        
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    self._add_proxy(line)
        
        logger.info(f"Loaded {len(self._proxies)} proxies from {filepath}")
    
    @property
    def available_proxies(self) -> List[str]:
        """Get list of available (non-banned) proxies."""
        now = time.time()
        available = []
        
        for url, health in self._proxies.items():
            if health.is_banned:
                if health.banned_until and now > health.banned_until:
                    # Unban proxy
                    health.is_banned = False
                    health.banned_until = None
                    health.consecutive_failures = 0
                    available.append(url)
            else:
                available.append(url)
        
        return available
    
    @property
    def has_proxies(self) -> bool:
        """Check if any proxies are available."""
        return len(self.available_proxies) > 0
    
    async def get_proxy(self) -> Optional[str]:
        """
        Get the next proxy based on the rotation strategy.
        
        Returns:
            Proxy URL or None if no proxies available
        """
        available = self.available_proxies
        
        if not available:
            return None
        
        async with self._lock:
            if self.rotation_strategy == "round_robin":
                proxy_url = available[self._rotation_index % len(available)]
                self._rotation_index += 1
            
            elif self.rotation_strategy == "random":
                proxy_url = random.choice(available)
            
            elif self.rotation_strategy == "weighted_random":
                # Weight by proxy score
                weights = [max(0.1, self._proxies[url].score) for url in available]
                total_weight = sum(weights)
                weights = [w / total_weight for w in weights]
                
                proxy_url = random.choices(available, weights=weights, k=1)[0]
            
            else:
                proxy_url = available[0]
            
            # Update last used
            self._proxies[proxy_url].last_used = time.time()
            
            return proxy_url
    
    async def report_success(self, proxy_url: str, response_time: float) -> None:
        """Report a successful request through a proxy."""
        if proxy_url not in self._proxies:
            return
        
        async with self._lock:
            health = self._proxies[proxy_url]
            health.success_count += 1
            health.total_response_time += response_time
            health.last_success = time.time()
            health.consecutive_failures = 0
    
    async def report_failure(self, proxy_url: str, error: Optional[str] = None) -> None:
        """Report a failed request through a proxy."""
        if proxy_url not in self._proxies:
            return
        
        async with self._lock:
            health = self._proxies[proxy_url]
            health.failure_count += 1
            health.last_failure = time.time()
            health.consecutive_failures += 1
            
            # Check if should be banned
            if health.consecutive_failures >= self.max_consecutive_failures:
                health.is_banned = True
                health.banned_until = time.time() + self.ban_duration
                logger.warning(
                    f"Proxy {proxy_url} banned for {self.ban_duration}s "
                    f"after {health.consecutive_failures} consecutive failures"
                )
    
    async def test_proxy(self, proxy_url: str, timeout: float = 10.0) -> bool:
        """
        Test if a proxy is working.
        
        Args:
            proxy_url: Proxy URL to test
            timeout: Timeout for the test request
            
        Returns:
            True if proxy is working, False otherwise
        """
        try:
            start_time = time.time()
            async with httpx.AsyncClient(
                proxies={"all://": proxy_url},
                timeout=timeout,
                follow_redirects=True,
            ) as client:
                response = await client.get(self.test_url)
                response_time = time.time() - start_time
                
                if response.status_code == 200:
                    await self.report_success(proxy_url, response_time)
                    return True
                else:
                    await self.report_failure(proxy_url, f"HTTP {response.status_code}")
                    return False
        
        except Exception as e:
            await self.report_failure(proxy_url, str(e))
            return False
    
    async def health_check_all(self) -> Dict[str, bool]:
        """
        Run health check on all proxies.
        
        Returns:
            Dict mapping proxy URL to health status
        """
        logger.info("Running health check on all proxies...")
        results = {}
        
        tasks = [self.test_proxy(url) for url in self._proxies.keys()]
        proxy_urls = list(self._proxies.keys())
        
        test_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for url, result in zip(proxy_urls, test_results):
            if isinstance(result, Exception):
                results[url] = False
            else:
                results[url] = result
        
        healthy = sum(1 for v in results.values() if v)
        logger.info(f"Health check complete: {healthy}/{len(results)} proxies healthy")
        
        return results
    
    async def start_health_checks(self) -> None:
        """Start periodic health checks."""
        if self._health_check_task is not None:
            return
        
        async def _health_check_loop():
            while True:
                await asyncio.sleep(self.health_check_interval)
                await self.health_check_all()
        
        self._health_check_task = asyncio.create_task(_health_check_loop())
        logger.info(f"Started periodic health checks (interval: {self.health_check_interval}s)")
    
    async def stop_health_checks(self) -> None:
        """Stop periodic health checks."""
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
            self._health_check_task = None
    
    def get_stats(self) -> Dict[str, dict]:
        """Get statistics for all proxies."""
        stats = {}
        for url, health in self._proxies.items():
            stats[url] = {
                'success_count': health.success_count,
                'failure_count': health.failure_count,
                'success_rate': f"{health.success_rate:.1%}",
                'avg_response_time': f"{health.avg_response_time:.2f}s" if health.avg_response_time != float('inf') else "N/A",
                'score': f"{health.score:.1f}",
                'is_banned': health.is_banned,
            }
        return stats
    
    def remove_proxy(self, proxy_url: str) -> None:
        """Remove a proxy from the pool."""
        if proxy_url in self._proxies:
            del self._proxies[proxy_url]
            logger.info(f"Removed proxy: {proxy_url}")
    
    def clear_all(self) -> None:
        """Remove all proxies."""
        self._proxies.clear()
        self._rotation_index = 0


def get_httpx_proxy_config(proxy_url: Optional[str]) -> Optional[Dict[str, str]]:
    """
    Get httpx-compatible proxy configuration.
    
    Args:
        proxy_url: Proxy URL
        
    Returns:
        Dict for httpx proxies parameter
    """
    if not proxy_url:
        return None
    
    # httpx uses "all://" for all traffic
    return {"all://": proxy_url}
