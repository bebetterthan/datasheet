"""
Rate limiting module for responsible scraping.
Implements token bucket algorithm and respects server rate limits.
"""

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Optional
from urllib.parse import urlparse

import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

from .logger import get_logger

logger = get_logger(__name__)


@dataclass
class RateLimitState:
    """State for a single domain's rate limiting."""
    tokens: float = 10.0
    max_tokens: float = 10.0
    refill_rate: float = 1.0  # tokens per second
    last_refill: float = field(default_factory=time.time)
    last_request: float = 0.0
    requests_count: int = 0
    backoff_until: Optional[float] = None


class RateLimiter:
    """
    Rate limiter implementing token bucket algorithm.
    Supports per-domain rate limiting and automatic backoff on 429 responses.
    """
    
    def __init__(
        self,
        requests_per_second: float = 1.0,
        burst_size: int = 10,
        respect_retry_after: bool = True,
        global_delay: float = 0.5,
    ):
        """
        Initialize the rate limiter.
        
        Args:
            requests_per_second: Maximum requests per second per domain
            burst_size: Maximum burst size (token bucket capacity)
            respect_retry_after: Whether to respect Retry-After headers
            global_delay: Minimum delay between any two requests
        """
        self.requests_per_second = requests_per_second
        self.burst_size = burst_size
        self.respect_retry_after = respect_retry_after
        self.global_delay = global_delay
        
        self._domain_states: Dict[str, RateLimitState] = defaultdict(
            lambda: RateLimitState(
                tokens=float(burst_size),
                max_tokens=float(burst_size),
                refill_rate=requests_per_second,
            )
        )
        self._lock = asyncio.Lock()
        self._last_global_request = 0.0
    
    def _get_domain(self, url: str) -> str:
        """Extract domain from URL."""
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    
    def _refill_tokens(self, state: RateLimitState) -> None:
        """Refill tokens based on time elapsed."""
        now = time.time()
        elapsed = now - state.last_refill
        tokens_to_add = elapsed * state.refill_rate
        state.tokens = min(state.max_tokens, state.tokens + tokens_to_add)
        state.last_refill = now
    
    async def acquire(self, url: str) -> float:
        """
        Acquire permission to make a request.
        
        Args:
            url: The URL to request
            
        Returns:
            Time waited in seconds
        """
        domain = self._get_domain(url)
        wait_time = 0.0
        
        async with self._lock:
            state = self._domain_states[domain]
            
            # Check if we're in backoff period
            if state.backoff_until:
                now = time.time()
                if now < state.backoff_until:
                    wait_time = state.backoff_until - now
                    logger.debug(f"Rate limited for {domain}, waiting {wait_time:.2f}s")
                    await asyncio.sleep(wait_time)
                state.backoff_until = None
            
            # Refill tokens
            self._refill_tokens(state)
            
            # Wait for token if needed
            if state.tokens < 1:
                wait_for_token = (1 - state.tokens) / state.refill_rate
                logger.debug(f"Waiting {wait_for_token:.2f}s for token on {domain}")
                await asyncio.sleep(wait_for_token)
                wait_time += wait_for_token
                self._refill_tokens(state)
            
            # Apply global delay
            now = time.time()
            global_wait = self.global_delay - (now - self._last_global_request)
            if global_wait > 0:
                await asyncio.sleep(global_wait)
                wait_time += global_wait
            
            # Consume token
            state.tokens -= 1
            state.last_request = time.time()
            state.requests_count += 1
            self._last_global_request = time.time()
        
        return wait_time
    
    async def handle_response(self, url: str, response: httpx.Response) -> None:
        """
        Handle response and adjust rate limiting if needed.
        
        Args:
            url: The requested URL
            response: The HTTP response
        """
        domain = self._get_domain(url)
        
        if response.status_code == 429:  # Too Many Requests
            async with self._lock:
                state = self._domain_states[domain]
                
                # Get retry-after header
                retry_after = None
                if self.respect_retry_after:
                    retry_after_header = response.headers.get('Retry-After')
                    if retry_after_header:
                        try:
                            retry_after = int(retry_after_header)
                        except ValueError:
                            # Try parsing as HTTP date
                            try:
                                retry_date = datetime.strptime(
                                    retry_after_header,
                                    '%a, %d %b %Y %H:%M:%S GMT'
                                )
                                retry_after = (retry_date - datetime.utcnow()).total_seconds()
                            except ValueError:
                                pass
                
                # Default backoff if no Retry-After header
                if retry_after is None:
                    retry_after = 60  # Default to 60 seconds
                
                state.backoff_until = time.time() + retry_after
                
                # Reduce rate for this domain
                state.refill_rate = max(0.1, state.refill_rate * 0.5)
                
                logger.warning(
                    f"Rate limited by {domain}, backing off for {retry_after}s. "
                    f"New rate: {state.refill_rate:.2f} req/s"
                )
        
        elif response.status_code == 200:
            # Gradually increase rate on success
            async with self._lock:
                state = self._domain_states[domain]
                if state.refill_rate < self.requests_per_second:
                    state.refill_rate = min(
                        self.requests_per_second,
                        state.refill_rate * 1.1
                    )
    
    def get_stats(self) -> Dict[str, dict]:
        """Get statistics for all domains."""
        stats = {}
        for domain, state in self._domain_states.items():
            stats[domain] = {
                'requests_count': state.requests_count,
                'current_tokens': state.tokens,
                'current_rate': state.refill_rate,
                'in_backoff': state.backoff_until is not None and time.time() < state.backoff_until,
            }
        return stats
    
    def reset_domain(self, domain: str) -> None:
        """Reset rate limiting state for a specific domain."""
        if domain in self._domain_states:
            del self._domain_states[domain]
    
    def reset_all(self) -> None:
        """Reset all rate limiting state."""
        self._domain_states.clear()
        self._last_global_request = 0.0


class AdaptiveRateLimiter(RateLimiter):
    """
    Adaptive rate limiter that adjusts rates based on response times and errors.
    """
    
    def __init__(
        self,
        initial_rate: float = 1.0,
        min_rate: float = 0.1,
        max_rate: float = 10.0,
        target_response_time: float = 2.0,
        **kwargs
    ):
        super().__init__(requests_per_second=initial_rate, **kwargs)
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.target_response_time = target_response_time
        self._response_times: Dict[str, list] = defaultdict(list)
    
    async def record_response_time(self, url: str, response_time: float) -> None:
        """Record response time for adaptive rate adjustment."""
        domain = self._get_domain(url)
        
        async with self._lock:
            # Keep last 10 response times
            self._response_times[domain].append(response_time)
            if len(self._response_times[domain]) > 10:
                self._response_times[domain].pop(0)
            
            # Adjust rate based on average response time
            avg_response_time = sum(self._response_times[domain]) / len(self._response_times[domain])
            state = self._domain_states[domain]
            
            if avg_response_time < self.target_response_time * 0.5:
                # Server is fast, increase rate
                new_rate = min(self.max_rate, state.refill_rate * 1.2)
            elif avg_response_time > self.target_response_time * 1.5:
                # Server is slow, decrease rate
                new_rate = max(self.min_rate, state.refill_rate * 0.8)
            else:
                new_rate = state.refill_rate
            
            if new_rate != state.refill_rate:
                logger.debug(
                    f"Adjusting rate for {domain}: {state.refill_rate:.2f} -> {new_rate:.2f} "
                    f"(avg response time: {avg_response_time:.2f}s)"
                )
                state.refill_rate = new_rate


def create_retry_decorator(
    max_attempts: int = 3,
    min_wait: float = 1.0,
    max_wait: float = 60.0,
    retry_on_timeout: bool = True,
    retry_on_connection_error: bool = True,
):
    """
    Create a tenacity retry decorator with exponential backoff.
    
    Args:
        max_attempts: Maximum number of retry attempts
        min_wait: Minimum wait time between retries
        max_wait: Maximum wait time between retries
        retry_on_timeout: Whether to retry on timeout errors
        retry_on_connection_error: Whether to retry on connection errors
        
    Returns:
        Configured retry decorator
    """
    exceptions_to_retry = []
    
    if retry_on_timeout:
        exceptions_to_retry.append(httpx.TimeoutException)
    if retry_on_connection_error:
        exceptions_to_retry.append(httpx.ConnectError)
        exceptions_to_retry.append(httpx.NetworkError)
    
    return retry(
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(multiplier=1, min=min_wait, max=max_wait),
        retry=retry_if_exception_type(tuple(exceptions_to_retry)) if exceptions_to_retry else None,
        before_sleep=before_sleep_log(logger, logging_level=20),  # INFO level
        reraise=True,
    )


class RateLimitContext:
    """Context manager for rate-limited requests."""
    
    def __init__(self, rate_limiter: RateLimiter, url: str):
        self.rate_limiter = rate_limiter
        self.url = url
        self.wait_time: float = 0.0
        self.start_time: float = 0.0
    
    async def __aenter__(self):
        self.wait_time = await self.rate_limiter.acquire(self.url)
        self.start_time = time.time()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if isinstance(self.rate_limiter, AdaptiveRateLimiter):
            response_time = time.time() - self.start_time
            await self.rate_limiter.record_response_time(self.url, response_time)
        return False
