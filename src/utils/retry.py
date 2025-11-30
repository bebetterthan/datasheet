"""
Retry utilities with exponential backoff and circuit breaker.
"""

import asyncio
import functools
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Type, Tuple, Any
from enum import Enum

from .logger import get_logger

logger = get_logger(__name__)


class CircuitState(str, Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"      # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    retry_on: Tuple[Type[Exception], ...] = (Exception,)
    
    def get_delay(self, attempt: int) -> float:
        """Calculate delay for attempt number."""
        delay = min(
            self.base_delay * (self.exponential_base ** attempt),
            self.max_delay
        )
        if self.jitter:
            import random
            delay *= (0.5 + random.random())
        return delay


@dataclass 
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    half_open_max_calls: int = 3


class CircuitBreaker:
    """
    Circuit breaker pattern implementation.
    Prevents cascading failures by stopping requests to failing services.
    """
    
    def __init__(self, config: Optional[CircuitBreakerConfig] = None):
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = 0.0
        self._half_open_calls = 0
    
    @property
    def state(self) -> CircuitState:
        """Get current state, checking for recovery."""
        if self._state == CircuitState.OPEN:
            if time.time() - self._last_failure_time > self.config.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
        return self._state
    
    def can_execute(self) -> bool:
        """Check if execution is allowed."""
        state = self.state
        if state == CircuitState.CLOSED:
            return True
        if state == CircuitState.HALF_OPEN:
            return self._half_open_calls < self.config.half_open_max_calls
        return False
    
    def record_success(self):
        """Record successful execution."""
        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.config.half_open_max_calls:
                self._reset()
        elif self._state == CircuitState.CLOSED:
            self._failure_count = max(0, self._failure_count - 1)
    
    def record_failure(self):
        """Record failed execution."""
        self._failure_count += 1
        self._last_failure_time = time.time()
        
        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.OPEN
            self._half_open_calls = 0
        elif self._failure_count >= self.config.failure_threshold:
            self._state = CircuitState.OPEN
            logger.warning(f"Circuit breaker opened after {self._failure_count} failures")
    
    def _reset(self):
        """Reset to closed state."""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_calls = 0


def retry_async(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    retry_on: Tuple[Type[Exception], ...] = (Exception,),
    on_retry: Optional[Callable] = None,
):
    """
    Async retry decorator with exponential backoff.
    
    Args:
        max_attempts: Maximum number of attempts
        base_delay: Initial delay between retries
        max_delay: Maximum delay between retries
        retry_on: Exception types to retry on
        on_retry: Callback function called before each retry
    """
    config = RetryConfig(
        max_attempts=max_attempts,
        base_delay=base_delay,
        max_delay=max_delay,
        retry_on=retry_on,
    )
    
    def decorator(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(config.max_attempts):
                try:
                    return await func(*args, **kwargs)
                except retry_on as e:
                    last_exception = e
                    
                    if attempt < config.max_attempts - 1:
                        delay = config.get_delay(attempt)
                        
                        if on_retry:
                            on_retry(attempt + 1, e, delay)
                        
                        logger.debug(
                            f"Retry {attempt + 1}/{config.max_attempts} "
                            f"for {func.__name__}: {e}. Waiting {delay:.2f}s"
                        )
                        await asyncio.sleep(delay)
            
            raise last_exception
        
        return wrapper
    return decorator


def retry_sync(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    retry_on: Tuple[Type[Exception], ...] = (Exception,),
):
    """Synchronous retry decorator."""
    config = RetryConfig(
        max_attempts=max_attempts,
        base_delay=base_delay,
        max_delay=max_delay,
        retry_on=retry_on,
    )
    
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(config.max_attempts):
                try:
                    return func(*args, **kwargs)
                except retry_on as e:
                    last_exception = e
                    
                    if attempt < config.max_attempts - 1:
                        delay = config.get_delay(attempt)
                        logger.debug(f"Retry {attempt + 1}/{config.max_attempts}: {e}")
                        time.sleep(delay)
            
            raise last_exception
        
        return wrapper
    return decorator


class RetryableClient:
    """
    Wrapper for HTTP client with built-in retry and circuit breaker.
    """
    
    def __init__(
        self,
        retry_config: Optional[RetryConfig] = None,
        circuit_config: Optional[CircuitBreakerConfig] = None,
    ):
        self.retry_config = retry_config or RetryConfig()
        self.circuit_breaker = CircuitBreaker(circuit_config)
    
    async def execute(
        self,
        func: Callable,
        *args,
        **kwargs,
    ) -> Any:
        """
        Execute function with retry and circuit breaker.
        """
        if not self.circuit_breaker.can_execute():
            raise RuntimeError("Circuit breaker is open")
        
        last_exception = None
        
        for attempt in range(self.retry_config.max_attempts):
            try:
                result = await func(*args, **kwargs)
                self.circuit_breaker.record_success()
                return result
            
            except self.retry_config.retry_on as e:
                last_exception = e
                self.circuit_breaker.record_failure()
                
                if attempt < self.retry_config.max_attempts - 1:
                    if self.circuit_breaker.can_execute():
                        delay = self.retry_config.get_delay(attempt)
                        await asyncio.sleep(delay)
                    else:
                        break
        
        raise last_exception
