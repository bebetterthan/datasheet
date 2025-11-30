"""
GitHub API Helper module.
Provides authenticated access to GitHub API with rate limit handling.
"""

import asyncio
import os
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta

import httpx

from .logger import get_logger

logger = get_logger(__name__)


class GitHubAPIError(Exception):
    """Exception for GitHub API errors."""
    pass


class GitHubRateLimitError(GitHubAPIError):
    """Exception when GitHub rate limit is exceeded."""
    def __init__(self, reset_time: datetime, message: str = "Rate limit exceeded"):
        self.reset_time = reset_time
        super().__init__(f"{message}. Resets at {reset_time}")


class GitHubHelper:
    """
    Helper class for GitHub API interactions.
    Handles authentication, rate limiting, and common operations.
    """
    
    API_BASE = "https://api.github.com"
    RAW_BASE = "https://raw.githubusercontent.com"
    
    def __init__(
        self,
        token: Optional[str] = None,
        timeout: int = 30,
    ):
        """
        Initialize GitHub helper.
        
        Args:
            token: GitHub personal access token (or from GITHUB_TOKEN env var)
            timeout: Request timeout in seconds
        """
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        
        # Rate limit tracking
        self.rate_limit_remaining = 60  # Default for unauthenticated
        self.rate_limit_reset: Optional[datetime] = None
        
        if self.token:
            logger.info("GitHub API: Using authenticated requests (5000 req/hour)")
        else:
            logger.warning("GitHub API: No token set - limited to 60 requests/hour. "
                         "Set GITHUB_TOKEN environment variable for higher limits.")
    
    @property
    def headers(self) -> Dict[str, str]:
        """Get headers for GitHub API requests."""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SecurityDatasetScraper/1.0",
        }
        if self.token:
            headers["Authorization"] = f"token {self.token}"
        return headers
    
    async def __aenter__(self):
        """Async context manager entry."""
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            headers=self.headers,
            follow_redirects=True,
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    def _update_rate_limit(self, response: httpx.Response):
        """Update rate limit info from response headers."""
        remaining = response.headers.get("X-RateLimit-Remaining")
        reset_time = response.headers.get("X-RateLimit-Reset")
        
        if remaining:
            self.rate_limit_remaining = int(remaining)
        
        if reset_time:
            self.rate_limit_reset = datetime.fromtimestamp(int(reset_time))
        
        if self.rate_limit_remaining < 10:
            logger.warning(f"GitHub API: Only {self.rate_limit_remaining} requests remaining. "
                          f"Resets at {self.rate_limit_reset}")
    
    async def _wait_for_rate_limit(self):
        """Wait if rate limit is close to being exceeded."""
        if self.rate_limit_remaining <= 1 and self.rate_limit_reset:
            wait_seconds = (self.rate_limit_reset - datetime.now()).total_seconds()
            if wait_seconds > 0:
                logger.info(f"GitHub API: Rate limit reached. Waiting {wait_seconds:.0f}s...")
                await asyncio.sleep(min(wait_seconds + 1, 3600))  # Max wait 1 hour
    
    async def get(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Make a GET request to GitHub API.
        
        Args:
            endpoint: API endpoint (e.g., "/repos/owner/repo/contents")
            params: Query parameters
            
        Returns:
            JSON response as dict
        """
        if not self._client:
            raise GitHubAPIError("Client not initialized. Use 'async with' context manager.")
        
        await self._wait_for_rate_limit()
        
        url = f"{self.API_BASE}{endpoint}" if endpoint.startswith("/") else endpoint
        
        try:
            response = await self._client.get(url, params=params)
            self._update_rate_limit(response)
            
            if response.status_code == 403:
                if "rate limit" in response.text.lower():
                    raise GitHubRateLimitError(
                        self.rate_limit_reset or datetime.now() + timedelta(hours=1),
                        "GitHub API rate limit exceeded"
                    )
                raise GitHubAPIError(f"Forbidden: {response.text}")
            
            if response.status_code == 404:
                raise GitHubAPIError(f"Not found: {url}")
            
            response.raise_for_status()
            return response.json()
            
        except httpx.HTTPStatusError as e:
            raise GitHubAPIError(f"HTTP error {e.response.status_code}: {e}")
        except httpx.RequestError as e:
            raise GitHubAPIError(f"Request error: {e}")
    
    async def get_repo_contents(
        self,
        owner: str,
        repo: str,
        path: str = "",
        ref: str = "master",
    ) -> List[Dict[str, Any]]:
        """
        Get contents of a repository directory.
        
        Args:
            owner: Repository owner
            repo: Repository name
            path: Path within repository
            ref: Branch or tag reference
            
        Returns:
            List of file/directory info
        """
        endpoint = f"/repos/{owner}/{repo}/contents/{path}"
        params = {"ref": ref}
        
        result = await self.get(endpoint, params)
        
        if isinstance(result, dict):
            return [result]
        return result
    
    async def get_file_content(
        self,
        owner: str,
        repo: str,
        path: str,
        ref: str = "master",
    ) -> str:
        """
        Get raw content of a file.
        
        Args:
            owner: Repository owner
            repo: Repository name
            path: File path within repository
            ref: Branch or tag reference
            
        Returns:
            File content as string
        """
        url = f"{self.RAW_BASE}/{owner}/{repo}/{ref}/{path}"
        
        if not self._client:
            raise GitHubAPIError("Client not initialized")
        
        response = await self._client.get(url)
        response.raise_for_status()
        return response.text
    
    async def search_code(
        self,
        query: str,
        repo: Optional[str] = None,
        language: Optional[str] = None,
        per_page: int = 30,
        page: int = 1,
    ) -> Dict[str, Any]:
        """
        Search code in GitHub repositories.
        
        Args:
            query: Search query
            repo: Limit to specific repo (owner/repo format)
            language: Filter by programming language
            per_page: Results per page
            page: Page number
            
        Returns:
            Search results
        """
        q_parts = [query]
        if repo:
            q_parts.append(f"repo:{repo}")
        if language:
            q_parts.append(f"language:{language}")
        
        params = {
            "q": " ".join(q_parts),
            "per_page": per_page,
            "page": page,
        }
        
        return await self.get("/search/code", params)
    
    async def get_rate_limit_info(self) -> Dict[str, Any]:
        """Get current rate limit status."""
        return await self.get("/rate_limit")
    
    def get_raw_url(self, owner: str, repo: str, ref: str, path: str) -> str:
        """
        Get raw content URL for a file.
        
        Args:
            owner: Repository owner
            repo: Repository name
            ref: Branch/tag reference
            path: File path
            
        Returns:
            Raw content URL
        """
        return f"{self.RAW_BASE}/{owner}/{repo}/{ref}/{path}"


# Singleton instance for easy access
_github_helper: Optional[GitHubHelper] = None


def get_github_helper(token: Optional[str] = None) -> GitHubHelper:
    """Get or create GitHub helper instance."""
    global _github_helper
    if _github_helper is None:
        _github_helper = GitHubHelper(token=token)
    return _github_helper
