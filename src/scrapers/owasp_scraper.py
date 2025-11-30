"""
OWASP scraper - scrapes security knowledge from OWASP resources.
Target: OWASP CheatSheet Series, Web Security Testing Guide, Top 10
"""

import os
import re
from typing import Any, Dict, List, Optional
import json

from .base_scraper import BaseScraper, ScrapedItem
from ..utils.logger import get_logger
from ..utils.github_helper import GitHubHelper, GitHubAPIError, GitHubRateLimitError

logger = get_logger(__name__)


class OWASPScraper(BaseScraper):
    """
    Scraper for OWASP resources - CheatSheet Series, Testing Guide, Top 10.
    """
    
    SOURCE_NAME = "owasp"
    
    # OWASP GitHub repos
    CHEATSHEET_API = "https://api.github.com/repos/OWASP/CheatSheetSeries/contents/cheatsheets"
    CHEATSHEET_RAW = "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets"
    
    WSTG_API = "https://api.github.com/repos/OWASP/wstg/contents/document"
    WSTG_RAW = "https://raw.githubusercontent.com/OWASP/wstg/master/document"
    
    TOP10_API = "https://api.github.com/repos/OWASP/Top10/contents/2021/docs"
    TOP10_RAW = "https://raw.githubusercontent.com/OWASP/Top10/master/2021/docs"
    
    # Category mappings
    CATEGORY_MAP = {
        'injection': 'web_security/injection',
        'broken access': 'web_security/access_control',
        'cryptographic': 'cryptography',
        'security misconfiguration': 'web_security/misconfiguration',
        'xss': 'web_security/xss',
        'insecure deserialization': 'web_security/deserialization',
        'using components': 'security/supply_chain',
        'insufficient logging': 'defense/logging',
        'ssrf': 'web_security/ssrf',
        'authentication': 'credential_access/authentication',
        'session management': 'credential_access/session',
        'input validation': 'web_security/input_validation',
        'output encoding': 'web_security/encoding',
        'sql injection': 'web_security/sql_injection',
        'ldap injection': 'web_security/ldap_injection',
        'command injection': 'exploitation/command_injection',
        'file upload': 'web_security/file_upload',
        'xxe': 'web_security/xxe',
        'csrf': 'web_security/csrf',
        'clickjacking': 'web_security/clickjacking',
        'cors': 'web_security/cors',
        'content security policy': 'defense/csp',
        'http security headers': 'defense/security_headers',
        'tls': 'cryptography/tls',
        'password storage': 'cryptography/password_hashing',
        'secrets management': 'credential_access/secrets',
        'logging': 'defense/logging',
        'error handling': 'defense/error_handling',
        'api security': 'web_security/api',
        'graphql': 'web_security/graphql',
        'jwt': 'credential_access/jwt',
        'oauth': 'web_security/oauth',
        'saml': 'credential_access/saml',
    }
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._discovered_urls: List[Dict] = []
        # Initialize GitHub helper with token from env
        self._github = GitHubHelper(token=os.environ.get("GITHUB_TOKEN", ""))
    
    async def __aenter__(self):
        """Async context manager entry."""
        await super().__aenter__()
        await self._github.__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self._github.__aexit__(exc_type, exc_val, exc_tb)
        await super().__aexit__(exc_type, exc_val, exc_tb)
    
    async def discover_urls(self) -> List[str]:
        """Discover OWASP resources."""
        if self._discovered_urls:
            return [d['path'] for d in self._discovered_urls]
        
        logger.info("Discovering OWASP resources...")
        
        # Discover from each source
        cheatsheets = await self._discover_cheatsheets()
        logger.info(f"Found {len(cheatsheets)} CheatSheet Series documents")
        
        wstg_docs = await self._discover_wstg()
        logger.info(f"Found {len(wstg_docs)} Web Security Testing Guide documents")
        
        top10_docs = await self._discover_top10()
        logger.info(f"Found {len(top10_docs)} Top 10 documents")
        
        self._discovered_urls = cheatsheets + wstg_docs + top10_docs
        logger.info(f"Total: {len(self._discovered_urls)} OWASP documents")
        
        return [d['path'] for d in self._discovered_urls]
    
    async def _discover_cheatsheets(self) -> List[Dict]:
        """Discover CheatSheet Series documents."""
        docs = []
        
        try:
            # Use GitHub helper instead of direct API call
            items = await self._github.get_repo_contents(
                owner="OWASP",
                repo="CheatSheetSeries",
                path="cheatsheets",
                ref="master"
            )
            
            for item in items:
                if item.get('type') == 'file' and item.get('name', '').endswith('.md'):
                    docs.append({
                        'path': item['name'],
                        'source': 'cheatsheet',
                        'raw_url': f"{self.CHEATSHEET_RAW}/{item['name']}",
                    })
        
        except GitHubRateLimitError as e:
            logger.error(f"GitHub rate limit exceeded: {e}")
            logger.info("Set GITHUB_TOKEN environment variable for higher rate limits")
        except GitHubAPIError as e:
            logger.error(f"GitHub API error discovering cheatsheets: {e}")
        except Exception as e:
            logger.error(f"Error discovering cheatsheets: {e}")
        
        return docs
    
    async def _discover_wstg(self) -> List[Dict]:
        """Discover Web Security Testing Guide documents."""
        docs = []
        
        # WSTG sections
        sections = ['1-Frontispiece', '2-Introduction', '4-Web_Application_Security_Testing']
        
        for section in sections:
            try:
                items = await self._github.get_repo_contents(
                    owner="OWASP",
                    repo="wstg",
                    path=f"document/{section}",
                    ref="master"
                )
                
                for item in items:
                    if item.get('type') == 'file' and item.get('name', '').endswith('.md'):
                        docs.append({
                            'path': f"wstg/{section}/{item['name']}",
                            'source': 'wstg',
                            'raw_url': f"{self.WSTG_RAW}/{section}/{item['name']}",
                        })
                    elif item.get('type') == 'dir':
                        # Recurse into testing categories
                        sub_docs = await self._discover_wstg_subdir(f"{section}/{item['name']}")
                        docs.extend(sub_docs)
            
            except GitHubRateLimitError as e:
                logger.error(f"GitHub rate limit during WSTG discovery: {e}")
                break
            except GitHubAPIError as e:
                logger.debug(f"GitHub API error for WSTG section {section}: {e}")
            except Exception as e:
                logger.debug(f"Error discovering WSTG section {section}: {e}")
        
        return docs
    
    async def _discover_wstg_subdir(self, path: str) -> List[Dict]:
        """Discover WSTG subdirectory contents."""
        docs = []
        
        try:
            items = await self._github.get_repo_contents(
                owner="OWASP",
                repo="wstg",
                path=f"document/{path}",
                ref="master"
            )
            
            for item in items:
                if item.get('type') == 'file' and item.get('name', '').endswith('.md'):
                    docs.append({
                        'path': f"wstg/{path}/{item['name']}",
                        'source': 'wstg',
                        'raw_url': f"{self.WSTG_RAW}/{path}/{item['name']}",
                    })
        
        except GitHubAPIError as e:
            logger.debug(f"GitHub API error in WSTG subdir {path}: {e}")
        except Exception as e:
            logger.debug(f"Error in WSTG subdir {path}: {e}")
        
        return docs
    
    async def _discover_top10(self) -> List[Dict]:
        """Discover OWASP Top 10 documents."""
        docs = []
        
        try:
            items = await self._github.get_repo_contents(
                owner="OWASP",
                repo="Top10",
                path="2021/docs",
                ref="master"
            )
            
            for item in items:
                if item.get('type') == 'file' and item.get('name', '').endswith('.md'):
                    docs.append({
                        'path': f"top10/{item['name']}",
                        'source': 'top10',
                        'raw_url': f"{self.TOP10_RAW}/{item['name']}",
                    })
        
        except GitHubRateLimitError as e:
            logger.error(f"GitHub rate limit during Top 10 discovery: {e}")
        except GitHubAPIError as e:
            logger.error(f"GitHub API error discovering Top 10: {e}")
        except Exception as e:
            logger.error(f"Error discovering Top 10: {e}")
        
        return docs
    
    async def scrape_page(self, path: str) -> Optional[ScrapedItem]:
        """Scrape a specific OWASP document."""
        # Find the document info
        doc_info = None
        for doc in self._discovered_urls:
            if doc['path'] == path:
                doc_info = doc
                break
        
        if not doc_info:
            return None
        
        try:
            content = await self.fetch_page(doc_info['raw_url'])
            if not content:
                return None
            
            return self._parse_owasp_doc(path, content, doc_info)
        
        except Exception as e:
            logger.error(f"Error scraping {path}: {e}")
            return None
    
    def _parse_owasp_doc(self, path: str, content: str, doc_info: Dict) -> Optional[ScrapedItem]:
        """Parse OWASP markdown document."""
        source_type = doc_info['source']
        
        # Extract title
        title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
        title = title_match.group(1) if title_match else path.replace('.md', '')
        
        # Clean up title
        title = re.sub(r'\[.*?\]\(.*?\)', '', title).strip()
        
        # Extract headers
        headers = re.findall(r'^#+\s+(.+)$', content, re.MULTILINE)
        
        # Extract code blocks
        code_blocks = []
        code_pattern = r'```(\w*)\n(.*?)```'
        for match in re.finditer(code_pattern, content, re.DOTALL):
            lang = match.group(1) or 'text'
            code = match.group(2).strip()
            if code:
                code_blocks.append({
                    'language': lang,
                    'code': code,
                })
        
        # Determine category
        category = self._determine_category(path, title, headers, content)
        
        # Determine difficulty
        difficulty = self._determine_difficulty(source_type, content)
        
        # Extract tags
        tags = self._extract_tags(path, title, source_type)
        
        # Build source URL
        if source_type == 'cheatsheet':
            url = f"https://cheatsheetseries.owasp.org/cheatsheets/{path}"
        elif source_type == 'wstg':
            url = doc_info['raw_url'].replace('raw.githubusercontent.com', 'github.com').replace('/master/', '/blob/master/')
        else:
            url = doc_info['raw_url'].replace('raw.githubusercontent.com', 'github.com').replace('/master/', '/blob/master/')
        
        return ScrapedItem(
            url=url,
            title=f"OWASP {source_type.upper()}: {title}",
            content=content,
            code_blocks=code_blocks,
            headers=headers,
            metadata={
                'category': category,
                'difficulty': difficulty,
                'source_type': f'owasp_{source_type}',
                'owasp_source': source_type,
                'topic': title,
                'tags': tags,
            }
        )
    
    def _determine_category(self, path: str, title: str, headers: List[str], content: str) -> str:
        """Determine category from OWASP document."""
        text = ' '.join([path.lower(), title.lower()] + [h.lower() for h in headers])
        
        for key, category in self.CATEGORY_MAP.items():
            if key in text:
                return category
        
        # WSTG specific categories
        if 'WSTG-INFO' in content or 'information gathering' in text:
            return 'recon/information_gathering'
        if 'WSTG-CONF' in content or 'configuration' in text:
            return 'web_security/misconfiguration'
        if 'WSTG-IDNT' in content or 'identity' in text:
            return 'credential_access/identity'
        if 'WSTG-ATHN' in content or 'authentication' in text:
            return 'credential_access/authentication'
        if 'WSTG-ATHZ' in content or 'authorization' in text:
            return 'web_security/access_control'
        if 'WSTG-SESS' in content or 'session' in text:
            return 'credential_access/session'
        if 'WSTG-INPV' in content or 'input validation' in text:
            return 'web_security/input_validation'
        if 'WSTG-ERRH' in content or 'error handling' in text:
            return 'defense/error_handling'
        if 'WSTG-CRYP' in content or 'cryptography' in text:
            return 'cryptography'
        if 'WSTG-BUSL' in content or 'business logic' in text:
            return 'web_security/business_logic'
        if 'WSTG-CLNT' in content or 'client-side' in text:
            return 'web_security/client_side'
        if 'WSTG-APIT' in content or 'api' in text:
            return 'web_security/api'
        
        return 'security/web_security'
    
    def _determine_difficulty(self, source_type: str, content: str) -> str:
        """Determine difficulty based on source and content."""
        content_lower = content.lower()
        
        # CheatSheets are generally beginner-friendly
        if source_type == 'cheatsheet':
            return 'beginner'
        
        # Top 10 is introductory
        if source_type == 'top10':
            return 'beginner'
        
        # WSTG varies by complexity indicators
        advanced_indicators = ['advanced', 'complex', 'sophisticated', 
                             'race condition', 'timing attack', 'blind']
        if any(ind in content_lower for ind in advanced_indicators):
            return 'advanced'
        
        return 'intermediate'
    
    def _extract_tags(self, path: str, title: str, source_type: str) -> List[str]:
        """Extract tags from document."""
        tags = {'owasp', source_type}
        
        # From title
        title_words = re.findall(r'\b\w+\b', title.lower())
        security_terms = {'xss', 'sqli', 'csrf', 'ssrf', 'xxe', 'injection',
                         'authentication', 'authorization', 'session', 'crypto',
                         'api', 'jwt', 'oauth', 'saml', 'tls', 'ssl'}
        
        for word in title_words:
            if word in security_terms:
                tags.add(word)
        
        # From path
        if 'cheatsheet' in path.lower():
            # Extract topic from filename
            topic = path.replace('_Cheat_Sheet.md', '').replace('_', ' ').lower()
            tags.add(topic.replace(' ', '_'))
        
        return list(tags)
    
    def generate_qa_from_item(self, item: ScrapedItem) -> List[Dict[str, Any]]:
        """Generate Q&A pairs from OWASP document."""
        qa_pairs = []
        
        topic = item.metadata.get('topic', '')
        source_type = item.metadata.get('owasp_source', '')
        category = item.metadata.get('category', '')
        
        # Main explanation Q&A
        if source_type == 'cheatsheet':
            qa_pairs.append({
                'instruction': f"Provide a security cheat sheet for {topic}",
                'input': '',
                'output': item.content[:4000],
                'category': category,
                'source': item.url,
                'difficulty': 'beginner',
                'tags': item.metadata.get('tags', []),
            })
        elif source_type == 'wstg':
            qa_pairs.append({
                'instruction': f"How do I test for {topic} according to OWASP Web Security Testing Guide?",
                'input': '',
                'output': item.content[:4000],
                'category': category,
                'source': item.url,
                'difficulty': 'intermediate',
                'tags': item.metadata.get('tags', []),
            })
        elif source_type == 'top10':
            qa_pairs.append({
                'instruction': f"Explain {topic} from OWASP Top 10",
                'input': '',
                'output': item.content[:4000],
                'category': category,
                'source': item.url,
                'difficulty': 'beginner',
                'tags': item.metadata.get('tags', []) + ['owasp_top_10'],
            })
        
        # Code example Q&A
        for code_block in item.code_blocks[:2]:
            lang = code_block['language']
            code = code_block['code']
            
            if len(code) > 30:
                qa_pairs.append({
                    'instruction': f"Show me an example of {topic} in {lang}",
                    'input': '',
                    'output': f"Here's an OWASP-recommended example:\n\n```{lang}\n{code}\n```",
                    'category': category,
                    'source': item.url,
                    'difficulty': item.metadata.get('difficulty', 'intermediate'),
                    'tags': item.metadata.get('tags', []) + [lang],
                })
        
        return qa_pairs
