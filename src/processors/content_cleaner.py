"""
Content cleaning module for processing scraped HTML and text content.
Handles HTML cleaning, code block extraction, and text normalization.
"""

import re
import html
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from bs4 import BeautifulSoup, NavigableString, Tag
from selectolax.parser import HTMLParser


@dataclass
class ExtractedContent:
    """Container for extracted and cleaned content."""
    title: str
    text: str
    code_blocks: List[Dict[str, str]]
    headers: List[Dict[str, str]]
    links: List[Dict[str, str]]
    lists: List[List[str]]
    tables: List[Dict]
    metadata: Dict[str, str]


class ContentCleaner:
    """
    Cleans and extracts content from HTML and raw text.
    Preserves code blocks and important formatting.
    """
    
    # Tags to completely remove
    REMOVE_TAGS = [
        'script', 'style', 'nav', 'footer', 'header', 'aside',
        'advertisement', 'ads', 'banner', 'cookie', 'popup',
        'modal', 'sidebar', 'menu', 'breadcrumb', 'pagination'
    ]
    
    # Classes/IDs that indicate non-content elements
    REMOVE_PATTERNS = [
        r'nav', r'menu', r'footer', r'header', r'sidebar',
        r'advertisement', r'ads', r'banner', r'cookie',
        r'popup', r'modal', r'social', r'share', r'comment',
        r'related', r'recommend', r'subscribe', r'newsletter'
    ]
    
    # Code block indicators
    CODE_INDICATORS = ['pre', 'code', 'highlight', 'syntax', 'codehilite']
    
    def __init__(
        self,
        preserve_code_blocks: bool = True,
        preserve_links: bool = True,
        normalize_whitespace: bool = True,
        min_text_length: int = 10,
        use_selectolax: bool = False,
    ):
        """
        Initialize content cleaner.
        
        Args:
            preserve_code_blocks: Whether to preserve code formatting
            preserve_links: Whether to preserve hyperlinks
            normalize_whitespace: Whether to normalize whitespace
            min_text_length: Minimum text length to consider valid
            use_selectolax: Use selectolax for faster parsing
        """
        self.preserve_code_blocks = preserve_code_blocks
        self.preserve_links = preserve_links
        self.normalize_whitespace = normalize_whitespace
        self.min_text_length = min_text_length
        self.use_selectolax = use_selectolax
    
    def clean_html(self, html_content: str) -> ExtractedContent:
        """
        Clean HTML content and extract structured data.
        
        Args:
            html_content: Raw HTML string
            
        Returns:
            ExtractedContent with cleaned and structured data
        """
        if self.use_selectolax:
            return self._clean_with_selectolax(html_content)
        return self._clean_with_beautifulsoup(html_content)
    
    def _clean_with_beautifulsoup(self, html_content: str) -> ExtractedContent:
        """Clean HTML using BeautifulSoup."""
        soup = BeautifulSoup(html_content, 'lxml')
        
        # Remove unwanted tags
        for tag_name in self.REMOVE_TAGS:
            for tag in soup.find_all(tag_name):
                tag.decompose()
        
        # Remove elements with unwanted classes/IDs
        for pattern in self.REMOVE_PATTERNS:
            regex = re.compile(pattern, re.I)
            for tag in soup.find_all(class_=regex):
                tag.decompose()
            for tag in soup.find_all(id=regex):
                tag.decompose()
        
        # Extract title
        title = ""
        title_tag = soup.find('title')
        if title_tag:
            title = title_tag.get_text(strip=True)
        else:
            h1 = soup.find('h1')
            if h1:
                title = h1.get_text(strip=True)
        
        # Extract code blocks before cleaning
        code_blocks = self._extract_code_blocks_bs(soup)
        
        # Extract headers
        headers = self._extract_headers_bs(soup)
        
        # Extract links
        links = self._extract_links_bs(soup)
        
        # Extract lists
        lists = self._extract_lists_bs(soup)
        
        # Extract tables
        tables = self._extract_tables_bs(soup)
        
        # Get main text content
        main_content = soup.find('main') or soup.find('article') or soup.find('body') or soup
        text = self._extract_text_bs(main_content, code_blocks)
        
        # Extract metadata
        metadata = self._extract_metadata_bs(soup)
        
        return ExtractedContent(
            title=title,
            text=text,
            code_blocks=code_blocks,
            headers=headers,
            links=links,
            lists=lists,
            tables=tables,
            metadata=metadata,
        )
    
    def _clean_with_selectolax(self, html_content: str) -> ExtractedContent:
        """Clean HTML using selectolax for speed."""
        parser = HTMLParser(html_content)
        
        # Remove unwanted tags
        for tag_name in self.REMOVE_TAGS:
            for tag in parser.css(tag_name):
                tag.decompose()
        
        # Extract title
        title = ""
        title_node = parser.css_first('title')
        if title_node:
            title = title_node.text(strip=True)
        else:
            h1 = parser.css_first('h1')
            if h1:
                title = h1.text(strip=True)
        
        # Extract code blocks
        code_blocks = []
        for pre in parser.css('pre'):
            code = pre.css_first('code')
            lang = ""
            if code:
                classes = code.attributes.get('class', '')
                lang_match = re.search(r'language-(\w+)', classes)
                if lang_match:
                    lang = lang_match.group(1)
            code_blocks.append({
                'code': pre.text(strip=True),
                'language': lang
            })
        
        # Get main text
        main = parser.css_first('main') or parser.css_first('article') or parser.css_first('body')
        text = main.text(separator='\n', strip=True) if main else ""
        
        return ExtractedContent(
            title=title,
            text=text,
            code_blocks=code_blocks,
            headers=[],
            links=[],
            lists=[],
            tables=[],
            metadata={},
        )
    
    def _extract_code_blocks_bs(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """Extract code blocks from BeautifulSoup parsed HTML."""
        code_blocks = []
        
        # Find all pre > code blocks
        for pre in soup.find_all('pre'):
            code_tag = pre.find('code')
            code_text = ""
            language = ""
            
            if code_tag:
                code_text = code_tag.get_text()
                # Try to detect language from class
                classes = code_tag.get('class', [])
                for cls in classes:
                    if cls.startswith('language-'):
                        language = cls.replace('language-', '')
                        break
                    elif cls.startswith('lang-'):
                        language = cls.replace('lang-', '')
                        break
            else:
                code_text = pre.get_text()
            
            if code_text.strip():
                code_blocks.append({
                    'code': code_text.strip(),
                    'language': language,
                })
        
        # Find inline code blocks (standalone <code> not in <pre>)
        for code in soup.find_all('code'):
            if code.parent.name != 'pre':
                code_text = code.get_text().strip()
                if len(code_text) > 50:  # Only include substantial code
                    code_blocks.append({
                        'code': code_text,
                        'language': '',
                        'inline': True,
                    })
        
        return code_blocks
    
    def _extract_headers_bs(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """Extract headers from BeautifulSoup parsed HTML."""
        headers = []
        for level in range(1, 7):
            for header in soup.find_all(f'h{level}'):
                text = header.get_text(strip=True)
                if text:
                    header_id = header.get('id', '')
                    headers.append({
                        'level': level,
                        'text': text,
                        'id': header_id,
                    })
        return headers
    
    def _extract_links_bs(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """Extract links from BeautifulSoup parsed HTML."""
        links = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            text = a.get_text(strip=True)
            if href and not href.startswith('#'):
                links.append({
                    'url': href,
                    'text': text,
                })
        return links
    
    def _extract_lists_bs(self, soup: BeautifulSoup) -> List[List[str]]:
        """Extract lists from BeautifulSoup parsed HTML."""
        lists = []
        for ul in soup.find_all(['ul', 'ol']):
            items = []
            for li in ul.find_all('li', recursive=False):
                text = li.get_text(strip=True)
                if text:
                    items.append(text)
            if items:
                lists.append(items)
        return lists
    
    def _extract_tables_bs(self, soup: BeautifulSoup) -> List[Dict]:
        """Extract tables from BeautifulSoup parsed HTML."""
        tables = []
        for table in soup.find_all('table'):
            table_data = {'headers': [], 'rows': []}
            
            # Extract headers
            thead = table.find('thead')
            if thead:
                for th in thead.find_all('th'):
                    table_data['headers'].append(th.get_text(strip=True))
            
            # Extract rows
            tbody = table.find('tbody') or table
            for tr in tbody.find_all('tr'):
                row = []
                for td in tr.find_all(['td', 'th']):
                    row.append(td.get_text(strip=True))
                if row:
                    table_data['rows'].append(row)
            
            if table_data['rows']:
                tables.append(table_data)
        
        return tables
    
    def _extract_text_bs(self, element: Tag, code_blocks: List[Dict]) -> str:
        """Extract clean text from element, preserving code block markers."""
        # Create placeholder for code blocks
        code_placeholder = "___CODE_BLOCK_{}___"
        
        # Replace code blocks with placeholders
        text = str(element)
        for i, block in enumerate(code_blocks):
            # Simple replacement - in production, need more sophisticated matching
            pass
        
        # Parse again and get text
        soup = BeautifulSoup(text, 'lxml')
        
        # Get text with newlines preserved
        lines = []
        for elem in soup.descendants:
            if isinstance(elem, NavigableString):
                text = str(elem).strip()
                if text:
                    lines.append(text)
            elif elem.name in ['br', 'p', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li']:
                lines.append('\n')
        
        result = ' '.join(lines)
        
        if self.normalize_whitespace:
            result = self._normalize_whitespace(result)
        
        return result
    
    def _extract_metadata_bs(self, soup: BeautifulSoup) -> Dict[str, str]:
        """Extract metadata from HTML head."""
        metadata = {}
        
        # Meta description
        desc = soup.find('meta', attrs={'name': 'description'})
        if desc and desc.get('content'):
            metadata['description'] = desc['content']
        
        # Meta keywords
        keywords = soup.find('meta', attrs={'name': 'keywords'})
        if keywords and keywords.get('content'):
            metadata['keywords'] = keywords['content']
        
        # Open Graph
        for og in soup.find_all('meta', attrs={'property': re.compile(r'^og:')}):
            prop = og.get('property', '').replace('og:', '')
            content = og.get('content', '')
            if prop and content:
                metadata[f'og_{prop}'] = content
        
        return metadata
    
    def _normalize_whitespace(self, text: str) -> str:
        """Normalize whitespace in text."""
        # Replace multiple spaces with single space
        text = re.sub(r' +', ' ', text)
        # Replace multiple newlines with double newline
        text = re.sub(r'\n\s*\n', '\n\n', text)
        # Strip each line
        lines = [line.strip() for line in text.split('\n')]
        text = '\n'.join(lines)
        return text.strip()
    
    def clean_text(self, text: str) -> str:
        """
        Clean raw text content.
        
        Args:
            text: Raw text string
            
        Returns:
            Cleaned text
        """
        # Decode HTML entities
        text = html.unescape(text)
        
        # Remove control characters except newlines and tabs
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', text)
        
        # Normalize unicode
        text = text.encode('utf-8', errors='ignore').decode('utf-8')
        
        if self.normalize_whitespace:
            text = self._normalize_whitespace(text)
        
        return text
    
    def extract_code_from_text(self, text: str) -> Tuple[str, List[Dict[str, str]]]:
        """
        Extract code blocks from markdown-style text.
        
        Args:
            text: Text potentially containing markdown code blocks
            
        Returns:
            Tuple of (text with placeholders, list of code blocks)
        """
        code_blocks = []
        
        # Find fenced code blocks (```)
        pattern = r'```(\w*)\n(.*?)```'
        
        def replace_code(match):
            lang = match.group(1) or ''
            code = match.group(2)
            idx = len(code_blocks)
            code_blocks.append({
                'code': code.strip(),
                'language': lang,
            })
            return f'[CODE_BLOCK_{idx}]'
        
        text = re.sub(pattern, replace_code, text, flags=re.DOTALL)
        
        # Find indented code blocks (4 spaces or tab)
        lines = text.split('\n')
        in_code_block = False
        code_lines = []
        result_lines = []
        
        for line in lines:
            if line.startswith('    ') or line.startswith('\t'):
                if not in_code_block:
                    in_code_block = True
                    code_lines = []
                code_lines.append(line[4:] if line.startswith('    ') else line[1:])
            else:
                if in_code_block:
                    idx = len(code_blocks)
                    code_blocks.append({
                        'code': '\n'.join(code_lines),
                        'language': '',
                    })
                    result_lines.append(f'[CODE_BLOCK_{idx}]')
                    in_code_block = False
                result_lines.append(line)
        
        # Handle code block at end
        if in_code_block and code_lines:
            idx = len(code_blocks)
            code_blocks.append({
                'code': '\n'.join(code_lines),
                'language': '',
            })
            result_lines.append(f'[CODE_BLOCK_{idx}]')
        
        return '\n'.join(result_lines), code_blocks
    
    def reconstruct_with_code(self, text: str, code_blocks: List[Dict[str, str]]) -> str:
        """
        Reconstruct text with code blocks.
        
        Args:
            text: Text with code block placeholders
            code_blocks: List of code blocks
            
        Returns:
            Text with code blocks reinserted
        """
        for i, block in enumerate(code_blocks):
            placeholder = f'[CODE_BLOCK_{i}]'
            lang = block.get('language', '')
            code = block.get('code', '')
            formatted = f'```{lang}\n{code}\n```'
            text = text.replace(placeholder, formatted)
        return text
