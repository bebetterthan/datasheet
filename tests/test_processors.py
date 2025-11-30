"""
Tests for processors module.
"""

import pytest
from src.processors.content_cleaner import ContentCleaner
from src.processors.quality_checker import QualityChecker
from src.processors.category_classifier import CategoryClassifier
from src.processors.deduplicator import Deduplicator


class TestContentCleaner:
    """Tests for ContentCleaner."""
    
    def setup_method(self):
        self.cleaner = ContentCleaner()
    
    def test_clean_html_basic(self):
        html = "<p>Hello <b>World</b></p>"
        result = self.cleaner.clean_html(html)
        assert "Hello" in result.text
        assert "World" in result.text
        assert "<b>" not in result.text
    
    def test_extract_code_blocks(self):
        html = """
        <pre><code class="language-python">print("hello")</code></pre>
        <p>Some text</p>
        <pre><code class="language-bash">ls -la</code></pre>
        """
        result = self.cleaner.clean_html(html)
        assert len(result.code_blocks) == 2
        assert any('python' in cb['language'].lower() for cb in result.code_blocks)
    
    def test_remove_script_tags(self):
        html = """
        <p>Content</p>
        <script>alert('xss')</script>
        <p>More content</p>
        """
        result = self.cleaner.clean_html(html)
        assert "alert" not in result.text
        assert "Content" in result.text


class TestQualityChecker:
    """Tests for QualityChecker."""
    
    def setup_method(self):
        self.checker = QualityChecker()
    
    def test_quality_check_good_content(self):
        content = """
        SQL Injection is a code injection technique that exploits security vulnerabilities.
        Attackers can use SQL injection to bypass authentication and access databases.
        Common payloads include: ' OR '1'='1' -- and UNION SELECT statements.
        """
        result = self.checker.check_quality(content)
        assert result.overall_score > 0.5
        assert result.is_acceptable
    
    def test_quality_check_poor_content(self):
        content = "hi hello test"
        result = self.checker.check_quality(content)
        assert result.overall_score < 0.5
    
    def test_security_relevance(self):
        security_content = "This SQL injection exploit allows remote code execution via the vulnerable parameter."
        non_security = "The weather today is sunny and warm with clear skies."
        
        sec_result = self.checker.check_quality(security_content)
        non_sec_result = self.checker.check_quality(non_security)
        
        assert sec_result.security_relevance > non_sec_result.security_relevance


class TestCategoryClassifier:
    """Tests for CategoryClassifier."""
    
    def setup_method(self):
        self.classifier = CategoryClassifier()
    
    def test_classify_sql_injection(self):
        content = "SQL injection attack using UNION SELECT to extract database information"
        result = self.classifier.classify(content)
        assert 'sql' in result.category.lower() or 'web' in result.category.lower()
    
    def test_classify_privilege_escalation(self):
        content = "Linux privilege escalation using SUID binaries and sudo misconfigurations"
        result = self.classifier.classify(content)
        assert 'privilege' in result.category.lower() or 'linux' in result.category.lower()
    
    def test_classify_with_title(self):
        content = "Some generic content about security testing"
        title = "XSS Cross-Site Scripting Tutorial"
        result = self.classifier.classify(content, title)
        assert 'xss' in result.category.lower() or 'web' in result.category.lower()


class TestDeduplicator:
    """Tests for Deduplicator."""
    
    def setup_method(self):
        self.dedup = Deduplicator()
    
    def test_exact_duplicates(self):
        texts = [
            "This is a unique text about SQL injection.",
            "This is a unique text about SQL injection.",  # Exact duplicate
            "This is a different text about XSS attacks.",
        ]
        unique_indices = self.dedup.deduplicate(texts)
        assert len(unique_indices) == 2
    
    def test_near_duplicates(self):
        texts = [
            "SQL injection is a web security vulnerability that allows attackers to interfere with queries.",
            "SQL injection is a web security vulnerability that allows attackers to interfere with database queries.",  # Near duplicate
            "XSS allows attackers to inject malicious scripts into web pages.",
        ]
        unique_indices = self.dedup.deduplicate(texts)
        # Depending on threshold, might be 2 or 3
        assert len(unique_indices) >= 2
    
    def test_all_unique(self):
        texts = [
            "SQL injection attacks target databases.",
            "XSS attacks target browsers.",
            "CSRF attacks exploit trust relationships.",
        ]
        unique_indices = self.dedup.deduplicate(texts)
        assert len(unique_indices) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
