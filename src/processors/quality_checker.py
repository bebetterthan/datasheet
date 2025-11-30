"""
Quality checker module for validating dataset samples.
Ensures data meets quality standards before final output.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from enum import Enum


class QualityIssue(str, Enum):
    """Types of quality issues."""
    TOO_SHORT = "too_short"
    TOO_LONG = "too_long"
    EMPTY_FIELD = "empty_field"
    INCOMPLETE_SENTENCE = "incomplete_sentence"
    MALFORMED_CODE = "malformed_code"
    LOW_INFORMATION = "low_information"
    ENCODING_ERROR = "encoding_error"
    MISSING_REQUIRED = "missing_required"
    INVALID_FORMAT = "invalid_format"
    GENERIC_CONTENT = "generic_content"


@dataclass
class QualityReport:
    """Quality check report for a sample."""
    sample_id: int
    is_valid: bool
    issues: List[QualityIssue] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    scores: Dict[str, float] = field(default_factory=dict)
    
    def add_issue(self, issue: QualityIssue, message: str = ""):
        self.issues.append(issue)
        if message:
            self.warnings.append(f"{issue.value}: {message}")
        self.is_valid = False


@dataclass
class QualityStats:
    """Statistics from quality checking."""
    total_checked: int = 0
    passed: int = 0
    failed: int = 0
    issues_breakdown: Dict[str, int] = field(default_factory=dict)
    
    @property
    def pass_rate(self) -> float:
        return self.passed / self.total_checked if self.total_checked > 0 else 0.0


class QualityChecker:
    """
    Validates quality of dataset samples.
    Checks for completeness, formatting, and content quality.
    """
    
    # Common filler/generic phrases to detect
    GENERIC_PHRASES = [
        "click here",
        "read more",
        "learn more",
        "see also",
        "related articles",
        "subscribe",
        "share this",
        "follow us",
        "copyright",
        "all rights reserved",
        "cookie policy",
        "privacy policy",
        "terms of service",
    ]
    
    # Required technical terms for security content
    SECURITY_INDICATORS = [
        "vulnerability", "exploit", "payload", "injection",
        "authentication", "authorization", "encryption",
        "hash", "password", "token", "session",
        "privilege", "escalation", "bypass", "attack",
        "command", "shell", "reverse", "bind",
        "scan", "enumerate", "recon", "footprint",
        "port", "service", "protocol", "network",
        "web", "http", "api", "sql", "xss", "xxe",
        "cve", "cvss", "poc", "rce", "lfi", "rfi",
    ]
    
    def __init__(
        self,
        min_instruction_length: int = 10,
        max_instruction_length: int = 500,
        min_output_length: int = 100,
        max_output_length: int = 4000,
        required_fields: Optional[List[str]] = None,
        check_security_relevance: bool = True,
        min_security_score: float = 0.1,
    ):
        """
        Initialize quality checker.
        
        Args:
            min_instruction_length: Minimum instruction length
            max_instruction_length: Maximum instruction length
            min_output_length: Minimum output length
            max_output_length: Maximum output length
            required_fields: Required fields in sample
            check_security_relevance: Check if content is security-related
            min_security_score: Minimum security relevance score
        """
        self.min_instruction_length = min_instruction_length
        self.max_instruction_length = max_instruction_length
        self.min_output_length = min_output_length
        self.max_output_length = max_output_length
        self.required_fields = required_fields or ['instruction', 'output']
        self.check_security_relevance = check_security_relevance
        self.min_security_score = min_security_score
        
        self._stats = QualityStats()
    
    def check_sample(
        self,
        sample: Dict[str, Any],
        sample_id: int = 0,
    ) -> QualityReport:
        """
        Check quality of a single sample.
        
        Args:
            sample: Sample to check
            sample_id: Identifier for the sample
            
        Returns:
            QualityReport with issues and scores
        """
        report = QualityReport(sample_id=sample_id, is_valid=True)
        
        # Check required fields
        self._check_required_fields(sample, report)
        
        # Check instruction quality
        instruction = sample.get('instruction', '')
        self._check_instruction(instruction, report)
        
        # Check output quality
        output = sample.get('output', '')
        self._check_output(output, report)
        
        # Check for encoding issues
        self._check_encoding(sample, report)
        
        # Check for generic content
        self._check_generic_content(sample, report)
        
        # Check security relevance
        if self.check_security_relevance:
            security_score = self._calculate_security_score(sample)
            report.scores['security_relevance'] = security_score
            if security_score < self.min_security_score:
                report.add_issue(
                    QualityIssue.LOW_INFORMATION,
                    f"Low security relevance score: {security_score:.2f}"
                )
        
        # Check code block formatting
        self._check_code_blocks(output, report)
        
        return report
    
    def _check_required_fields(
        self,
        sample: Dict[str, Any],
        report: QualityReport,
    ) -> None:
        """Check if all required fields are present and non-empty."""
        for field in self.required_fields:
            if field not in sample:
                report.add_issue(
                    QualityIssue.MISSING_REQUIRED,
                    f"Missing field: {field}"
                )
            elif not sample[field] or (isinstance(sample[field], str) and not sample[field].strip()):
                report.add_issue(
                    QualityIssue.EMPTY_FIELD,
                    f"Empty field: {field}"
                )
    
    def _check_instruction(
        self,
        instruction: str,
        report: QualityReport,
    ) -> None:
        """Check instruction quality."""
        if not instruction:
            return
        
        length = len(instruction)
        
        if length < self.min_instruction_length:
            report.add_issue(
                QualityIssue.TOO_SHORT,
                f"Instruction too short: {length} chars"
            )
        
        if length > self.max_instruction_length:
            report.add_issue(
                QualityIssue.TOO_LONG,
                f"Instruction too long: {length} chars"
            )
        
        # Check if it looks like a valid question/instruction
        instruction_indicators = ['?', 'how', 'what', 'explain', 'describe', 'show', 'demonstrate', 'create', 'write', 'implement', 'find', 'list']
        has_indicator = any(ind in instruction.lower() for ind in instruction_indicators)
        
        if not has_indicator and not instruction.endswith('.'):
            report.warnings.append("Instruction may not be properly formed")
    
    def _check_output(
        self,
        output: str,
        report: QualityReport,
    ) -> None:
        """Check output quality."""
        if not output:
            return
        
        length = len(output)
        
        if length < self.min_output_length:
            report.add_issue(
                QualityIssue.TOO_SHORT,
                f"Output too short: {length} chars"
            )
        
        if length > self.max_output_length:
            report.add_issue(
                QualityIssue.TOO_LONG,
                f"Output too long: {length} chars"
            )
        
        # Check for incomplete sentences
        sentences = re.split(r'[.!?]\s+', output)
        if sentences:
            last_sentence = sentences[-1].strip()
            # If last part doesn't end with punctuation and isn't a code block
            if last_sentence and not re.search(r'[.!?`}\])]$', last_sentence):
                if not last_sentence.startswith('```') and '```' not in output[-100:]:
                    report.warnings.append("Output may have incomplete sentence")
    
    def _check_encoding(
        self,
        sample: Dict[str, Any],
        report: QualityReport,
    ) -> None:
        """Check for encoding issues."""
        for field, value in sample.items():
            if isinstance(value, str):
                # Check for common encoding issues
                if '\ufffd' in value:  # Replacement character
                    report.add_issue(
                        QualityIssue.ENCODING_ERROR,
                        f"Encoding issues in {field}"
                    )
                
                # Check for null bytes
                if '\x00' in value:
                    report.add_issue(
                        QualityIssue.ENCODING_ERROR,
                        f"Null bytes in {field}"
                    )
    
    def _check_generic_content(
        self,
        sample: Dict[str, Any],
        report: QualityReport,
    ) -> None:
        """Check for generic/filler content."""
        output = sample.get('output', '').lower()
        
        generic_count = sum(1 for phrase in self.GENERIC_PHRASES if phrase in output)
        
        if generic_count >= 3:
            report.add_issue(
                QualityIssue.GENERIC_CONTENT,
                f"Too many generic phrases ({generic_count})"
            )
    
    def _check_code_blocks(
        self,
        output: str,
        report: QualityReport,
    ) -> None:
        """Check code block formatting."""
        if not output:
            return
        
        # Count opening and closing code fences
        open_fences = output.count('```')
        
        # Should be even (pairs of opening and closing)
        if open_fences % 2 != 0:
            report.add_issue(
                QualityIssue.MALFORMED_CODE,
                "Unmatched code block fences"
            )
        
        # Check for empty code blocks
        empty_blocks = re.findall(r'```\w*\s*```', output)
        if empty_blocks:
            report.warnings.append(f"Found {len(empty_blocks)} empty code blocks")
    
    def _calculate_security_score(
        self,
        sample: Dict[str, Any],
    ) -> float:
        """Calculate security relevance score."""
        text = ' '.join(
            str(v).lower() for v in sample.values() if isinstance(v, str)
        )
        
        # Count security-related terms
        matches = sum(1 for term in self.SECURITY_INDICATORS if term in text)
        
        # Normalize by text length (per 1000 chars)
        text_length = len(text)
        if text_length == 0:
            return 0.0
        
        normalized_score = (matches / len(self.SECURITY_INDICATORS))
        
        return min(1.0, normalized_score)
    
    def check_batch(
        self,
        samples: List[Dict[str, Any]],
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], QualityStats]:
        """
        Check quality of a batch of samples.
        
        Args:
            samples: List of samples
            progress_callback: Progress callback function
            
        Returns:
            Tuple of (valid_samples, invalid_samples, stats)
        """
        self._stats = QualityStats()
        valid_samples = []
        invalid_samples = []
        
        for i, sample in enumerate(samples):
            report = self.check_sample(sample, i)
            
            self._stats.total_checked += 1
            
            if report.is_valid:
                self._stats.passed += 1
                valid_samples.append(sample)
            else:
                self._stats.failed += 1
                invalid_samples.append({
                    'sample': sample,
                    'issues': [issue.value for issue in report.issues],
                    'warnings': report.warnings,
                })
                
                # Track issues
                for issue in report.issues:
                    self._stats.issues_breakdown[issue.value] = \
                        self._stats.issues_breakdown.get(issue.value, 0) + 1
            
            if progress_callback and (i + 1) % 100 == 0:
                progress_callback(i + 1, len(samples))
        
        return valid_samples, invalid_samples, self._stats
    
    def get_stats(self) -> QualityStats:
        """Get current statistics."""
        return self._stats


class TokenCounter:
    """Count tokens for samples using tiktoken."""
    
    def __init__(self, model: str = "gpt-4"):
        """
        Initialize token counter.
        
        Args:
            model: Model name for tokenizer selection
        """
        self.model = model
        self._encoder = None
    
    def _get_encoder(self):
        """Lazy load encoder."""
        if self._encoder is None:
            try:
                import tiktoken
                try:
                    self._encoder = tiktoken.encoding_for_model(self.model)
                except KeyError:
                    self._encoder = tiktoken.get_encoding("cl100k_base")
            except ImportError:
                return None
        return self._encoder
    
    def count_tokens(self, text: str) -> int:
        """Count tokens in text."""
        encoder = self._get_encoder()
        if encoder is None:
            # Fallback: rough estimate
            return len(text) // 4
        return len(encoder.encode(text))
    
    def count_sample_tokens(self, sample: Dict[str, Any]) -> int:
        """Count total tokens in a sample."""
        total = 0
        for field in ['instruction', 'input', 'output']:
            value = sample.get(field, '')
            if isinstance(value, str):
                total += self.count_tokens(value)
        return total
    
    def validate_token_limit(
        self,
        sample: Dict[str, Any],
        max_tokens: int = 4096,
    ) -> Tuple[bool, int]:
        """
        Check if sample is within token limit.
        
        Returns:
            Tuple of (is_valid, token_count)
        """
        count = self.count_sample_tokens(sample)
        return count <= max_tokens, count
