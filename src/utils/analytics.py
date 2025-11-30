"""
Analytics module for dataset analysis and statistics.
"""

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import re


@dataclass
class DatasetAnalytics:
    """Comprehensive analytics for a dataset."""
    total_samples: int = 0
    total_tokens: int = 0
    avg_instruction_length: float = 0.0
    avg_output_length: float = 0.0
    category_distribution: Dict[str, int] = field(default_factory=dict)
    difficulty_distribution: Dict[str, int] = field(default_factory=dict)
    source_distribution: Dict[str, int] = field(default_factory=dict)
    tag_frequency: Dict[str, int] = field(default_factory=dict)
    length_histogram: Dict[str, int] = field(default_factory=dict)
    quality_metrics: Dict[str, float] = field(default_factory=dict)


class DatasetAnalyzer:
    """
    Analyzes security datasets for insights and quality metrics.
    """
    
    # Length buckets for histogram
    LENGTH_BUCKETS = [
        (0, 100, "0-100"),
        (100, 250, "100-250"),
        (250, 500, "250-500"),
        (500, 1000, "500-1000"),
        (1000, 2000, "1000-2000"),
        (2000, 4000, "2000-4000"),
        (4000, float('inf'), "4000+"),
    ]
    
    # Security keywords for relevance scoring
    SECURITY_KEYWORDS = {
        'high_value': [
            'exploit', 'vulnerability', 'cve', 'payload', 'injection',
            'privilege escalation', 'reverse shell', 'buffer overflow',
            'authentication bypass', 'rce', 'command injection'
        ],
        'medium_value': [
            'scan', 'enumerate', 'pentest', 'attack', 'bypass',
            'credentials', 'hash', 'token', 'session', 'cookie'
        ],
        'general': [
            'security', 'hack', 'malware', 'phishing', 'firewall',
            'encryption', 'password', 'access', 'permission'
        ]
    }
    
    def __init__(self, use_tiktoken: bool = True):
        self.use_tiktoken = use_tiktoken
        self._tokenizer = None
        
        if use_tiktoken:
            try:
                import tiktoken
                self._tokenizer = tiktoken.get_encoding("cl100k_base")
            except ImportError:
                self.use_tiktoken = False
    
    def analyze(self, samples: List[Dict[str, Any]]) -> DatasetAnalytics:
        """
        Perform comprehensive analysis on dataset.
        
        Args:
            samples: List of dataset samples
            
        Returns:
            DatasetAnalytics with all metrics
        """
        analytics = DatasetAnalytics()
        analytics.total_samples = len(samples)
        
        instruction_lengths = []
        output_lengths = []
        all_tags = []
        
        for sample in samples:
            instruction = sample.get('instruction', '')
            output = sample.get('output', '')
            
            # Length analysis
            inst_len = len(instruction)
            out_len = len(output)
            instruction_lengths.append(inst_len)
            output_lengths.append(out_len)
            
            # Token counting
            if self._tokenizer:
                analytics.total_tokens += len(self._tokenizer.encode(instruction))
                analytics.total_tokens += len(self._tokenizer.encode(output))
            
            # Category distribution
            category = sample.get('category', 'unknown')
            analytics.category_distribution[category] = \
                analytics.category_distribution.get(category, 0) + 1
            
            # Difficulty distribution
            difficulty = sample.get('difficulty', 'unknown')
            analytics.difficulty_distribution[difficulty] = \
                analytics.difficulty_distribution.get(difficulty, 0) + 1
            
            # Source distribution
            source = self._extract_domain(sample.get('source', 'unknown'))
            analytics.source_distribution[source] = \
                analytics.source_distribution.get(source, 0) + 1
            
            # Tags
            tags = sample.get('tags', [])
            all_tags.extend(tags)
            
            # Length histogram
            bucket = self._get_length_bucket(out_len)
            analytics.length_histogram[bucket] = \
                analytics.length_histogram.get(bucket, 0) + 1
        
        # Calculate averages
        if samples:
            analytics.avg_instruction_length = sum(instruction_lengths) / len(samples)
            analytics.avg_output_length = sum(output_lengths) / len(samples)
        
        # Tag frequency (top 50)
        tag_counter = Counter(all_tags)
        analytics.tag_frequency = dict(tag_counter.most_common(50))
        
        # Quality metrics
        analytics.quality_metrics = self._calculate_quality_metrics(samples)
        
        return analytics
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        if not url or 'http' not in url:
            return url[:30] if url else 'unknown'
        
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            return parsed.netloc or 'unknown'
        except:
            return 'unknown'
    
    def _get_length_bucket(self, length: int) -> str:
        """Get length bucket for histogram."""
        for min_len, max_len, label in self.LENGTH_BUCKETS:
            if min_len <= length < max_len:
                return label
        return "4000+"
    
    def _calculate_quality_metrics(self, samples: List[Dict]) -> Dict[str, float]:
        """Calculate quality metrics for dataset."""
        metrics = {
            'security_relevance': 0.0,
            'code_coverage': 0.0,
            'diversity_score': 0.0,
            'completeness': 0.0,
        }
        
        if not samples:
            return metrics
        
        total_relevance = 0
        has_code = 0
        complete = 0
        
        for sample in samples:
            output = sample.get('output', '').lower()
            instruction = sample.get('instruction', '')
            
            # Security relevance
            relevance = self._calculate_security_relevance(output)
            total_relevance += relevance
            
            # Code coverage
            if '```' in sample.get('output', '') or 'def ' in output or 'function' in output:
                has_code += 1
            
            # Completeness
            if instruction and sample.get('output') and len(sample.get('output', '')) > 50:
                complete += 1
        
        metrics['security_relevance'] = total_relevance / len(samples)
        metrics['code_coverage'] = has_code / len(samples)
        metrics['completeness'] = complete / len(samples)
        
        # Diversity score (based on unique categories)
        categories = set(s.get('category', '') for s in samples)
        metrics['diversity_score'] = min(1.0, len(categories) / 20)
        
        return metrics
    
    def _calculate_security_relevance(self, text: str) -> float:
        """Calculate security relevance score for text."""
        text_lower = text.lower()
        score = 0.0
        
        # High value keywords (weight: 3)
        for kw in self.SECURITY_KEYWORDS['high_value']:
            if kw in text_lower:
                score += 0.15
        
        # Medium value keywords (weight: 2)
        for kw in self.SECURITY_KEYWORDS['medium_value']:
            if kw in text_lower:
                score += 0.08
        
        # General keywords (weight: 1)
        for kw in self.SECURITY_KEYWORDS['general']:
            if kw in text_lower:
                score += 0.04
        
        return min(1.0, score)
    
    def compare_datasets(
        self,
        dataset1: List[Dict],
        dataset2: List[Dict],
    ) -> Dict[str, Any]:
        """Compare two datasets."""
        analytics1 = self.analyze(dataset1)
        analytics2 = self.analyze(dataset2)
        
        return {
            'size_diff': analytics2.total_samples - analytics1.total_samples,
            'token_diff': analytics2.total_tokens - analytics1.total_tokens,
            'quality_diff': {
                k: analytics2.quality_metrics.get(k, 0) - analytics1.quality_metrics.get(k, 0)
                for k in analytics1.quality_metrics
            },
            'new_categories': set(analytics2.category_distribution.keys()) - \
                            set(analytics1.category_distribution.keys()),
        }
    
    def generate_report(
        self,
        analytics: DatasetAnalytics,
        output_format: str = 'markdown',
    ) -> str:
        """Generate analysis report."""
        if output_format == 'markdown':
            return self._generate_markdown_report(analytics)
        elif output_format == 'json':
            return json.dumps(analytics.__dict__, indent=2)
        else:
            raise ValueError(f"Unknown format: {output_format}")
    
    def _generate_markdown_report(self, analytics: DatasetAnalytics) -> str:
        """Generate Markdown report."""
        lines = [
            "# Dataset Analysis Report\n",
            "## Overview\n",
            f"- **Total Samples**: {analytics.total_samples:,}",
            f"- **Total Tokens**: {analytics.total_tokens:,}",
            f"- **Avg Instruction Length**: {analytics.avg_instruction_length:.1f} chars",
            f"- **Avg Output Length**: {analytics.avg_output_length:.1f} chars\n",
            
            "## Quality Metrics\n",
        ]
        
        for metric, value in analytics.quality_metrics.items():
            lines.append(f"- **{metric.replace('_', ' ').title()}**: {value:.2%}")
        
        lines.append("\n## Category Distribution\n")
        lines.append("| Category | Count | Percentage |")
        lines.append("|----------|-------|------------|")
        
        sorted_cats = sorted(
            analytics.category_distribution.items(),
            key=lambda x: -x[1]
        )[:15]
        
        for cat, count in sorted_cats:
            pct = count / analytics.total_samples * 100
            lines.append(f"| {cat} | {count} | {pct:.1f}% |")
        
        lines.append("\n## Difficulty Distribution\n")
        for diff, count in analytics.difficulty_distribution.items():
            pct = count / analytics.total_samples * 100
            lines.append(f"- **{diff}**: {count} ({pct:.1f}%)")
        
        lines.append("\n## Top Tags\n")
        for tag, count in list(analytics.tag_frequency.items())[:20]:
            lines.append(f"- `{tag}`: {count}")
        
        return '\n'.join(lines)


def analyze_dataset_file(filepath: str) -> DatasetAnalytics:
    """Convenience function to analyze a dataset file."""
    path = Path(filepath)
    
    with open(path, 'r', encoding='utf-8') as f:
        if path.suffix == '.jsonl':
            samples = [json.loads(line) for line in f]
        else:
            samples = json.load(f)
    
    analyzer = DatasetAnalyzer()
    return analyzer.analyze(samples)
