"""
Pattern Loader Module
====================
Loads and manages security patterns from YAML configuration files.
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Pattern
from dataclasses import dataclass, field
import yaml

from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DetectionPattern:
    """Represents a single detection pattern."""
    
    name: str
    pattern: str
    severity: str
    description: str
    compiled: Optional[Pattern] = None
    patterns: List[str] = field(default_factory=list)
    context_required: List[str] = field(default_factory=list)
    case_insensitive: bool = False
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Compile regex pattern after initialization."""
        flags = re.IGNORECASE if self.case_insensitive else 0
        
        if self.pattern:
            try:
                self.compiled = re.compile(self.pattern, flags)
            except re.error as e:
                logger.error(f"Failed to compile pattern {self.name}: {e}")
                self.compiled = None
        
        # Compile all patterns in list
        self._compiled_patterns = []
        for p in self.patterns:
            try:
                self._compiled_patterns.append(re.compile(p, flags))
            except re.error as e:
                logger.error(f"Failed to compile pattern in {self.name}: {e}")
    
    def match(self, text: str) -> List[Dict[str, Any]]:
        """
        Match pattern against text.
        
        Args:
            text: Text to match against
            
        Returns:
            List of matches with details
        """
        matches = []
        
        # Check context requirements
        if self.context_required:
            has_context = any(
                ctx.lower() in text.lower() 
                for ctx in self.context_required
            )
            if not has_context:
                return matches
        
        # Match single pattern
        if self.compiled:
            for match in self.compiled.finditer(text):
                matches.append({
                    "pattern_name": self.name,
                    "match": match.group(),
                    "start": match.start(),
                    "end": match.end(),
                    "severity": self.severity,
                    "description": self.description
                })
        
        # Match pattern list
        for compiled in self._compiled_patterns:
            for match in compiled.finditer(text):
                matches.append({
                    "pattern_name": self.name,
                    "match": match.group(),
                    "start": match.start(),
                    "end": match.end(),
                    "severity": self.severity,
                    "description": self.description
                })
        
        return matches


@dataclass
class PatternCategory:
    """Category of related patterns."""
    
    name: str
    description: str
    patterns: Dict[str, DetectionPattern] = field(default_factory=dict)
    
    def add_pattern(self, pattern: DetectionPattern):
        """Add a pattern to the category."""
        self.patterns[pattern.name] = pattern
    
    def match_all(self, text: str) -> List[Dict[str, Any]]:
        """Match all patterns in category against text."""
        all_matches = []
        for pattern in self.patterns.values():
            if pattern.enabled:
                all_matches.extend(pattern.match(text))
        return all_matches


class PatternLoader:
    """
    Loads and manages security detection patterns.
    
    Supports loading patterns from:
    - Individual YAML files
    - Pattern directories
    - Embedded configurations
    """
    
    def __init__(self, patterns_dir: Optional[str] = None):
        """
        Initialize pattern loader.
        
        Args:
            patterns_dir: Directory containing pattern YAML files
        """
        self.patterns_dir = Path(patterns_dir) if patterns_dir else None
        self.categories: Dict[str, PatternCategory] = {}
        self.all_patterns: Dict[str, DetectionPattern] = {}
        
        # Load patterns if directory provided
        if self.patterns_dir and self.patterns_dir.exists():
            self.load_all_patterns()
    
    def load_all_patterns(self):
        """Load all patterns from patterns directory."""
        if not self.patterns_dir:
            logger.warning("No patterns directory configured")
            return
        
        for yaml_file in self.patterns_dir.glob("*.yaml"):
            try:
                self.load_pattern_file(yaml_file)
                logger.info(f"Loaded patterns from {yaml_file.name}")
            except Exception as e:
                logger.error(f"Failed to load {yaml_file}: {e}")
    
    def load_pattern_file(self, filepath: Path) -> Dict[str, PatternCategory]:
        """
        Load patterns from a YAML file.
        
        Args:
            filepath: Path to YAML pattern file
            
        Returns:
            Dict of loaded pattern categories
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        loaded_categories = {}
        
        for category_name, category_data in data.items():
            if isinstance(category_data, dict):
                category = self._parse_category(category_name, category_data)
                self.categories[category_name] = category
                loaded_categories[category_name] = category
                
                # Index all patterns
                for pattern in category.patterns.values():
                    self.all_patterns[f"{category_name}.{pattern.name}"] = pattern
        
        return loaded_categories
    
    def _parse_category(
        self, 
        name: str, 
        data: Dict[str, Any]
    ) -> PatternCategory:
        """Parse a category from YAML data."""
        category = PatternCategory(
            name=name,
            description=data.get("description", "")
        )
        
        for pattern_name, pattern_data in data.items():
            if pattern_name in ["description", "metadata"]:
                continue
                
            if isinstance(pattern_data, dict):
                pattern = self._parse_pattern(pattern_name, pattern_data)
                category.add_pattern(pattern)
        
        return category
    
    def _parse_pattern(
        self, 
        name: str, 
        data: Dict[str, Any]
    ) -> DetectionPattern:
        """Parse a single pattern from YAML data."""
        return DetectionPattern(
            name=name,
            pattern=data.get("pattern", ""),
            patterns=data.get("patterns", []),
            severity=data.get("severity", "medium"),
            description=data.get("description", ""),
            context_required=data.get("context_required", []),
            case_insensitive=data.get("case_insensitive", False),
            enabled=data.get("enabled", True),
            metadata=data.get("metadata", {})
        )
    
    def get_pattern(self, full_name: str) -> Optional[DetectionPattern]:
        """
        Get a pattern by full name (category.pattern_name).
        
        Args:
            full_name: Full pattern name
            
        Returns:
            DetectionPattern if found, None otherwise
        """
        return self.all_patterns.get(full_name)
    
    def get_category(self, category_name: str) -> Optional[PatternCategory]:
        """
        Get a pattern category by name.
        
        Args:
            category_name: Category name
            
        Returns:
            PatternCategory if found, None otherwise
        """
        return self.categories.get(category_name)
    
    def match(
        self, 
        text: str, 
        categories: Optional[List[str]] = None,
        severity_filter: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Match text against patterns.
        
        Args:
            text: Text to match
            categories: Optional list of categories to use
            severity_filter: Optional list of severities to include
            
        Returns:
            List of all matches
        """
        all_matches = []
        
        # Determine which categories to search
        search_categories = (
            [self.categories[c] for c in categories if c in self.categories]
            if categories else self.categories.values()
        )
        
        for category in search_categories:
            matches = category.match_all(text)
            
            # Apply severity filter
            if severity_filter:
                matches = [
                    m for m in matches 
                    if m["severity"] in severity_filter
                ]
            
            # Add category info
            for match in matches:
                match["category"] = category.name
            
            all_matches.extend(matches)
        
        # Deduplicate by match position
        seen = set()
        unique_matches = []
        for match in all_matches:
            key = (match["start"], match["end"], match["pattern_name"])
            if key not in seen:
                seen.add(key)
                unique_matches.append(match)
        
        return unique_matches
    
    def get_patterns_by_severity(
        self, 
        severity: str
    ) -> List[DetectionPattern]:
        """Get all patterns with a specific severity."""
        return [
            p for p in self.all_patterns.values() 
            if p.severity == severity
        ]
    
    def list_categories(self) -> List[str]:
        """List all loaded categories."""
        return list(self.categories.keys())
    
    def list_patterns(
        self, 
        category: Optional[str] = None
    ) -> List[str]:
        """List all pattern names, optionally filtered by category."""
        if category:
            cat = self.categories.get(category)
            if cat:
                return [f"{category}.{p}" for p in cat.patterns.keys()]
            return []
        return list(self.all_patterns.keys())
    
    def stats(self) -> Dict[str, Any]:
        """Get statistics about loaded patterns."""
        severity_counts = {}
        for pattern in self.all_patterns.values():
            severity_counts[pattern.severity] = (
                severity_counts.get(pattern.severity, 0) + 1
            )
        
        return {
            "total_categories": len(self.categories),
            "total_patterns": len(self.all_patterns),
            "patterns_by_severity": severity_counts,
            "categories": {
                name: len(cat.patterns) 
                for name, cat in self.categories.items()
            }
        }


class PatternMatcher:
    """
    High-level pattern matching interface.
    
    Provides easy-to-use methods for common pattern matching tasks.
    """
    
    def __init__(self, patterns_dir: Optional[str] = None):
        """Initialize pattern matcher."""
        self.loader = PatternLoader(patterns_dir)
    
    def scan_for_credentials(self, text: str) -> List[Dict[str, Any]]:
        """Scan text for exposed credentials."""
        return self.loader.match(
            text, 
            categories=["credentials", "private_keys"]
        )
    
    def scan_for_pii(self, text: str) -> List[Dict[str, Any]]:
        """Scan text for PII (Personally Identifiable Information)."""
        return self.loader.match(text, categories=["pii"])
    
    def scan_for_vulnerabilities(self, text: str) -> List[Dict[str, Any]]:
        """Scan text for vulnerability indicators."""
        return self.loader.match(
            text, 
            categories=["sqli", "xss", "ssrf", "command_injection", "xxe"]
        )
    
    def scan_for_skimmers(self, text: str) -> List[Dict[str, Any]]:
        """Scan text for Magecart/skimmer indicators."""
        return self.loader.match(
            text, 
            categories=[
                "malicious_domains", 
                "code_patterns", 
                "exfiltration_indicators"
            ]
        )
    
    def full_scan(
        self, 
        text: str, 
        severity_filter: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Perform a full security scan.
        
        Args:
            text: Text to scan
            severity_filter: Optional severity filter
            
        Returns:
            Comprehensive scan results
        """
        all_matches = self.loader.match(
            text, 
            severity_filter=severity_filter
        )
        
        # Group by category
        by_category = {}
        for match in all_matches:
            cat = match.get("category", "unknown")
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(match)
        
        # Group by severity
        by_severity = {}
        for match in all_matches:
            sev = match.get("severity", "unknown")
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(match)
        
        return {
            "total_findings": len(all_matches),
            "findings": all_matches,
            "by_category": by_category,
            "by_severity": by_severity,
            "summary": {
                "critical": len(by_severity.get("critical", [])),
                "high": len(by_severity.get("high", [])),
                "medium": len(by_severity.get("medium", [])),
                "low": len(by_severity.get("low", [])),
                "info": len(by_severity.get("info", []))
            }
        }
