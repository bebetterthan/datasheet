"""
Data validation module for ensuring dataset quality.
Validates samples, detects anomalies, and provides quality reports.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field, field_validator

from ..utils.logger import get_logger

logger = get_logger(__name__)


class ValidationSeverity(str, Enum):
    """Severity level for validation issues."""
    ERROR = "error"      # Must fix
    WARNING = "warning"  # Should fix
    INFO = "info"        # Good to know


class ValidationIssue(BaseModel):
    """Represents a single validation issue."""
    field: str
    message: str
    severity: ValidationSeverity
    value_preview: Optional[str] = None
    suggestion: Optional[str] = None


class ValidationResult(BaseModel):
    """Result of validating a single sample."""
    is_valid: bool
    sample_id: Optional[str] = None
    issues: List[ValidationIssue] = Field(default_factory=list)
    score: float = 1.0  # 0.0 to 1.0
    
    def add_issue(
        self,
        field: str,
        message: str,
        severity: ValidationSeverity,
        value_preview: Optional[str] = None,
        suggestion: Optional[str] = None,
    ):
        """Add a validation issue."""
        self.issues.append(ValidationIssue(
            field=field,
            message=message,
            severity=severity,
            value_preview=value_preview[:100] if value_preview else None,
            suggestion=suggestion,
        ))
        
        # Adjust score based on severity
        if severity == ValidationSeverity.ERROR:
            self.score *= 0.5
            self.is_valid = False
        elif severity == ValidationSeverity.WARNING:
            self.score *= 0.9
    
    @property
    def error_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == ValidationSeverity.ERROR)
    
    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == ValidationSeverity.WARNING)


@dataclass
class ValidationReport:
    """Comprehensive validation report for a dataset."""
    total_samples: int = 0
    valid_samples: int = 0
    invalid_samples: int = 0
    total_errors: int = 0
    total_warnings: int = 0
    avg_quality_score: float = 0.0
    issues_by_field: Dict[str, int] = field(default_factory=dict)
    issues_by_type: Dict[str, int] = field(default_factory=dict)
    sample_results: List[ValidationResult] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'summary': {
                'total_samples': self.total_samples,
                'valid_samples': self.valid_samples,
                'invalid_samples': self.invalid_samples,
                'validity_rate': round(self.valid_samples / max(self.total_samples, 1) * 100, 2),
                'avg_quality_score': round(self.avg_quality_score, 3),
                'total_errors': self.total_errors,
                'total_warnings': self.total_warnings,
            },
            'issues_by_field': self.issues_by_field,
            'issues_by_type': self.issues_by_type,
            'generated_at': self.generated_at,
        }
    
    def to_markdown(self) -> str:
        """Generate markdown report."""
        lines = [
            "# Dataset Validation Report",
            f"\nGenerated: {self.generated_at}\n",
            "## Summary",
            f"- **Total Samples**: {self.total_samples}",
            f"- **Valid Samples**: {self.valid_samples} ({self.valid_samples / max(self.total_samples, 1) * 100:.1f}%)",
            f"- **Invalid Samples**: {self.invalid_samples}",
            f"- **Average Quality Score**: {self.avg_quality_score:.3f}",
            f"- **Total Errors**: {self.total_errors}",
            f"- **Total Warnings**: {self.total_warnings}",
            "",
            "## Issues by Field",
        ]
        
        for field, count in sorted(self.issues_by_field.items(), key=lambda x: -x[1]):
            lines.append(f"- `{field}`: {count} issues")
        
        lines.extend([
            "",
            "## Issues by Type",
        ])
        
        for issue_type, count in sorted(self.issues_by_type.items(), key=lambda x: -x[1]):
            lines.append(f"- {issue_type}: {count}")
        
        return "\n".join(lines)


class DataValidator:
    """
    Validates dataset samples for quality and consistency.
    
    Example:
        validator = DataValidator()
        result = validator.validate_sample(sample)
        report = validator.validate_dataset(samples)
    """
    
    # Known security categories
    VALID_CATEGORIES = {
        'web_security', 'network_security', 'cryptography',
        'malware_analysis', 'forensics', 'reverse_engineering',
        'penetration_testing', 'privilege_escalation', 'vulnerability',
        'exploitation', 'defense', 'compliance', 'general'
    }
    
    # Difficulty levels
    VALID_DIFFICULTIES = {'beginner', 'intermediate', 'advanced', 'expert'}
    
    # Suspicious patterns that might indicate bad data
    SUSPICIOUS_PATTERNS = [
        r'<script[^>]*>',  # Script tags
        r'javascript:',    # JS protocol
        r'\x00',           # Null bytes
        r'[\x00-\x08\x0B\x0C\x0E-\x1F]',  # Control characters
    ]
    
    # Placeholder text patterns
    PLACEHOLDER_PATTERNS = [
        r'\[your (answer|response|text)\]',
        r'\{.*placeholder.*\}',
        r'TODO:?',
        r'FIXME:?',
        r'Lorem ipsum',
        r'example\.com',
        r'xxx+',
    ]
    
    def __init__(
        self,
        min_instruction_length: int = 20,
        max_instruction_length: int = 2000,
        min_output_length: int = 50,
        max_output_length: int = 10000,
        require_category: bool = True,
        allowed_categories: Optional[Set[str]] = None,
        custom_validators: Optional[List[Callable]] = None,
    ):
        """
        Initialize validator with configuration.
        
        Args:
            min_instruction_length: Minimum instruction length
            max_instruction_length: Maximum instruction length
            min_output_length: Minimum output length
            max_output_length: Maximum output length
            require_category: Whether category is required
            allowed_categories: Set of allowed category values
            custom_validators: List of custom validation functions
        """
        self.min_instruction_length = min_instruction_length
        self.max_instruction_length = max_instruction_length
        self.min_output_length = min_output_length
        self.max_output_length = max_output_length
        self.require_category = require_category
        self.allowed_categories = allowed_categories or self.VALID_CATEGORIES
        self.custom_validators = custom_validators or []
        
        # Compile patterns
        self._suspicious_patterns = [re.compile(p, re.I) for p in self.SUSPICIOUS_PATTERNS]
        self._placeholder_patterns = [re.compile(p, re.I) for p in self.PLACEHOLDER_PATTERNS]
    
    def validate_sample(
        self,
        sample: Dict[str, Any],
        sample_id: Optional[str] = None,
    ) -> ValidationResult:
        """
        Validate a single sample.
        
        Args:
            sample: Sample dictionary (Alpaca format)
            sample_id: Optional identifier for the sample
            
        Returns:
            ValidationResult with issues and score
        """
        result = ValidationResult(is_valid=True, sample_id=sample_id)
        
        # Validate instruction
        self._validate_instruction(sample, result)
        
        # Validate output
        self._validate_output(sample, result)
        
        # Validate optional input
        self._validate_input(sample, result)
        
        # Validate category
        self._validate_category(sample, result)
        
        # Validate difficulty
        self._validate_difficulty(sample, result)
        
        # Check for suspicious content
        self._check_suspicious_content(sample, result)
        
        # Check for placeholder text
        self._check_placeholder_text(sample, result)
        
        # Run custom validators
        for validator in self.custom_validators:
            try:
                validator(sample, result)
            except Exception as e:
                logger.warning(f"Custom validator error: {e}")
        
        return result
    
    def validate_dataset(
        self,
        samples: List[Dict[str, Any]],
        sample_id_field: str = "id",
    ) -> ValidationReport:
        """
        Validate an entire dataset.
        
        Args:
            samples: List of sample dictionaries
            sample_id_field: Field to use as sample identifier
            
        Returns:
            ValidationReport with summary and details
        """
        report = ValidationReport(total_samples=len(samples))
        quality_scores = []
        
        for i, sample in enumerate(samples):
            sample_id = sample.get(sample_id_field, str(i))
            result = self.validate_sample(sample, sample_id)
            
            report.sample_results.append(result)
            quality_scores.append(result.score)
            
            if result.is_valid:
                report.valid_samples += 1
            else:
                report.invalid_samples += 1
            
            for issue in result.issues:
                # Track by field
                report.issues_by_field[issue.field] = \
                    report.issues_by_field.get(issue.field, 0) + 1
                
                # Track by type (message)
                short_message = issue.message.split(':')[0] if ':' in issue.message else issue.message
                report.issues_by_type[short_message] = \
                    report.issues_by_type.get(short_message, 0) + 1
                
                # Count errors and warnings
                if issue.severity == ValidationSeverity.ERROR:
                    report.total_errors += 1
                elif issue.severity == ValidationSeverity.WARNING:
                    report.total_warnings += 1
        
        if quality_scores:
            report.avg_quality_score = sum(quality_scores) / len(quality_scores)
        
        return report
    
    def _validate_instruction(self, sample: Dict, result: ValidationResult):
        """Validate instruction field."""
        instruction = sample.get('instruction', '')
        
        if not instruction:
            result.add_issue(
                'instruction', 
                'Missing instruction field',
                ValidationSeverity.ERROR,
                suggestion="Add a clear instruction or question"
            )
            return
        
        if not isinstance(instruction, str):
            result.add_issue(
                'instruction',
                f'Instruction must be string, got {type(instruction).__name__}',
                ValidationSeverity.ERROR
            )
            return
        
        length = len(instruction.strip())
        
        if length < self.min_instruction_length:
            result.add_issue(
                'instruction',
                f'Instruction too short: {length} < {self.min_instruction_length} chars',
                ValidationSeverity.WARNING,
                value_preview=instruction,
                suggestion="Provide more detailed instruction"
            )
        
        if length > self.max_instruction_length:
            result.add_issue(
                'instruction',
                f'Instruction too long: {length} > {self.max_instruction_length} chars',
                ValidationSeverity.WARNING,
                value_preview=instruction[:100] + "...",
                suggestion="Consider splitting into multiple samples"
            )
        
        # Check if instruction ends with question mark or colon
        if not re.search(r'[?:.]$', instruction.strip()):
            result.add_issue(
                'instruction',
                'Instruction should end with punctuation',
                ValidationSeverity.INFO,
                value_preview=instruction[-50:],
                suggestion="Add question mark, colon, or period"
            )
    
    def _validate_output(self, sample: Dict, result: ValidationResult):
        """Validate output field."""
        output = sample.get('output', '')
        
        if not output:
            result.add_issue(
                'output',
                'Missing output field',
                ValidationSeverity.ERROR,
                suggestion="Add the expected response/answer"
            )
            return
        
        if not isinstance(output, str):
            result.add_issue(
                'output',
                f'Output must be string, got {type(output).__name__}',
                ValidationSeverity.ERROR
            )
            return
        
        length = len(output.strip())
        
        if length < self.min_output_length:
            result.add_issue(
                'output',
                f'Output too short: {length} < {self.min_output_length} chars',
                ValidationSeverity.WARNING,
                value_preview=output,
                suggestion="Provide more comprehensive answer"
            )
        
        if length > self.max_output_length:
            result.add_issue(
                'output',
                f'Output too long: {length} > {self.max_output_length} chars',
                ValidationSeverity.WARNING,
                value_preview=output[:100] + "...",
                suggestion="Consider splitting into multiple samples"
            )
        
        # Check if output is just repeating the instruction
        instruction = sample.get('instruction', '')
        if instruction and output.strip() == instruction.strip():
            result.add_issue(
                'output',
                'Output is identical to instruction',
                ValidationSeverity.ERROR,
                suggestion="Provide a proper answer, not echo the question"
            )
        
        # Check for very high similarity with instruction
        if instruction and len(instruction) > 20:
            instruction_words = set(instruction.lower().split())
            output_words = set(output.lower().split()[:50])  # First 50 words
            overlap = len(instruction_words & output_words) / len(instruction_words)
            if overlap > 0.9:
                result.add_issue(
                    'output',
                    'Output has very high overlap with instruction',
                    ValidationSeverity.WARNING,
                    suggestion="Ensure output provides new information"
                )
    
    def _validate_input(self, sample: Dict, result: ValidationResult):
        """Validate optional input field."""
        input_text = sample.get('input', '')
        
        if input_text and not isinstance(input_text, str):
            result.add_issue(
                'input',
                f'Input must be string, got {type(input_text).__name__}',
                ValidationSeverity.ERROR
            )
    
    def _validate_category(self, sample: Dict, result: ValidationResult):
        """Validate category field."""
        category = sample.get('category', '')
        
        if self.require_category and not category:
            result.add_issue(
                'category',
                'Missing category field',
                ValidationSeverity.WARNING,
                suggestion=f"Add one of: {', '.join(sorted(self.allowed_categories)[:5])}..."
            )
            return
        
        if category and category.lower() not in {c.lower() for c in self.allowed_categories}:
            result.add_issue(
                'category',
                f'Unknown category: {category}',
                ValidationSeverity.INFO,
                value_preview=category,
                suggestion=f"Use one of: {', '.join(sorted(self.allowed_categories)[:5])}..."
            )
    
    def _validate_difficulty(self, sample: Dict, result: ValidationResult):
        """Validate difficulty field."""
        difficulty = sample.get('difficulty', '')
        
        if difficulty and difficulty.lower() not in self.VALID_DIFFICULTIES:
            result.add_issue(
                'difficulty',
                f'Invalid difficulty: {difficulty}',
                ValidationSeverity.INFO,
                value_preview=difficulty,
                suggestion=f"Use one of: {', '.join(self.VALID_DIFFICULTIES)}"
            )
    
    def _check_suspicious_content(self, sample: Dict, result: ValidationResult):
        """Check for suspicious content patterns."""
        for field in ['instruction', 'input', 'output']:
            content = sample.get(field, '')
            if not content:
                continue
            
            for pattern in self._suspicious_patterns:
                if pattern.search(content):
                    result.add_issue(
                        field,
                        f'Suspicious content detected: {pattern.pattern}',
                        ValidationSeverity.WARNING,
                        suggestion="Review and sanitize content"
                    )
                    break
    
    def _check_placeholder_text(self, sample: Dict, result: ValidationResult):
        """Check for placeholder text."""
        for field in ['instruction', 'input', 'output']:
            content = sample.get(field, '')
            if not content:
                continue
            
            for pattern in self._placeholder_patterns:
                match = pattern.search(content)
                if match:
                    result.add_issue(
                        field,
                        f'Placeholder text detected: "{match.group()}"',
                        ValidationSeverity.WARNING,
                        value_preview=content[max(0, match.start()-20):match.end()+20],
                        suggestion="Replace placeholder with actual content"
                    )
                    break


class SchemaValidator:
    """
    Validates data against expected schema.
    Ensures consistency across samples.
    """
    
    ALPACA_SCHEMA = {
        'required': ['instruction', 'output'],
        'optional': ['input', 'category', 'difficulty', 'source', 'tags'],
        'types': {
            'instruction': str,
            'input': str,
            'output': str,
            'category': str,
            'difficulty': str,
            'source': str,
            'tags': list,
        }
    }
    
    SHAREGPT_SCHEMA = {
        'required': ['conversations'],
        'optional': ['source', 'category'],
        'types': {
            'conversations': list,
            'source': str,
            'category': str,
        }
    }
    
    def __init__(self, schema: Optional[Dict] = None):
        """Initialize with schema (defaults to Alpaca)."""
        self.schema = schema or self.ALPACA_SCHEMA
    
    def validate(self, sample: Dict) -> Tuple[bool, List[str]]:
        """
        Validate sample against schema.
        
        Returns:
            Tuple of (is_valid, list of error messages)
        """
        errors = []
        
        # Check required fields
        for field in self.schema.get('required', []):
            if field not in sample:
                errors.append(f"Missing required field: {field}")
            elif sample[field] is None or sample[field] == '':
                errors.append(f"Required field is empty: {field}")
        
        # Check types
        for field, expected_type in self.schema.get('types', {}).items():
            if field in sample and sample[field] is not None:
                if not isinstance(sample[field], expected_type):
                    errors.append(
                        f"Invalid type for {field}: expected {expected_type.__name__}, "
                        f"got {type(sample[field]).__name__}"
                    )
        
        # Check for unknown fields (warning only)
        known_fields = set(self.schema.get('required', [])) | set(self.schema.get('optional', []))
        unknown_fields = set(sample.keys()) - known_fields
        # We don't add these as errors, just for info
        
        return len(errors) == 0, errors
