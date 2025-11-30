"""
Deduplication module for removing duplicate and near-duplicate content.
Uses multiple strategies including exact matching and semantic similarity.
"""

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DeduplicationStats:
    """Statistics from deduplication process."""
    original_count: int = 0
    final_count: int = 0
    exact_duplicates: int = 0
    near_duplicates: int = 0
    hash_collisions: int = 0
    
    @property
    def duplicates_removed(self) -> int:
        return self.original_count - self.final_count
    
    @property
    def dedup_ratio(self) -> float:
        if self.original_count == 0:
            return 0.0
        return self.duplicates_removed / self.original_count


class Deduplicator:
    """
    Removes duplicate and near-duplicate samples from dataset.
    Supports multiple deduplication strategies.
    """
    
    def __init__(
        self,
        similarity_threshold: float = 0.85,
        hash_fields: Optional[List[str]] = None,
        compare_fields: Optional[List[str]] = None,
        use_semantic: bool = False,
        min_length_for_comparison: int = 50,
    ):
        """
        Initialize deduplicator.
        
        Args:
            similarity_threshold: Threshold for near-duplicate detection (0-1)
            hash_fields: Fields to use for exact hash matching
            compare_fields: Fields to use for similarity comparison
            use_semantic: Use semantic similarity (requires sentence-transformers)
            min_length_for_comparison: Minimum text length for similarity check
        """
        self.similarity_threshold = similarity_threshold
        self.hash_fields = hash_fields or ['instruction', 'output']
        self.compare_fields = compare_fields or ['output']
        self.use_semantic = use_semantic
        self.min_length_for_comparison = min_length_for_comparison
        
        self._seen_hashes: Set[str] = set()
        self._fingerprints: Dict[str, List[int]] = {}
        self._stats = DeduplicationStats()
        
        # Lazy load semantic model
        self._embedding_model = None
    
    def _normalize_text(self, text: str) -> str:
        """Normalize text for comparison."""
        # Lowercase
        text = text.lower()
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)
        # Remove special characters except basic punctuation
        text = re.sub(r'[^\w\s.,!?-]', '', text)
        return text.strip()
    
    def _compute_hash(self, sample: Dict[str, Any]) -> str:
        """Compute hash for a sample based on specified fields."""
        hash_content = []
        for field in self.hash_fields:
            value = sample.get(field, '')
            if isinstance(value, str):
                value = self._normalize_text(value)
            else:
                value = json.dumps(value, sort_keys=True)
            hash_content.append(value)
        
        combined = '||'.join(hash_content)
        return hashlib.md5(combined.encode('utf-8')).hexdigest()
    
    def _compute_ngram_fingerprint(
        self,
        text: str,
        n: int = 3,
        num_hashes: int = 100,
    ) -> List[int]:
        """
        Compute MinHash fingerprint using n-grams.
        
        Args:
            text: Input text
            n: N-gram size
            num_hashes: Number of hash functions
            
        Returns:
            List of MinHash values
        """
        text = self._normalize_text(text)
        
        # Generate n-grams
        ngrams = set()
        for i in range(len(text) - n + 1):
            ngrams.add(text[i:i+n])
        
        if not ngrams:
            return [0] * num_hashes
        
        # Compute MinHash
        fingerprint = []
        for seed in range(num_hashes):
            min_hash = float('inf')
            for ngram in ngrams:
                h = hash((ngram, seed)) & 0xFFFFFFFF
                min_hash = min(min_hash, h)
            fingerprint.append(min_hash)
        
        return fingerprint
    
    def _jaccard_similarity(
        self,
        fp1: List[int],
        fp2: List[int],
    ) -> float:
        """Estimate Jaccard similarity from MinHash fingerprints."""
        if not fp1 or not fp2:
            return 0.0
        matches = sum(1 for a, b in zip(fp1, fp2) if a == b)
        return matches / len(fp1)
    
    def _compute_text_similarity(self, text1: str, text2: str) -> float:
        """
        Compute similarity between two texts.
        Uses character-level comparison as fallback.
        """
        if self.use_semantic and len(text1) > 100 and len(text2) > 100:
            return self._semantic_similarity(text1, text2)
        
        # Use fingerprint-based similarity
        fp1 = self._compute_ngram_fingerprint(text1)
        fp2 = self._compute_ngram_fingerprint(text2)
        return self._jaccard_similarity(fp1, fp2)
    
    def _semantic_similarity(self, text1: str, text2: str) -> float:
        """Compute semantic similarity using embeddings."""
        try:
            if self._embedding_model is None:
                from sentence_transformers import SentenceTransformer
                self._embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            
            embeddings = self._embedding_model.encode([text1, text2])
            # Cosine similarity
            from numpy import dot
            from numpy.linalg import norm
            return float(dot(embeddings[0], embeddings[1]) / (norm(embeddings[0]) * norm(embeddings[1])))
        except ImportError:
            logger.warning("sentence-transformers not installed, falling back to fingerprint similarity")
            self.use_semantic = False
            return self._compute_text_similarity(text1, text2)
    
    def is_duplicate(
        self,
        sample: Dict[str, Any],
        check_near_duplicates: bool = True,
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if a sample is a duplicate.
        
        Args:
            sample: Sample to check
            check_near_duplicates: Whether to check for near-duplicates
            
        Returns:
            Tuple of (is_duplicate, reason)
        """
        # Check exact hash match
        sample_hash = self._compute_hash(sample)
        
        if sample_hash in self._seen_hashes:
            return True, "exact_duplicate"
        
        # Check near-duplicates if enabled
        if check_near_duplicates:
            compare_text = ' '.join(
                str(sample.get(f, '')) for f in self.compare_fields
            )
            
            if len(compare_text) >= self.min_length_for_comparison:
                fp = self._compute_ngram_fingerprint(compare_text)
                
                for existing_hash, existing_fp in self._fingerprints.items():
                    similarity = self._jaccard_similarity(fp, existing_fp)
                    if similarity >= self.similarity_threshold:
                        return True, f"near_duplicate (similarity: {similarity:.2f})"
                
                # Store fingerprint
                self._fingerprints[sample_hash] = fp
        
        # Not a duplicate
        self._seen_hashes.add(sample_hash)
        return False, None
    
    def deduplicate(
        self,
        samples: List[Dict[str, Any]],
        check_near_duplicates: bool = True,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Tuple[List[Dict[str, Any]], DeduplicationStats]:
        """
        Remove duplicates from a list of samples.
        
        Args:
            samples: List of samples
            check_near_duplicates: Check for near-duplicates
            progress_callback: Callback for progress updates
            
        Returns:
            Tuple of (deduplicated samples, statistics)
        """
        self.reset()
        self._stats.original_count = len(samples)
        
        unique_samples = []
        
        for i, sample in enumerate(samples):
            is_dup, reason = self.is_duplicate(sample, check_near_duplicates)
            
            if not is_dup:
                unique_samples.append(sample)
            else:
                if reason == "exact_duplicate":
                    self._stats.exact_duplicates += 1
                elif reason and "near_duplicate" in reason:
                    self._stats.near_duplicates += 1
            
            if progress_callback and (i + 1) % 100 == 0:
                progress_callback(i + 1, len(samples))
        
        self._stats.final_count = len(unique_samples)
        
        logger.info(
            f"Deduplication complete: {self._stats.original_count} -> {self._stats.final_count} "
            f"({self._stats.duplicates_removed} removed, "
            f"{self._stats.exact_duplicates} exact, "
            f"{self._stats.near_duplicates} near-duplicates)"
        )
        
        return unique_samples, self._stats
    
    def deduplicate_incremental(
        self,
        sample: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Add sample if not duplicate (for streaming deduplication).
        
        Args:
            sample: Sample to add
            
        Returns:
            Sample if unique, None if duplicate
        """
        is_dup, _ = self.is_duplicate(sample)
        return None if is_dup else sample
    
    def reset(self) -> None:
        """Reset deduplicator state."""
        self._seen_hashes.clear()
        self._fingerprints.clear()
        self._stats = DeduplicationStats()
    
    def get_stats(self) -> DeduplicationStats:
        """Get current statistics."""
        return self._stats


class CrossSourceDeduplicator:
    """
    Deduplicator that works across multiple sources.
    Useful for ensuring no duplicates when combining datasets.
    """
    
    def __init__(self, **kwargs):
        self.deduplicator = Deduplicator(**kwargs)
        self._source_stats: Dict[str, DeduplicationStats] = {}
    
    def add_source(
        self,
        source_name: str,
        samples: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Add samples from a source, removing cross-source duplicates.
        
        Args:
            source_name: Name of the source
            samples: Samples to add
            
        Returns:
            Unique samples
        """
        initial_count = len(samples)
        unique = []
        
        for sample in samples:
            if self.deduplicator.deduplicate_incremental(sample) is not None:
                unique.append(sample)
        
        # Track stats per source
        self._source_stats[source_name] = DeduplicationStats(
            original_count=initial_count,
            final_count=len(unique),
            exact_duplicates=initial_count - len(unique),
        )
        
        return unique
    
    def get_source_stats(self) -> Dict[str, DeduplicationStats]:
        """Get statistics per source."""
        return self._source_stats
    
    def reset(self) -> None:
        """Reset all state."""
        self.deduplicator.reset()
        self._source_stats.clear()


# Helper function moved here since we use it
def get_logger(name: str):
    """Get logger - import from utils if available, otherwise use standard logging."""
    try:
        from ..utils.logger import get_logger as _get_logger
        return _get_logger(name)
    except ImportError:
        import logging
        return logging.getLogger(name)
