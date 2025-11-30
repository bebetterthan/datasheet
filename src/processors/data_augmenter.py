"""
Data augmentation module for expanding security datasets.
Generates variations of existing samples while preserving quality.
"""

import random
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..utils.logger import get_logger

logger = get_logger(__name__)


class AugmentationType(str, Enum):
    """Types of data augmentation."""
    PARAPHRASE = "paraphrase"
    CONTEXT_VARIATION = "context_variation"
    DIFFICULTY_SCALING = "difficulty_scaling"
    CODE_VARIATION = "code_variation"
    SCENARIO_EXPANSION = "scenario_expansion"


@dataclass
class AugmentationConfig:
    """Configuration for augmentation."""
    max_augmentations_per_sample: int = 3
    preserve_code_blocks: bool = True
    min_similarity: float = 0.3  # Minimum similarity to original
    max_similarity: float = 0.9  # Maximum similarity (avoid duplicates)
    seed: int = 42


class SecurityTermMapper:
    """Maps security terms to variations and related concepts."""
    
    # Tool/command variations
    TOOL_VARIATIONS = {
        'nmap': ['nmap', 'network mapper', 'port scanner'],
        'metasploit': ['metasploit', 'msf', 'metasploit framework'],
        'burp': ['burp suite', 'burp', 'burp proxy'],
        'wireshark': ['wireshark', 'network analyzer', 'packet sniffer'],
        'sqlmap': ['sqlmap', 'sql injection tool', 'sqli scanner'],
        'hydra': ['hydra', 'brute force tool', 'password cracker'],
        'john': ['john the ripper', 'john', 'password cracker'],
        'hashcat': ['hashcat', 'hash cracker', 'gpu cracker'],
        'gobuster': ['gobuster', 'directory brute forcer', 'dir scanner'],
        'nikto': ['nikto', 'web scanner', 'vulnerability scanner'],
    }
    
    # Vulnerability type variations
    VULN_VARIATIONS = {
        'sql injection': ['sql injection', 'sqli', 'sql injection vulnerability'],
        'xss': ['cross-site scripting', 'xss', 'reflected xss', 'stored xss'],
        'rce': ['remote code execution', 'rce', 'command injection'],
        'lfi': ['local file inclusion', 'lfi', 'file inclusion'],
        'rfi': ['remote file inclusion', 'rfi'],
        'ssrf': ['server-side request forgery', 'ssrf'],
        'csrf': ['cross-site request forgery', 'csrf', 'xsrf'],
        'idor': ['insecure direct object reference', 'idor', 'broken access control'],
        'xxe': ['xml external entity', 'xxe', 'xml injection'],
    }
    
    # Context phrases
    CONTEXT_PHRASES = {
        'explain': ['explain', 'describe', 'elaborate on', 'walk me through'],
        'how to': ['how to', 'how do I', 'what is the method to', 'steps to'],
        'what is': ['what is', 'define', "what's", 'explain what'],
        'demonstrate': ['demonstrate', 'show', 'provide an example of', 'illustrate'],
    }
    
    # Difficulty markers
    DIFFICULTY_MARKERS = {
        'beginner': ['basic', 'simple', 'introductory', 'fundamental'],
        'intermediate': ['moderate', 'standard', 'common'],
        'advanced': ['complex', 'sophisticated', 'in-depth', 'detailed'],
        'expert': ['advanced', 'expert-level', 'complex', 'comprehensive'],
    }
    
    @classmethod
    def get_variation(cls, term: str, variation_dict: Dict[str, List[str]]) -> Optional[str]:
        """Get a random variation of a term."""
        term_lower = term.lower()
        for key, variations in variation_dict.items():
            if term_lower == key or term_lower in [v.lower() for v in variations]:
                return random.choice(variations)
        return None


class DataAugmenter:
    """
    Augments security dataset samples with variations.
    
    Example:
        augmenter = DataAugmenter()
        augmented = augmenter.augment_sample(sample)
    """
    
    def __init__(self, config: Optional[AugmentationConfig] = None):
        """Initialize augmenter with configuration."""
        self.config = config or AugmentationConfig()
        random.seed(self.config.seed)
        self.term_mapper = SecurityTermMapper()
    
    def augment_sample(
        self,
        sample: Dict[str, Any],
        augmentation_types: Optional[List[AugmentationType]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Generate augmented variations of a sample.
        
        Args:
            sample: Original sample dictionary
            augmentation_types: Types of augmentation to apply
            
        Returns:
            List of augmented samples (original not included)
        """
        if augmentation_types is None:
            augmentation_types = [
                AugmentationType.PARAPHRASE,
                AugmentationType.CONTEXT_VARIATION,
            ]
        
        augmented_samples = []
        
        for aug_type in augmentation_types:
            if len(augmented_samples) >= self.config.max_augmentations_per_sample:
                break
            
            try:
                if aug_type == AugmentationType.PARAPHRASE:
                    aug = self._paraphrase_instruction(sample)
                elif aug_type == AugmentationType.CONTEXT_VARIATION:
                    aug = self._vary_context(sample)
                elif aug_type == AugmentationType.DIFFICULTY_SCALING:
                    aug = self._scale_difficulty(sample)
                elif aug_type == AugmentationType.CODE_VARIATION:
                    aug = self._vary_code(sample)
                elif aug_type == AugmentationType.SCENARIO_EXPANSION:
                    aug = self._expand_scenario(sample)
                else:
                    continue
                
                if aug and self._is_valid_augmentation(sample, aug):
                    aug['augmentation_type'] = aug_type.value
                    aug['original_id'] = sample.get('id', '')
                    augmented_samples.append(aug)
                    
            except Exception as e:
                logger.debug(f"Augmentation failed for {aug_type}: {e}")
                continue
        
        return augmented_samples
    
    def augment_dataset(
        self,
        samples: List[Dict[str, Any]],
        augmentation_types: Optional[List[AugmentationType]] = None,
        target_multiplier: float = 2.0,
    ) -> List[Dict[str, Any]]:
        """
        Augment an entire dataset.
        
        Args:
            samples: List of original samples
            augmentation_types: Types of augmentation to apply
            target_multiplier: Target size multiplier (2.0 = double the dataset)
            
        Returns:
            Combined list of original and augmented samples
        """
        target_size = int(len(samples) * target_multiplier)
        augmented_size = target_size - len(samples)
        
        all_augmented = []
        samples_copy = samples.copy()
        random.shuffle(samples_copy)
        
        # Round-robin augmentation
        idx = 0
        while len(all_augmented) < augmented_size and idx < len(samples_copy) * 10:
            sample = samples_copy[idx % len(samples_copy)]
            augmented = self.augment_sample(sample, augmentation_types)
            
            if augmented:
                # Take only what we need
                remaining = augmented_size - len(all_augmented)
                all_augmented.extend(augmented[:remaining])
            
            idx += 1
        
        logger.info(
            f"Augmented dataset: {len(samples)} -> {len(samples) + len(all_augmented)} "
            f"(+{len(all_augmented)} samples)"
        )
        
        return samples + all_augmented
    
    def _paraphrase_instruction(self, sample: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create a paraphrased version of the instruction."""
        instruction = sample.get('instruction', '')
        if not instruction:
            return None
        
        # Simple paraphrasing techniques
        paraphrased = instruction
        
        # Replace context phrases
        for phrase, variations in SecurityTermMapper.CONTEXT_PHRASES.items():
            pattern = re.compile(rf'\b{re.escape(phrase)}\b', re.I)
            if pattern.search(paraphrased):
                replacement = random.choice([v for v in variations if v.lower() != phrase])
                paraphrased = pattern.sub(replacement, paraphrased, count=1)
                break
        
        # Replace tool names with variations
        for tool, variations in SecurityTermMapper.TOOL_VARIATIONS.items():
            pattern = re.compile(rf'\b{re.escape(tool)}\b', re.I)
            if pattern.search(paraphrased):
                other_variations = [v for v in variations if v.lower() != tool]
                if other_variations:
                    paraphrased = pattern.sub(random.choice(other_variations), paraphrased, count=1)
        
        if paraphrased == instruction:
            return None
        
        return {
            **sample,
            'instruction': paraphrased,
        }
    
    def _vary_context(self, sample: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Add contextual variations to the sample."""
        instruction = sample.get('instruction', '')
        output = sample.get('output', '')
        
        if not instruction or not output:
            return None
        
        # Context prefixes for security scenarios
        context_prefixes = [
            "In a penetration testing scenario, ",
            "During a security assessment, ",
            "As a security researcher, ",
            "In a CTF (Capture The Flag) challenge, ",
            "When conducting a vulnerability assessment, ",
            "In a red team engagement, ",
            "For defensive purposes, ",
            "In a bug bounty context, ",
        ]
        
        # Only add context if not already present
        has_context = any(
            prefix.lower() in instruction.lower()[:50]
            for prefix in context_prefixes
        )
        
        if has_context:
            return None
        
        prefix = random.choice(context_prefixes)
        
        # Lowercase first letter if needed
        new_instruction = instruction
        if instruction[0].isupper() and not instruction[:5].isupper():
            new_instruction = instruction[0].lower() + instruction[1:]
        
        return {
            **sample,
            'instruction': prefix + new_instruction,
        }
    
    def _scale_difficulty(self, sample: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create difficulty-scaled variation."""
        difficulty = sample.get('difficulty', 'intermediate').lower()
        instruction = sample.get('instruction', '')
        
        if not instruction:
            return None
        
        # Determine adjacent difficulty level
        difficulty_order = ['beginner', 'intermediate', 'advanced', 'expert']
        try:
            current_idx = difficulty_order.index(difficulty)
        except ValueError:
            current_idx = 1
        
        # Choose adjacent difficulty
        adjacent = []
        if current_idx > 0:
            adjacent.append(difficulty_order[current_idx - 1])
        if current_idx < len(difficulty_order) - 1:
            adjacent.append(difficulty_order[current_idx + 1])
        
        if not adjacent:
            return None
        
        new_difficulty = random.choice(adjacent)
        
        # Modify instruction based on new difficulty
        modifiers = SecurityTermMapper.DIFFICULTY_MARKERS.get(new_difficulty, [])
        if not modifiers:
            return None
        
        modifier = random.choice(modifiers)
        
        # Add modifier to instruction
        if new_difficulty in ['beginner', 'intermediate']:
            new_instruction = f"Provide a {modifier} explanation: {instruction}"
        else:
            new_instruction = f"Provide a {modifier} and {modifier} analysis: {instruction}"
        
        return {
            **sample,
            'instruction': new_instruction,
            'difficulty': new_difficulty,
        }
    
    def _vary_code(self, sample: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create code variation if sample contains code."""
        output = sample.get('output', '')
        
        if not output:
            return None
        
        # Check if output contains code
        code_patterns = [
            r'```\w*\n',  # Markdown code blocks
            r'^\s*\$\s+',  # Shell commands
            r'^\s*#\s*\w+',  # Comments
        ]
        
        has_code = any(re.search(p, output, re.M) for p in code_patterns)
        
        if not has_code:
            return None
        
        # Simple code variations
        new_output = output
        
        # Vary shell prompt style
        new_output = re.sub(r'^\$\s+', lambda m: random.choice(['$ ', '# ', '> ']), new_output, flags=re.M)
        
        # Vary comment style (only if significant change)
        if '# ' in new_output:
            # Add inline comments
            pass
        
        if new_output == output:
            return None
        
        return {
            **sample,
            'output': new_output,
        }
    
    def _expand_scenario(self, sample: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Expand the scenario with additional context."""
        instruction = sample.get('instruction', '')
        
        if not instruction:
            return None
        
        # Scenario expansions
        expansions = [
            "\n\nInclude common pitfalls to avoid.",
            "\n\nExplain the underlying concepts.",
            "\n\nProvide real-world examples.",
            "\n\nDiscuss the security implications.",
            "\n\nMention relevant tools and techniques.",
        ]
        
        # Only expand if instruction is not too long
        if len(instruction) > 500:
            return None
        
        expansion = random.choice(expansions)
        
        return {
            **sample,
            'instruction': instruction + expansion,
        }
    
    def _is_valid_augmentation(
        self,
        original: Dict[str, Any],
        augmented: Dict[str, Any]
    ) -> bool:
        """Check if augmentation is valid (not too similar, not too different)."""
        orig_instruction = original.get('instruction', '')
        aug_instruction = augmented.get('instruction', '')
        
        if not orig_instruction or not aug_instruction:
            return False
        
        # Simple word-based similarity
        orig_words = set(orig_instruction.lower().split())
        aug_words = set(aug_instruction.lower().split())
        
        if not orig_words or not aug_words:
            return False
        
        intersection = len(orig_words & aug_words)
        union = len(orig_words | aug_words)
        
        jaccard = intersection / union if union > 0 else 0
        
        return self.config.min_similarity <= jaccard <= self.config.max_similarity


class TemplateBasedAugmenter:
    """
    Generates samples from templates.
    Useful for creating structured variations.
    """
    
    # Security Q&A templates
    TEMPLATES = {
        'tool_usage': {
            'instruction': "How do I use {tool} to {action}?",
            'variations': {
                'tool': ['nmap', 'metasploit', 'burp suite', 'wireshark'],
                'action': [
                    'scan for open ports',
                    'identify vulnerabilities',
                    'capture network traffic',
                    'exploit a vulnerability'
                ]
            }
        },
        'vulnerability_explanation': {
            'instruction': "Explain {vulnerability} and how to {action} it.",
            'variations': {
                'vulnerability': ['SQL injection', 'XSS', 'CSRF', 'SSRF', 'XXE'],
                'action': ['detect', 'exploit', 'prevent', 'mitigate']
            }
        },
        'concept_comparison': {
            'instruction': "What is the difference between {concept1} and {concept2}?",
            'variations': {
                'concept1': ['symmetric encryption', 'TCP', 'authentication', 'vulnerability'],
                'concept2': ['asymmetric encryption', 'UDP', 'authorization', 'exploit']
            }
        }
    }
    
    def generate_from_template(
        self,
        template_name: str,
        count: int = 10,
    ) -> List[Dict[str, str]]:
        """Generate samples from a template."""
        template = self.TEMPLATES.get(template_name)
        if not template:
            return []
        
        samples = []
        instruction_template = template['instruction']
        variations = template['variations']
        
        # Generate combinations
        keys = list(variations.keys())
        
        for _ in range(count):
            values = {key: random.choice(variations[key]) for key in keys}
            instruction = instruction_template.format(**values)
            
            samples.append({
                'instruction': instruction,
                'output': '',  # To be filled
                'input': '',
                'template': template_name,
                'generated': True,
            })
        
        return samples
