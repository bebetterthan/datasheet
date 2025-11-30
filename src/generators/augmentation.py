"""
Data augmentation module for expanding and diversifying the dataset.
Creates variations of existing samples to increase dataset size and diversity.
"""

import random
import re
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class AugmentationConfig:
    """Configuration for augmentation."""
    enable_paraphrase: bool = True
    enable_context_variation: bool = True
    enable_difficulty_variation: bool = True
    enable_format_variation: bool = True
    max_variations_per_sample: int = 3
    preserve_code_blocks: bool = True


class DataAugmentor:
    """
    Augments security dataset by creating variations.
    Uses rule-based and optional LLM-based augmentation.
    """
    
    # Instruction paraphrase patterns
    INSTRUCTION_PATTERNS = {
        "how_to": [
            "How do I {action}?",
            "What's the best way to {action}?",
            "Can you show me how to {action}?",
            "I need to {action}. How should I proceed?",
            "Walk me through {action}.",
            "Explain the process of {action}.",
            "What steps should I follow to {action}?",
        ],
        "explain": [
            "Explain {topic}.",
            "What is {topic} and how does it work?",
            "Can you describe {topic}?",
            "Tell me about {topic}.",
            "I need to understand {topic}. Can you help?",
            "Give me an overview of {topic}.",
            "Help me understand {topic}.",
        ],
        "demonstrate": [
            "Show me an example of {topic}.",
            "Can you demonstrate {topic}?",
            "Give me a practical example of {topic}.",
            "I'd like to see {topic} in action.",
            "Provide a demonstration of {topic}.",
            "Show me how {topic} works.",
        ],
        "list": [
            "List the {topic}.",
            "What are the different {topic}?",
            "Name the various {topic}.",
            "Give me a list of {topic}.",
            "What {topic} exist?",
            "Enumerate the {topic}.",
        ],
    }
    
    # Context additions for security scenarios
    SECURITY_CONTEXTS = [
        "I'm conducting a penetration test.",
        "This is for a CTF challenge.",
        "I'm doing a security assessment.",
        "I need this for a red team engagement.",
        "I'm preparing for OSCP.",
        "This is for authorized security testing.",
        "",  # No context
    ]
    
    # Difficulty level variations
    DIFFICULTY_PREFIXES = {
        "beginner": [
            "As a beginner,",
            "I'm new to this. ",
            "For someone just starting out,",
            "In simple terms,",
        ],
        "intermediate": [
            "",  # No prefix
            "Building on basics,",
        ],
        "advanced": [
            "For an advanced scenario,",
            "Going deeper,",
            "In a more complex situation,",
            "For expert-level understanding,",
        ],
    }
    
    def __init__(
        self,
        config: Optional[AugmentationConfig] = None,
        use_llm: bool = False,
        llm_provider: Optional[str] = None,
        llm_api_key: Optional[str] = None,
    ):
        """
        Initialize augmentor.
        
        Args:
            config: Augmentation configuration
            use_llm: Whether to use LLM for augmentation
            llm_provider: LLM provider name
            llm_api_key: API key for LLM
        """
        self.config = config or AugmentationConfig()
        self.use_llm = use_llm
        self.llm_provider = llm_provider
        self.llm_api_key = llm_api_key
        self._llm_client = None
    
    def augment_sample(
        self,
        sample: Dict[str, Any],
        num_variations: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Generate variations of a sample.
        
        Args:
            sample: Original sample
            num_variations: Number of variations to generate
            
        Returns:
            List of augmented samples (includes original)
        """
        if num_variations is None:
            num_variations = self.config.max_variations_per_sample
        
        variations = [sample]  # Include original
        
        # Generate instruction variations
        if self.config.enable_paraphrase:
            instruction_vars = self._generate_instruction_variations(sample)
            variations.extend(instruction_vars[:num_variations])
        
        # Generate context variations
        if self.config.enable_context_variation:
            context_vars = self._generate_context_variations(sample)
            variations.extend(context_vars[:num_variations])
        
        # Generate difficulty variations
        if self.config.enable_difficulty_variation:
            diff_vars = self._generate_difficulty_variations(sample)
            variations.extend(diff_vars[:num_variations])
        
        # Limit total variations
        return variations[:num_variations + 1]
    
    def _generate_instruction_variations(
        self,
        sample: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Generate instruction paraphrases."""
        variations = []
        instruction = sample.get('instruction', '')
        
        # Detect instruction type
        instruction_lower = instruction.lower()
        
        if any(kw in instruction_lower for kw in ['how', 'steps', 'process']):
            pattern_type = "how_to"
            topic = self._extract_action_from_instruction(instruction)
        elif any(kw in instruction_lower for kw in ['explain', 'describe', 'what is']):
            pattern_type = "explain"
            topic = self._extract_topic_from_instruction(instruction)
        elif any(kw in instruction_lower for kw in ['show', 'example', 'demonstrate']):
            pattern_type = "demonstrate"
            topic = self._extract_topic_from_instruction(instruction)
        elif any(kw in instruction_lower for kw in ['list', 'name', 'enumerate']):
            pattern_type = "list"
            topic = self._extract_topic_from_instruction(instruction)
        else:
            return variations
        
        # Generate variations using patterns
        patterns = self.INSTRUCTION_PATTERNS.get(pattern_type, [])
        
        for pattern in random.sample(patterns, min(3, len(patterns))):
            if pattern_type == "how_to":
                new_instruction = pattern.format(action=topic)
            else:
                new_instruction = pattern.format(topic=topic)
            
            if new_instruction != instruction:
                variation = sample.copy()
                variation['instruction'] = new_instruction
                variation['augmented'] = True
                variation['augmentation_type'] = 'paraphrase'
                variations.append(variation)
        
        return variations
    
    def _generate_context_variations(
        self,
        sample: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Generate variations with different contexts."""
        variations = []
        original_input = sample.get('input', '')
        
        for context in random.sample(self.SECURITY_CONTEXTS, 3):
            if context and context not in original_input:
                variation = sample.copy()
                if original_input:
                    variation['input'] = f"{context} {original_input}"
                else:
                    variation['input'] = context
                variation['augmented'] = True
                variation['augmentation_type'] = 'context'
                variations.append(variation)
        
        return variations
    
    def _generate_difficulty_variations(
        self,
        sample: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Generate variations at different difficulty levels."""
        variations = []
        original_difficulty = sample.get('difficulty', 'intermediate')
        instruction = sample.get('instruction', '')
        
        for difficulty, prefixes in self.DIFFICULTY_PREFIXES.items():
            if difficulty != original_difficulty:
                prefix = random.choice(prefixes)
                if prefix:
                    variation = sample.copy()
                    variation['instruction'] = f"{prefix} {instruction}"
                    variation['difficulty'] = difficulty
                    variation['augmented'] = True
                    variation['augmentation_type'] = 'difficulty'
                    variations.append(variation)
        
        return variations
    
    def _extract_action_from_instruction(self, instruction: str) -> str:
        """Extract action/task from how-to instruction."""
        # Remove question words and punctuation
        action = re.sub(r'^(how\s+(do\s+i|can\s+i|to)|what.*?to)\s*', '', instruction, flags=re.I)
        action = re.sub(r'\?+$', '', action)
        return action.strip().lower()
    
    def _extract_topic_from_instruction(self, instruction: str) -> str:
        """Extract topic from instruction."""
        # Remove common prefixes
        topic = re.sub(r'^(explain|describe|what\s+is|show\s+me|list\s+the)\s*', '', instruction, flags=re.I)
        topic = re.sub(r'[.?!]+$', '', topic)
        return topic.strip()
    
    def augment_batch(
        self,
        samples: List[Dict[str, Any]],
        target_size: Optional[int] = None,
        balance_categories: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Augment a batch of samples.
        
        Args:
            samples: List of samples to augment
            target_size: Target dataset size
            balance_categories: Whether to balance category distribution
            
        Returns:
            Augmented list of samples
        """
        if target_size is None:
            target_size = len(samples) * 2
        
        augmented = list(samples)  # Start with originals
        
        if balance_categories:
            # Get category distribution
            categories = {}
            for sample in samples:
                cat = sample.get('category', 'unknown')
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(sample)
            
            # Find max category size
            max_size = max(len(v) for v in categories.values())
            
            # Augment underrepresented categories
            for cat, cat_samples in categories.items():
                while len(cat_samples) < max_size:
                    # Pick random sample from category
                    sample = random.choice(cat_samples)
                    variations = self.augment_sample(sample, num_variations=1)
                    if len(variations) > 1:
                        augmented.append(variations[1])
                        cat_samples.append(variations[1])
        
        # Add more variations if needed
        while len(augmented) < target_size:
            sample = random.choice(samples)
            variations = self.augment_sample(sample, num_variations=1)
            if len(variations) > 1:
                augmented.append(variations[1])
        
        return augmented[:target_size]
    
    def create_multi_turn_conversation(
        self,
        samples: List[Dict[str, Any]],
        turns: int = 3,
    ) -> Dict[str, Any]:
        """
        Create a multi-turn conversation from related samples.
        
        Args:
            samples: List of related samples
            turns: Number of conversation turns
            
        Returns:
            Multi-turn conversation sample
        """
        if len(samples) < turns:
            turns = len(samples)
        
        selected = random.sample(samples, turns)
        
        conversation = []
        for i, sample in enumerate(selected):
            conversation.append({
                'role': 'user',
                'content': sample.get('instruction', '') + (
                    f"\n{sample.get('input', '')}" if sample.get('input') else ""
                )
            })
            conversation.append({
                'role': 'assistant', 
                'content': sample.get('output', '')
            })
        
        return {
            'conversations': conversation,
            'category': selected[0].get('category', ''),
            'source': selected[0].get('source', ''),
            'augmentation_type': 'multi_turn',
        }


class CodeAugmentor:
    """Specialized augmentor for code samples."""
    
    # Language-specific comment styles
    COMMENT_STYLES = {
        'python': '#',
        'bash': '#',
        'javascript': '//',
        'powershell': '#',
        'ruby': '#',
        'php': '//',
        'java': '//',
        'c': '//',
    }
    
    def __init__(self):
        pass
    
    def add_comments(
        self,
        code: str,
        language: str,
    ) -> str:
        """Add explanatory comments to code."""
        comment_char = self.COMMENT_STYLES.get(language, '#')
        lines = code.split('\n')
        
        # Simple heuristic: add comment before significant lines
        result_lines = []
        for line in lines:
            stripped = line.strip()
            
            # Skip empty lines and existing comments
            if not stripped or stripped.startswith(comment_char):
                result_lines.append(line)
                continue
            
            # Add comment for specific patterns
            if any(kw in stripped.lower() for kw in ['import', 'from', 'require']):
                result_lines.append(f"{comment_char} Import required modules")
            elif 'def ' in stripped or 'function ' in stripped:
                result_lines.append(f"{comment_char} Define function")
            elif 'if ' in stripped or 'for ' in stripped or 'while ' in stripped:
                result_lines.append(f"{comment_char} Control flow")
            
            result_lines.append(line)
        
        return '\n'.join(result_lines)
    
    def create_code_variations(
        self,
        code: str,
        language: str,
    ) -> List[str]:
        """Create variations of code."""
        variations = [code]
        
        # Variation 1: Add comments
        commented = self.add_comments(code, language)
        if commented != code:
            variations.append(commented)
        
        # Variation 2: Add error handling wrapper (for applicable languages)
        if language == 'python':
            wrapped = f"try:\n    {code.replace(chr(10), chr(10) + '    ')}\nexcept Exception as e:\n    print(f'Error: {{e}}')"
            variations.append(wrapped)
        
        return variations
