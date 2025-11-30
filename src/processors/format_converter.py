"""
Format converter module for converting data between different formats.
Supports Alpaca, ShareGPT, JSONL, and custom formats.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from enum import Enum

from pydantic import BaseModel, Field, field_validator


class OutputFormat(str, Enum):
    """Supported output formats."""
    ALPACA = "alpaca"
    SHAREGPT = "sharegpt"
    JSONL = "jsonl"
    OPENAI = "openai"


class AlpacaSample(BaseModel):
    """Alpaca format sample schema."""
    instruction: str = Field(..., min_length=1)
    input: str = Field(default="")
    output: str = Field(..., min_length=1)
    category: str = Field(default="general")
    source: str = Field(default="")
    difficulty: str = Field(default="intermediate")
    tags: List[str] = Field(default_factory=list)
    
    @field_validator('difficulty')
    @classmethod
    def validate_difficulty(cls, v):
        valid = ['beginner', 'intermediate', 'advanced']
        if v.lower() not in valid:
            return 'intermediate'
        return v.lower()


class ShareGPTMessage(BaseModel):
    """ShareGPT message format."""
    from_: str = Field(..., alias='from')
    value: str
    
    class Config:
        populate_by_name = True


class ShareGPTSample(BaseModel):
    """ShareGPT format sample schema."""
    conversations: List[ShareGPTMessage]
    source: Optional[str] = None
    category: Optional[str] = None


class OpenAIMessage(BaseModel):
    """OpenAI chat format message."""
    role: str  # system, user, assistant
    content: str


class OpenAISample(BaseModel):
    """OpenAI chat format sample."""
    messages: List[OpenAIMessage]


class DatasetMetadata(BaseModel):
    """Metadata for a dataset batch."""
    scrape_date: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    source: str
    total_samples: int
    categories_breakdown: Dict[str, int] = Field(default_factory=dict)
    avg_output_length: float = 0.0
    total_tokens: int = 0
    format: str = "alpaca"
    version: str = "1.0"


class FormatConverter:
    """
    Converts between different dataset formats.
    Primary target is Alpaca format for fine-tuning.
    """
    
    def __init__(self, default_format: OutputFormat = OutputFormat.ALPACA):
        """
        Initialize format converter.
        
        Args:
            default_format: Default output format
        """
        self.default_format = default_format
    
    def to_alpaca(
        self,
        instruction: str,
        output: str,
        input_text: str = "",
        category: str = "general",
        source: str = "",
        difficulty: str = "intermediate",
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Create an Alpaca format sample.
        
        Args:
            instruction: The instruction/question
            output: The expected output/answer
            input_text: Additional input context
            category: Category of the content
            source: Source URL or identifier
            difficulty: Difficulty level
            tags: List of tags
            
        Returns:
            Alpaca format dictionary
        """
        sample = AlpacaSample(
            instruction=instruction,
            input=input_text,
            output=output,
            category=category,
            source=source,
            difficulty=difficulty,
            tags=tags or [],
        )
        return sample.model_dump()
    
    def to_sharegpt(
        self,
        instruction: str,
        output: str,
        input_text: str = "",
        system_prompt: Optional[str] = None,
        source: str = "",
        category: str = "",
    ) -> Dict[str, Any]:
        """
        Convert to ShareGPT format.
        
        Args:
            instruction: User instruction
            output: Assistant response
            input_text: Additional context
            system_prompt: Optional system prompt
            source: Source identifier
            category: Category
            
        Returns:
            ShareGPT format dictionary
        """
        conversations = []
        
        if system_prompt:
            conversations.append({
                'from': 'system',
                'value': system_prompt
            })
        
        # Combine instruction and input
        user_message = instruction
        if input_text:
            user_message = f"{instruction}\n\nContext:\n{input_text}"
        
        conversations.append({
            'from': 'human',
            'value': user_message
        })
        
        conversations.append({
            'from': 'gpt',
            'value': output
        })
        
        result = {'conversations': conversations}
        if source:
            result['source'] = source
        if category:
            result['category'] = category
        
        return result
    
    def to_openai(
        self,
        instruction: str,
        output: str,
        input_text: str = "",
        system_prompt: str = "You are a helpful cybersecurity expert assistant.",
    ) -> Dict[str, Any]:
        """
        Convert to OpenAI chat format.
        
        Args:
            instruction: User message
            output: Assistant response
            input_text: Additional context
            system_prompt: System prompt
            
        Returns:
            OpenAI chat format dictionary
        """
        messages = [
            {'role': 'system', 'content': system_prompt}
        ]
        
        user_content = instruction
        if input_text:
            user_content = f"{instruction}\n\n{input_text}"
        
        messages.append({'role': 'user', 'content': user_content})
        messages.append({'role': 'assistant', 'content': output})
        
        return {'messages': messages}
    
    def convert_sample(
        self,
        sample: Dict[str, Any],
        from_format: OutputFormat,
        to_format: OutputFormat,
    ) -> Dict[str, Any]:
        """
        Convert a sample from one format to another.
        
        Args:
            sample: Input sample
            from_format: Source format
            to_format: Target format
            
        Returns:
            Converted sample
        """
        # First normalize to internal representation
        instruction = ""
        output = ""
        input_text = ""
        source = ""
        category = ""
        tags = []
        difficulty = "intermediate"
        
        if from_format == OutputFormat.ALPACA:
            instruction = sample.get('instruction', '')
            output = sample.get('output', '')
            input_text = sample.get('input', '')
            source = sample.get('source', '')
            category = sample.get('category', '')
            tags = sample.get('tags', [])
            difficulty = sample.get('difficulty', 'intermediate')
        
        elif from_format == OutputFormat.SHAREGPT:
            conversations = sample.get('conversations', [])
            for conv in conversations:
                role = conv.get('from', '')
                value = conv.get('value', '')
                if role in ['human', 'user']:
                    instruction = value
                elif role in ['gpt', 'assistant']:
                    output = value
            source = sample.get('source', '')
            category = sample.get('category', '')
        
        elif from_format == OutputFormat.OPENAI:
            messages = sample.get('messages', [])
            for msg in messages:
                role = msg.get('role', '')
                content = msg.get('content', '')
                if role == 'user':
                    instruction = content
                elif role == 'assistant':
                    output = content
        
        # Convert to target format
        if to_format == OutputFormat.ALPACA:
            return self.to_alpaca(
                instruction=instruction,
                output=output,
                input_text=input_text,
                source=source,
                category=category,
                tags=tags,
                difficulty=difficulty,
            )
        elif to_format == OutputFormat.SHAREGPT:
            return self.to_sharegpt(
                instruction=instruction,
                output=output,
                input_text=input_text,
                source=source,
                category=category,
            )
        elif to_format == OutputFormat.OPENAI:
            return self.to_openai(
                instruction=instruction,
                output=output,
                input_text=input_text,
            )
        elif to_format == OutputFormat.JSONL:
            return self.to_alpaca(
                instruction=instruction,
                output=output,
                input_text=input_text,
                source=source,
                category=category,
                tags=tags,
                difficulty=difficulty,
            )
        
        return sample
    
    def convert_batch(
        self,
        samples: List[Dict[str, Any]],
        from_format: OutputFormat,
        to_format: OutputFormat,
    ) -> List[Dict[str, Any]]:
        """
        Convert a batch of samples.
        
        Args:
            samples: List of samples
            from_format: Source format
            to_format: Target format
            
        Returns:
            List of converted samples
        """
        return [
            self.convert_sample(sample, from_format, to_format)
            for sample in samples
        ]
    
    def save_dataset(
        self,
        samples: List[Dict[str, Any]],
        output_path: Union[str, Path],
        format_type: OutputFormat = OutputFormat.ALPACA,
        pretty_print: bool = True,
        create_metadata: bool = True,
        source_name: str = "",
    ) -> Path:
        """
        Save dataset to file.
        
        Args:
            samples: List of samples
            output_path: Output file path
            format_type: Output format
            pretty_print: Whether to pretty print JSON
            create_metadata: Whether to create metadata file
            source_name: Source name for metadata
            
        Returns:
            Path to saved file
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if format_type == OutputFormat.JSONL:
            with open(output_path, 'w', encoding='utf-8') as f:
                for sample in samples:
                    f.write(json.dumps(sample, ensure_ascii=False) + '\n')
        else:
            indent = 2 if pretty_print else None
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(samples, f, ensure_ascii=False, indent=indent)
        
        # Create metadata
        if create_metadata:
            metadata = self._generate_metadata(samples, source_name, format_type)
            metadata_path = output_path.with_suffix('.meta.json')
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata.model_dump(), f, ensure_ascii=False, indent=2)
        
        return output_path
    
    def _generate_metadata(
        self,
        samples: List[Dict[str, Any]],
        source_name: str,
        format_type: OutputFormat,
    ) -> DatasetMetadata:
        """Generate metadata for dataset."""
        categories = {}
        total_output_length = 0
        
        for sample in samples:
            # Count categories
            category = sample.get('category', 'uncategorized')
            categories[category] = categories.get(category, 0) + 1
            
            # Sum output lengths
            output = sample.get('output', '')
            if isinstance(output, str):
                total_output_length += len(output)
        
        avg_length = total_output_length / len(samples) if samples else 0
        
        return DatasetMetadata(
            source=source_name,
            total_samples=len(samples),
            categories_breakdown=categories,
            avg_output_length=round(avg_length, 2),
            format=format_type.value,
        )
    
    def load_dataset(
        self,
        input_path: Union[str, Path],
        format_type: Optional[OutputFormat] = None,
    ) -> List[Dict[str, Any]]:
        """
        Load dataset from file.
        
        Args:
            input_path: Input file path
            format_type: Format type (auto-detect if None)
            
        Returns:
            List of samples
        """
        input_path = Path(input_path)
        
        # Auto-detect format
        if format_type is None:
            if input_path.suffix == '.jsonl':
                format_type = OutputFormat.JSONL
            else:
                format_type = OutputFormat.ALPACA
        
        samples = []
        
        if format_type == OutputFormat.JSONL:
            with open(input_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        samples.append(json.loads(line))
        else:
            with open(input_path, 'r', encoding='utf-8') as f:
                samples = json.load(f)
        
        return samples
    
    def split_dataset(
        self,
        samples: List[Dict[str, Any]],
        train_ratio: float = 0.9,
        shuffle: bool = True,
        seed: Optional[int] = None,
    ) -> tuple[List[Dict], List[Dict]]:
        """
        Split dataset into train and validation sets.
        
        Args:
            samples: List of samples
            train_ratio: Ratio for training set
            shuffle: Whether to shuffle before splitting
            seed: Random seed for reproducibility
            
        Returns:
            Tuple of (train_samples, val_samples)
        """
        import random
        
        if seed is not None:
            random.seed(seed)
        
        samples_copy = samples.copy()
        
        if shuffle:
            random.shuffle(samples_copy)
        
        split_idx = int(len(samples_copy) * train_ratio)
        train_samples = samples_copy[:split_idx]
        val_samples = samples_copy[split_idx:]
        
        return train_samples, val_samples
