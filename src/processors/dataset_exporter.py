"""
Dataset export utilities for multiple training formats.
Supports various fine-tuning frameworks and model architectures.
"""

import json
import random
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Iterator
from dataclasses import dataclass, asdict

import aiofiles


@dataclass
class DatasetSplit:
    """Represents a dataset split with metadata."""
    name: str
    samples: List[Dict[str, Any]]
    size: int
    
    @property
    def ratio(self) -> float:
        return self.size / max(1, len(self.samples))


class DatasetExporter:
    """
    Exports datasets to various formats for different training frameworks.
    Supports: Axolotl, LLaMA-Factory, Unsloth, OpenAI, etc.
    """
    
    # Format templates for different frameworks
    FORMATS = {
        'alpaca': {
            'extension': '.json',
            'required_fields': ['instruction', 'output'],
            'optional_fields': ['input', 'category', 'source'],
        },
        'sharegpt': {
            'extension': '.json',
            'required_fields': ['conversations'],
        },
        'openai': {
            'extension': '.jsonl',
            'required_fields': ['messages'],
        },
        'llama_factory': {
            'extension': '.json',
            'required_fields': ['instruction', 'output'],
        },
        'axolotl': {
            'extension': '.jsonl',
            'required_fields': ['instruction', 'output'],
        },
    }
    
    def __init__(
        self,
        output_dir: str = "data/exports",
        include_metadata: bool = True,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.include_metadata = include_metadata
    
    def split_dataset(
        self,
        samples: List[Dict[str, Any]],
        train_ratio: float = 0.8,
        val_ratio: float = 0.1,
        test_ratio: float = 0.1,
        shuffle: bool = True,
        seed: int = 42,
        stratify_by: Optional[str] = None,
    ) -> Dict[str, DatasetSplit]:
        """
        Split dataset into train/val/test sets.
        
        Args:
            samples: List of samples to split
            train_ratio: Ratio for training set
            val_ratio: Ratio for validation set
            test_ratio: Ratio for test set
            shuffle: Whether to shuffle before splitting
            seed: Random seed for reproducibility
            stratify_by: Field to use for stratified splitting
        """
        if abs(train_ratio + val_ratio + test_ratio - 1.0) > 0.001:
            raise ValueError("Ratios must sum to 1.0")
        
        if stratify_by:
            return self._stratified_split(
                samples, train_ratio, val_ratio, test_ratio, seed, stratify_by
            )
        
        if shuffle:
            random.seed(seed)
            samples = samples.copy()
            random.shuffle(samples)
        
        n = len(samples)
        train_end = int(n * train_ratio)
        val_end = train_end + int(n * val_ratio)
        
        return {
            'train': DatasetSplit('train', samples[:train_end], train_end),
            'val': DatasetSplit('val', samples[train_end:val_end], val_end - train_end),
            'test': DatasetSplit('test', samples[val_end:], n - val_end),
        }
    
    def _stratified_split(
        self,
        samples: List[Dict[str, Any]],
        train_ratio: float,
        val_ratio: float,
        test_ratio: float,
        seed: int,
        stratify_by: str,
    ) -> Dict[str, DatasetSplit]:
        """Perform stratified split to maintain category distribution."""
        from collections import defaultdict
        
        random.seed(seed)
        
        # Group by stratify field
        groups = defaultdict(list)
        for sample in samples:
            key = sample.get(stratify_by, 'unknown')
            groups[key].append(sample)
        
        train, val, test = [], [], []
        
        for key, group in groups.items():
            random.shuffle(group)
            n = len(group)
            train_end = int(n * train_ratio)
            val_end = train_end + int(n * val_ratio)
            
            train.extend(group[:train_end])
            val.extend(group[train_end:val_end])
            test.extend(group[val_end:])
        
        # Final shuffle within each split
        random.shuffle(train)
        random.shuffle(val)
        random.shuffle(test)
        
        return {
            'train': DatasetSplit('train', train, len(train)),
            'val': DatasetSplit('val', val, len(val)),
            'test': DatasetSplit('test', test, len(test)),
        }
    
    def to_alpaca(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """Convert sample to Alpaca format."""
        return {
            'instruction': sample.get('instruction', ''),
            'input': sample.get('input', ''),
            'output': sample.get('output', ''),
            **({
                'category': sample.get('category', ''),
                'source': sample.get('source', ''),
                'difficulty': sample.get('difficulty', ''),
                'tags': sample.get('tags', []),
            } if self.include_metadata else {})
        }
    
    def to_sharegpt(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """Convert sample to ShareGPT format."""
        conversations = []
        
        # System message if category provides context
        if sample.get('category'):
            conversations.append({
                'from': 'system',
                'value': f"You are a security expert specializing in {sample['category']}."
            })
        
        # User message
        user_msg = sample.get('instruction', '')
        if sample.get('input'):
            user_msg += f"\n\nContext:\n{sample['input']}"
        conversations.append({
            'from': 'human',
            'value': user_msg
        })
        
        # Assistant message
        conversations.append({
            'from': 'gpt',
            'value': sample.get('output', '')
        })
        
        return {'conversations': conversations}
    
    def to_openai(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """Convert sample to OpenAI chat format."""
        messages = []
        
        # System message
        system_msg = "You are an expert security professional and penetration tester."
        if sample.get('category'):
            system_msg += f" You specialize in {sample['category']}."
        messages.append({'role': 'system', 'content': system_msg})
        
        # User message
        user_msg = sample.get('instruction', '')
        if sample.get('input'):
            user_msg += f"\n\n{sample['input']}"
        messages.append({'role': 'user', 'content': user_msg})
        
        # Assistant message
        messages.append({'role': 'assistant', 'content': sample.get('output', '')})
        
        return {'messages': messages}
    
    def to_llama_factory(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """Convert sample to LLaMA-Factory format."""
        result = {
            'instruction': sample.get('instruction', ''),
            'input': sample.get('input', ''),
            'output': sample.get('output', ''),
        }
        
        if sample.get('history'):
            result['history'] = sample['history']
        
        return result
    
    def to_axolotl(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """Convert sample to Axolotl format."""
        return {
            'instruction': sample.get('instruction', ''),
            'input': sample.get('input', ''),
            'output': sample.get('output', ''),
        }
    
    def export(
        self,
        samples: List[Dict[str, Any]],
        format_name: str,
        filename: str,
        split: bool = True,
        **split_kwargs,
    ) -> Dict[str, Path]:
        """
        Export dataset to specified format.
        
        Args:
            samples: List of samples
            format_name: Output format name
            filename: Base filename
            split: Whether to split into train/val/test
            **split_kwargs: Arguments for split_dataset
        """
        if format_name not in self.FORMATS:
            raise ValueError(f"Unknown format: {format_name}. Available: {list(self.FORMATS.keys())}")
        
        format_config = self.FORMATS[format_name]
        converter = getattr(self, f'to_{format_name}')
        
        # Convert all samples
        converted = [converter(s) for s in samples]
        
        output_files = {}
        
        if split:
            splits = self.split_dataset(converted, **split_kwargs)
            for split_name, split_data in splits.items():
                filepath = self.output_dir / f"{filename}_{split_name}{format_config['extension']}"
                self._write_file(filepath, split_data.samples, format_config['extension'])
                output_files[split_name] = filepath
        else:
            filepath = self.output_dir / f"{filename}{format_config['extension']}"
            self._write_file(filepath, converted, format_config['extension'])
            output_files['full'] = filepath
        
        # Write metadata
        metadata = {
            'format': format_name,
            'total_samples': len(samples),
            'exported_at': datetime.utcnow().isoformat(),
            'files': {k: str(v) for k, v in output_files.items()},
        }
        
        if split:
            splits = self.split_dataset(converted, **split_kwargs)
            metadata['splits'] = {k: v.size for k, v in splits.items()}
        
        metadata_path = self.output_dir / f"{filename}_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return output_files
    
    def _write_file(self, filepath: Path, data: List[Dict], extension: str):
        """Write data to file based on extension."""
        with open(filepath, 'w', encoding='utf-8') as f:
            if extension == '.jsonl':
                for item in data:
                    f.write(json.dumps(item, ensure_ascii=False) + '\n')
            else:
                json.dump(data, f, ensure_ascii=False, indent=2)
    
    async def export_async(
        self,
        samples: Iterator[Dict[str, Any]],
        format_name: str,
        filename: str,
        chunk_size: int = 1000,
    ) -> Path:
        """
        Export large dataset asynchronously in chunks.
        """
        format_config = self.FORMATS[format_name]
        converter = getattr(self, f'to_{format_name}')
        filepath = self.output_dir / f"{filename}{format_config['extension']}"
        
        async with aiofiles.open(filepath, 'w', encoding='utf-8') as f:
            if format_config['extension'] == '.jsonl':
                async for sample in samples:
                    converted = converter(sample)
                    await f.write(json.dumps(converted, ensure_ascii=False) + '\n')
            else:
                # Collect all for JSON format
                all_data = [converter(s) async for s in samples]
                await f.write(json.dumps(all_data, ensure_ascii=False, indent=2))
        
        return filepath


class DatasetValidator:
    """Validates exported datasets."""
    
    REQUIRED_FIELDS = {
        'alpaca': ['instruction', 'output'],
        'sharegpt': ['conversations'],
        'openai': ['messages'],
    }
    
    def validate(
        self,
        filepath: Path,
        format_name: str,
    ) -> Dict[str, Any]:
        """Validate exported dataset file."""
        errors = []
        warnings = []
        stats = {'total': 0, 'valid': 0, 'invalid': 0}
        
        extension = filepath.suffix
        
        with open(filepath, 'r', encoding='utf-8') as f:
            if extension == '.jsonl':
                for i, line in enumerate(f):
                    stats['total'] += 1
                    try:
                        sample = json.loads(line)
                        if self._validate_sample(sample, format_name):
                            stats['valid'] += 1
                        else:
                            stats['invalid'] += 1
                            errors.append(f"Line {i+1}: Missing required fields")
                    except json.JSONDecodeError as e:
                        stats['invalid'] += 1
                        errors.append(f"Line {i+1}: Invalid JSON - {e}")
            else:
                data = json.load(f)
                if isinstance(data, list):
                    for i, sample in enumerate(data):
                        stats['total'] += 1
                        if self._validate_sample(sample, format_name):
                            stats['valid'] += 1
                        else:
                            stats['invalid'] += 1
                            errors.append(f"Sample {i}: Missing required fields")
        
        return {
            'is_valid': len(errors) == 0,
            'stats': stats,
            'errors': errors[:10],  # First 10 errors
            'warnings': warnings,
        }
    
    def _validate_sample(self, sample: Dict, format_name: str) -> bool:
        """Validate a single sample."""
        required = self.REQUIRED_FIELDS.get(format_name, [])
        return all(field in sample and sample[field] for field in required)
