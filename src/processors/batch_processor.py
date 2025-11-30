"""
Batch processor for handling large-scale data processing efficiently.
Supports parallel processing, checkpointing, and streaming.
"""

import asyncio
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Dict,
    Generic,
    Iterator,
    List,
    Optional,
    TypeVar,
    Union,
)
import aiofiles
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

from ..utils.logger import get_logger

logger = get_logger(__name__)

T = TypeVar('T')
R = TypeVar('R')


@dataclass
class BatchConfig:
    """Configuration for batch processing."""
    batch_size: int = 100
    max_workers: int = 4
    checkpoint_interval: int = 1000
    checkpoint_dir: str = "data/checkpoints"
    use_multiprocessing: bool = False
    timeout_per_item: float = 30.0
    retry_failed: bool = True
    max_retries: int = 3


@dataclass
class BatchStats:
    """Statistics for batch processing."""
    total_items: int = 0
    processed_items: int = 0
    success_count: int = 0
    error_count: int = 0
    skipped_count: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    errors: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def duration_seconds(self) -> float:
        if not self.start_time:
            return 0
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()
    
    @property
    def items_per_second(self) -> float:
        if self.duration_seconds == 0:
            return 0
        return self.processed_items / self.duration_seconds
    
    @property
    def success_rate(self) -> float:
        if self.processed_items == 0:
            return 0
        return self.success_count / self.processed_items
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_items': self.total_items,
            'processed_items': self.processed_items,
            'success_count': self.success_count,
            'error_count': self.error_count,
            'skipped_count': self.skipped_count,
            'duration_seconds': self.duration_seconds,
            'items_per_second': round(self.items_per_second, 2),
            'success_rate': round(self.success_rate * 100, 2),
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
        }


class CheckpointManager:
    """Manages checkpoints for resumable processing."""
    
    def __init__(self, checkpoint_dir: str, job_id: str):
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.job_id = job_id
        self.checkpoint_file = self.checkpoint_dir / f"{job_id}.checkpoint.json"
    
    def save_checkpoint(self, state: Dict[str, Any]):
        """Save checkpoint state."""
        state['timestamp'] = datetime.now().isoformat()
        with open(self.checkpoint_file, 'w') as f:
            json.dump(state, f, indent=2)
        logger.debug(f"Checkpoint saved: {self.checkpoint_file}")
    
    def load_checkpoint(self) -> Optional[Dict[str, Any]]:
        """Load checkpoint state if exists."""
        if self.checkpoint_file.exists():
            with open(self.checkpoint_file, 'r') as f:
                return json.load(f)
        return None
    
    def clear_checkpoint(self):
        """Remove checkpoint file."""
        if self.checkpoint_file.exists():
            self.checkpoint_file.unlink()
            logger.debug(f"Checkpoint cleared: {self.checkpoint_file}")


class BatchProcessor(Generic[T, R]):
    """
    Generic batch processor for handling large datasets.
    
    Example:
        async def process_item(item: dict) -> dict:
            # Process item
            return processed_item
        
        processor = BatchProcessor(config)
        results = await processor.process(items, process_item)
    """
    
    def __init__(
        self,
        config: Optional[BatchConfig] = None,
        job_id: Optional[str] = None,
    ):
        self.config = config or BatchConfig()
        self.job_id = job_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.stats = BatchStats()
        self.checkpoint_manager = CheckpointManager(
            self.config.checkpoint_dir,
            self.job_id
        )
        self._processed_ids: set = set()
    
    async def process(
        self,
        items: Union[List[T], Iterator[T], AsyncIterator[T]],
        processor_func: Callable[[T], R],
        item_id_func: Optional[Callable[[T], str]] = None,
        on_batch_complete: Optional[Callable[[List[R]], None]] = None,
    ) -> List[R]:
        """
        Process items in batches.
        
        Args:
            items: Items to process (list, iterator, or async iterator)
            processor_func: Function to process each item
            item_id_func: Function to get unique ID from item (for checkpointing)
            on_batch_complete: Callback after each batch completes
            
        Returns:
            List of processed results
        """
        self.stats.start_time = datetime.now()
        results: List[R] = []
        
        # Load checkpoint if exists
        checkpoint = self.checkpoint_manager.load_checkpoint()
        if checkpoint:
            self._processed_ids = set(checkpoint.get('processed_ids', []))
            logger.info(f"Resuming from checkpoint: {len(self._processed_ids)} items already processed")
        
        # Determine if async processing
        if asyncio.iscoroutinefunction(processor_func):
            results = await self._process_async(
                items, processor_func, item_id_func, on_batch_complete
            )
        else:
            results = await self._process_sync(
                items, processor_func, item_id_func, on_batch_complete
            )
        
        self.stats.end_time = datetime.now()
        self.checkpoint_manager.clear_checkpoint()
        
        logger.info(f"Batch processing complete: {self.stats.to_dict()}")
        return results
    
    async def _process_async(
        self,
        items: Union[List[T], Iterator[T], AsyncIterator[T]],
        processor_func: Callable[[T], R],
        item_id_func: Optional[Callable[[T], str]],
        on_batch_complete: Optional[Callable[[List[R]], None]],
    ) -> List[R]:
        """Process items with async processor function."""
        results: List[R] = []
        batch: List[T] = []
        items_since_checkpoint = 0
        
        async for item in self._iterate_items(items):
            self.stats.total_items += 1
            
            # Check if already processed
            if item_id_func:
                item_id = item_id_func(item)
                if item_id in self._processed_ids:
                    self.stats.skipped_count += 1
                    continue
            
            batch.append(item)
            
            if len(batch) >= self.config.batch_size:
                batch_results = await self._process_batch_async(
                    batch, processor_func, item_id_func
                )
                results.extend(batch_results)
                
                if on_batch_complete:
                    on_batch_complete(batch_results)
                
                items_since_checkpoint += len(batch)
                if items_since_checkpoint >= self.config.checkpoint_interval:
                    self._save_checkpoint()
                    items_since_checkpoint = 0
                
                batch = []
        
        # Process remaining items
        if batch:
            batch_results = await self._process_batch_async(
                batch, processor_func, item_id_func
            )
            results.extend(batch_results)
            
            if on_batch_complete:
                on_batch_complete(batch_results)
        
        return results
    
    async def _process_batch_async(
        self,
        batch: List[T],
        processor_func: Callable[[T], R],
        item_id_func: Optional[Callable[[T], str]],
    ) -> List[R]:
        """Process a single batch asynchronously."""
        tasks = []
        for item in batch:
            task = asyncio.create_task(
                self._process_item_async(item, processor_func, item_id_func)
            )
            tasks.append(task)
        
        # Limit concurrency
        semaphore = asyncio.Semaphore(self.config.max_workers)
        
        async def bounded_task(task):
            async with semaphore:
                return await task
        
        results = await asyncio.gather(
            *[bounded_task(t) for t in tasks],
            return_exceptions=True
        )
        
        # Filter out exceptions and None results
        valid_results = []
        for result in results:
            if isinstance(result, Exception):
                continue
            if result is not None:
                valid_results.append(result)
        
        return valid_results
    
    async def _process_item_async(
        self,
        item: T,
        processor_func: Callable[[T], R],
        item_id_func: Optional[Callable[[T], str]],
    ) -> Optional[R]:
        """Process a single item with error handling."""
        item_id = item_id_func(item) if item_id_func else str(hash(str(item)))
        
        for attempt in range(self.config.max_retries):
            try:
                result = await asyncio.wait_for(
                    processor_func(item),
                    timeout=self.config.timeout_per_item
                )
                self.stats.processed_items += 1
                self.stats.success_count += 1
                self._processed_ids.add(item_id)
                return result
                
            except asyncio.TimeoutError:
                logger.warning(f"Timeout processing item {item_id} (attempt {attempt + 1})")
            except Exception as e:
                logger.error(f"Error processing item {item_id}: {e}")
                if attempt == self.config.max_retries - 1:
                    self.stats.error_count += 1
                    self.stats.errors.append({
                        'item_id': item_id,
                        'error': str(e),
                        'attempt': attempt + 1,
                    })
        
        self.stats.processed_items += 1
        return None
    
    async def _process_sync(
        self,
        items: Union[List[T], Iterator[T], AsyncIterator[T]],
        processor_func: Callable[[T], R],
        item_id_func: Optional[Callable[[T], str]],
        on_batch_complete: Optional[Callable[[List[R]], None]],
    ) -> List[R]:
        """Process items with sync processor function using thread/process pool."""
        results: List[R] = []
        batch: List[T] = []
        items_since_checkpoint = 0
        
        # Choose executor based on config
        executor_class = ProcessPoolExecutor if self.config.use_multiprocessing else ThreadPoolExecutor
        
        async for item in self._iterate_items(items):
            self.stats.total_items += 1
            
            if item_id_func:
                item_id = item_id_func(item)
                if item_id in self._processed_ids:
                    self.stats.skipped_count += 1
                    continue
            
            batch.append(item)
            
            if len(batch) >= self.config.batch_size:
                loop = asyncio.get_event_loop()
                
                with executor_class(max_workers=self.config.max_workers) as executor:
                    batch_results = list(executor.map(processor_func, batch))
                
                # Update stats
                for i, result in enumerate(batch_results):
                    self.stats.processed_items += 1
                    if result is not None:
                        self.stats.success_count += 1
                        results.append(result)
                        if item_id_func:
                            self._processed_ids.add(item_id_func(batch[i]))
                    else:
                        self.stats.error_count += 1
                
                if on_batch_complete:
                    on_batch_complete([r for r in batch_results if r is not None])
                
                items_since_checkpoint += len(batch)
                if items_since_checkpoint >= self.config.checkpoint_interval:
                    self._save_checkpoint()
                    items_since_checkpoint = 0
                
                batch = []
        
        # Process remaining
        if batch:
            with executor_class(max_workers=self.config.max_workers) as executor:
                batch_results = list(executor.map(processor_func, batch))
            
            for result in batch_results:
                self.stats.processed_items += 1
                if result is not None:
                    self.stats.success_count += 1
                    results.append(result)
                else:
                    self.stats.error_count += 1
            
            if on_batch_complete:
                on_batch_complete([r for r in batch_results if r is not None])
        
        return results
    
    async def _iterate_items(
        self,
        items: Union[List[T], Iterator[T], AsyncIterator[T]]
    ) -> AsyncIterator[T]:
        """Convert any iterable to async iterator."""
        if hasattr(items, '__aiter__'):
            async for item in items:
                yield item
        elif hasattr(items, '__iter__'):
            for item in items:
                yield item
        else:
            raise TypeError(f"Expected iterable, got {type(items)}")
    
    def _save_checkpoint(self):
        """Save current processing state."""
        state = {
            'processed_ids': list(self._processed_ids),
            'stats': self.stats.to_dict(),
        }
        self.checkpoint_manager.save_checkpoint(state)


class StreamingBatchWriter:
    """
    Writes processed results to files in a streaming manner.
    Useful for large datasets that don't fit in memory.
    """
    
    def __init__(
        self,
        output_path: str,
        format: str = "jsonl",
        buffer_size: int = 100,
    ):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.format = format
        self.buffer_size = buffer_size
        self._buffer: List[Dict] = []
        self._count = 0
    
    async def write(self, item: Dict):
        """Write a single item to buffer."""
        self._buffer.append(item)
        self._count += 1
        
        if len(self._buffer) >= self.buffer_size:
            await self.flush()
    
    async def write_batch(self, items: List[Dict]):
        """Write multiple items."""
        for item in items:
            await self.write(item)
    
    async def flush(self):
        """Flush buffer to file."""
        if not self._buffer:
            return
        
        mode = 'a' if self.output_path.exists() else 'w'
        
        async with aiofiles.open(self.output_path, mode) as f:
            if self.format == "jsonl":
                for item in self._buffer:
                    await f.write(json.dumps(item, ensure_ascii=False) + '\n')
            elif self.format == "json":
                # For JSON format, need to handle array properly
                # This is simplified - production code should handle this better
                for item in self._buffer:
                    await f.write(json.dumps(item, ensure_ascii=False) + '\n')
        
        logger.debug(f"Flushed {len(self._buffer)} items to {self.output_path}")
        self._buffer = []
    
    async def close(self):
        """Close writer and flush remaining buffer."""
        await self.flush()
        logger.info(f"StreamingBatchWriter closed. Total items written: {self._count}")
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


def chunked(iterable: List[T], size: int) -> Iterator[List[T]]:
    """Split an iterable into chunks of specified size."""
    for i in range(0, len(iterable), size):
        yield iterable[i:i + size]
