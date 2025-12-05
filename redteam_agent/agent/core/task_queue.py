"""
Task Queue System
=================

Priority-based task queue with dependency management.
"""

import asyncio
import heapq
from typing import Dict, Any, Optional, List, Callable, Awaitable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import uuid
import threading

from agent.utils.logger import get_logger


class TaskPriority(Enum):
    """Task priority levels."""
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    BACKGROUND = 5


class TaskStatus(Enum):
    """Task execution status."""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


@dataclass(order=True)
class PrioritizedTask:
    """Task wrapper for priority queue."""
    priority: int
    timestamp: float
    task: Any = field(compare=False)


@dataclass
class Task:
    """Task definition."""
    id: str
    name: str
    handler: str  # Handler function/method name
    params: Dict[str, Any] = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    depends_on: List[str] = field(default_factory=list)
    timeout: int = 300
    retries: int = 0
    retry_delay: int = 5
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[Any] = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    attempts: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class TaskQueue:
    """
    Priority-based task queue with async execution.
    
    Features:
    - Priority-based ordering
    - Task dependencies
    - Retry logic
    - Timeout handling
    - Concurrent execution
    - Event callbacks
    """
    
    def __init__(
        self,
        max_workers: int = 5,
        max_queue_size: int = 1000
    ):
        self.logger = get_logger("TaskQueue")
        self.max_workers = max_workers
        self.max_queue_size = max_queue_size
        
        # Priority queue (min-heap)
        self._queue: List[PrioritizedTask] = []
        self._queue_lock = threading.Lock()
        
        # Task tracking
        self._tasks: Dict[str, Task] = {}
        self._running: Dict[str, Task] = {}
        self._completed: Dict[str, Task] = {}
        
        # Handlers
        self._handlers: Dict[str, Callable] = {}
        
        # Event callbacks
        self._callbacks: Dict[str, List[Callable]] = {
            "task_started": [],
            "task_completed": [],
            "task_failed": [],
            "queue_empty": []
        }
        
        # Control
        self._running_flag = False
        self._worker_tasks: List[asyncio.Task] = []
        
    def register_handler(self, name: str, handler: Callable) -> None:
        """Register a task handler."""
        self._handlers[name] = handler
        self.logger.debug(f"Registered handler: {name}")
        
    def on(self, event: str, callback: Callable) -> None:
        """Register event callback."""
        if event in self._callbacks:
            self._callbacks[event].append(callback)
            
    def create_task(
        self,
        name: str,
        handler: str,
        params: Optional[Dict[str, Any]] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        depends_on: Optional[List[str]] = None,
        timeout: int = 300,
        retries: int = 0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Task:
        """Create a new task."""
        task = Task(
            id=str(uuid.uuid4()),
            name=name,
            handler=handler,
            params=params or {},
            priority=priority,
            depends_on=depends_on or [],
            timeout=timeout,
            retries=retries,
            metadata=metadata or {}
        )
        
        self._tasks[task.id] = task
        return task
        
    def enqueue(self, task: Task) -> bool:
        """Add task to queue."""
        if len(self._queue) >= self.max_queue_size:
            self.logger.warning("Queue is full, rejecting task")
            return False
            
        # Check if handler exists
        if task.handler not in self._handlers:
            self.logger.error(f"Unknown handler: {task.handler}")
            return False
            
        task.status = TaskStatus.QUEUED
        
        with self._queue_lock:
            heapq.heappush(
                self._queue,
                PrioritizedTask(
                    priority=task.priority.value,
                    timestamp=task.created_at.timestamp(),
                    task=task
                )
            )
            
        self.logger.info(f"Enqueued task: {task.name} (priority={task.priority.name})")
        return True
        
    def enqueue_many(self, tasks: List[Task]) -> int:
        """Add multiple tasks to queue."""
        count = 0
        for task in tasks:
            if self.enqueue(task):
                count += 1
        return count
        
    def dequeue(self) -> Optional[Task]:
        """Get next task from queue."""
        with self._queue_lock:
            while self._queue:
                prioritized = heapq.heappop(self._queue)
                task = prioritized.task
                
                # Check dependencies
                if task.depends_on:
                    deps_met = all(
                        self._tasks.get(dep_id, {}).status == TaskStatus.COMPLETED
                        for dep_id in task.depends_on
                        if dep_id in self._tasks
                    )
                    
                    if not deps_met:
                        # Re-queue with lower priority to avoid blocking
                        heapq.heappush(
                            self._queue,
                            PrioritizedTask(
                                priority=task.priority.value + 1,  # Lower priority
                                timestamp=datetime.now().timestamp(),
                                task=task
                            )
                        )
                        continue
                        
                return task
                
        return None
        
    def get_task(self, task_id: str) -> Optional[Task]:
        """Get task by ID."""
        return self._tasks.get(task_id)
        
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a pending task."""
        task = self._tasks.get(task_id)
        if task and task.status in [TaskStatus.PENDING, TaskStatus.QUEUED]:
            task.status = TaskStatus.CANCELLED
            return True
        return False
        
    def get_queue_status(self) -> Dict[str, Any]:
        """Get queue status."""
        return {
            "queue_size": len(self._queue),
            "running": len(self._running),
            "completed": len(self._completed),
            "total_tasks": len(self._tasks),
            "workers": self.max_workers,
            "is_running": self._running_flag,
            "status_counts": self._get_status_counts()
        }
        
    def _get_status_counts(self) -> Dict[str, int]:
        """Get task counts by status."""
        counts = {}
        for task in self._tasks.values():
            status = task.status.value
            counts[status] = counts.get(status, 0) + 1
        return counts
        
    async def start(self) -> None:
        """Start the task queue workers."""
        if self._running_flag:
            return
            
        self._running_flag = True
        self.logger.info(f"Starting task queue with {self.max_workers} workers")
        
        # Start worker tasks
        for i in range(self.max_workers):
            worker = asyncio.create_task(self._worker(i))
            self._worker_tasks.append(worker)
            
    async def stop(self, wait: bool = True) -> None:
        """Stop the task queue."""
        self._running_flag = False
        
        if wait and self._worker_tasks:
            await asyncio.gather(*self._worker_tasks, return_exceptions=True)
            
        self._worker_tasks.clear()
        self.logger.info("Task queue stopped")
        
    async def _worker(self, worker_id: int) -> None:
        """Worker coroutine that processes tasks."""
        self.logger.debug(f"Worker {worker_id} started")
        
        while self._running_flag:
            task = self.dequeue()
            
            if not task:
                # No tasks available
                await asyncio.sleep(0.1)
                continue
                
            try:
                await self._execute_task(task, worker_id)
            except Exception as e:
                self.logger.error(f"Worker {worker_id} error: {e}")
                
        self.logger.debug(f"Worker {worker_id} stopped")
        
    async def _execute_task(self, task: Task, worker_id: int) -> None:
        """Execute a single task."""
        task.status = TaskStatus.RUNNING
        task.started_at = datetime.now()
        task.attempts += 1
        
        self._running[task.id] = task
        self.logger.info(f"Worker {worker_id} executing: {task.name}")
        
        # Fire started callback
        await self._fire_callbacks("task_started", task)
        
        try:
            handler = self._handlers[task.handler]
            
            # Execute with timeout
            result = await asyncio.wait_for(
                self._call_handler(handler, task),
                timeout=task.timeout
            )
            
            task.result = result
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now()
            
            self._completed[task.id] = task
            
            # Fire completed callback
            await self._fire_callbacks("task_completed", task)
            
            self.logger.info(f"Task completed: {task.name}")
            
        except asyncio.TimeoutError:
            task.error = f"Task timed out after {task.timeout}s"
            task.status = TaskStatus.TIMEOUT
            self.logger.warning(f"Task timeout: {task.name}")
            
            # Retry if applicable
            if task.attempts <= task.retries:
                await self._retry_task(task)
            else:
                await self._fire_callbacks("task_failed", task)
                
        except Exception as e:
            task.error = str(e)
            task.status = TaskStatus.FAILED
            self.logger.error(f"Task failed: {task.name} - {e}")
            
            # Retry if applicable
            if task.attempts <= task.retries:
                await self._retry_task(task)
            else:
                await self._fire_callbacks("task_failed", task)
                
        finally:
            if task.id in self._running:
                del self._running[task.id]
                
    async def _call_handler(self, handler: Callable, task: Task) -> Any:
        """Call task handler."""
        if asyncio.iscoroutinefunction(handler):
            return await handler(**task.params)
        else:
            # Run sync handler in executor
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None,
                lambda: handler(**task.params)
            )
            
    async def _retry_task(self, task: Task) -> None:
        """Retry a failed task."""
        self.logger.info(f"Retrying task: {task.name} (attempt {task.attempts + 1})")
        
        await asyncio.sleep(task.retry_delay)
        
        task.status = TaskStatus.QUEUED
        task.error = None
        
        self.enqueue(task)
        
    async def _fire_callbacks(self, event: str, task: Task) -> None:
        """Fire event callbacks."""
        for callback in self._callbacks.get(event, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(task)
                else:
                    callback(task)
            except Exception as e:
                self.logger.error(f"Callback error: {e}")
                
    async def wait_for_task(self, task_id: str, timeout: float = None) -> Task:
        """Wait for a specific task to complete."""
        start = datetime.now()
        
        while True:
            task = self._tasks.get(task_id)
            if not task:
                raise ValueError(f"Task not found: {task_id}")
                
            if task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED, TaskStatus.TIMEOUT]:
                return task
                
            if timeout:
                elapsed = (datetime.now() - start).total_seconds()
                if elapsed >= timeout:
                    raise asyncio.TimeoutError(f"Timeout waiting for task: {task_id}")
                    
            await asyncio.sleep(0.1)
            
    async def wait_for_all(self, timeout: float = None) -> List[Task]:
        """Wait for all tasks to complete."""
        start = datetime.now()
        
        while True:
            pending = [
                t for t in self._tasks.values()
                if t.status in [TaskStatus.PENDING, TaskStatus.QUEUED, TaskStatus.RUNNING]
            ]
            
            if not pending:
                return list(self._tasks.values())
                
            if timeout:
                elapsed = (datetime.now() - start).total_seconds()
                if elapsed >= timeout:
                    raise asyncio.TimeoutError("Timeout waiting for all tasks")
                    
            await asyncio.sleep(0.1)
            
    def clear(self) -> None:
        """Clear all tasks and queue."""
        with self._queue_lock:
            self._queue.clear()
        self._tasks.clear()
        self._completed.clear()
        self.logger.info("Task queue cleared")


# Convenience class for batch task creation
class TaskBatch:
    """Helper for creating task batches."""
    
    def __init__(self, queue: TaskQueue):
        self.queue = queue
        self.tasks: List[Task] = []
        
    def add(
        self,
        name: str,
        handler: str,
        params: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> "TaskBatch":
        """Add task to batch."""
        task = self.queue.create_task(name, handler, params, **kwargs)
        self.tasks.append(task)
        return self
        
    def submit(self) -> int:
        """Submit all tasks in batch."""
        return self.queue.enqueue_many(self.tasks)
