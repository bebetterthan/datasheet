"""Core agent engine components."""

from agent.core.agent import RedTeamAgent, AgentState, AgentConfig, TaskResult, StepResult
from agent.core.planner import Planner
from agent.core.executor import Executor
from agent.core.observer import Observer
from agent.core.memory import Memory
from agent.core.reporter import Reporter
from agent.core.workflow import WorkflowEngine, WorkflowStep, WorkflowState
from agent.core.workflow import WorkflowDefinition as WorkflowDef
from agent.core.task_queue import TaskQueue, Task, TaskPriority, TaskStatus, TaskBatch
from agent.core.workflow_loader import (
    WorkflowLoader, 
    WorkflowDefinition, 
    WorkflowParameter,
    WorkflowStepDef,
    WorkflowPhaseDef,
    TemplateRenderer
)

# Aliases
Agent = RedTeamAgent

__all__ = [
    # Agent
    "RedTeamAgent",
    "Agent",
    "AgentState",
    "AgentConfig",
    "TaskResult",
    "StepResult",
    # Core modules
    "Planner",
    "Executor",
    "Observer",
    "Memory",
    "Reporter",
    # Workflow Engine
    "WorkflowEngine",
    "WorkflowDef",
    "WorkflowStep",
    "WorkflowState",
    # Workflow Loader
    "WorkflowLoader",
    "WorkflowDefinition",
    "WorkflowParameter",
    "WorkflowStepDef",
    "WorkflowPhaseDef",
    "TemplateRenderer",
    # Task Queue
    "TaskQueue",
    "Task",
    "TaskPriority",
    "TaskStatus",
    "TaskBatch"
]
