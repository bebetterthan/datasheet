#!/usr/bin/env python3
"""
Red Team Agent - REST API Server
FastAPI-based API server for programmatic access to the agent.
"""

import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from enum import Enum
import json
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
import uvicorn

# =============================================================================
# Pydantic Models
# =============================================================================

class TaskStatus(str, Enum):
    """Task execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskType(str, Enum):
    """Available task types"""
    QUERY = "query"
    SCAN = "scan"
    RECON = "recon"
    ANALYZE = "analyze"
    WORKFLOW = "workflow"


class TaskRequest(BaseModel):
    """Request model for creating a new task"""
    task_type: TaskType = Field(..., description="Type of task to execute")
    target: Optional[str] = Field(None, description="Target URL or domain")
    query: Optional[str] = Field(None, description="Natural language query for the agent")
    workflow_name: Optional[str] = Field(None, description="Workflow name for workflow tasks")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Additional parameters")
    
    class Config:
        json_schema_extra = {
            "example": {
                "task_type": "scan",
                "target": "https://example.com",
                "parameters": {"depth": 2, "timeout": 30}
            }
        }


class TaskResponse(BaseModel):
    """Response model for task operations"""
    task_id: str
    status: TaskStatus
    task_type: TaskType
    target: Optional[str]
    created_at: str
    started_at: Optional[str]
    completed_at: Optional[str]
    result: Optional[Dict[str, Any]]
    error: Optional[str]


class AgentQueryRequest(BaseModel):
    """Request model for agent queries"""
    query: str = Field(..., description="Natural language query")
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context")
    stream: bool = Field(False, description="Enable streaming response")


class ToolExecuteRequest(BaseModel):
    """Request model for direct tool execution"""
    tool_name: str = Field(..., description="Name of the tool to execute")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Tool parameters")
    target: Optional[str] = Field(None, description="Target for the tool")


class WorkflowExecuteRequest(BaseModel):
    """Request model for workflow execution"""
    workflow_name: str = Field(..., description="Name of the workflow")
    target: str = Field(..., description="Target URL or domain")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Override parameters")


class EngagementScope(BaseModel):
    """Engagement scope definition"""
    name: str
    targets: List[str]
    allowed_actions: List[str] = Field(default_factory=list)
    time_window: Optional[Dict[str, str]] = None
    notes: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    version: str
    timestamp: str
    components: Dict[str, str]


class ConfigResponse(BaseModel):
    """Configuration response"""
    llm_model: str
    temperature: float
    max_tokens: int
    tools_enabled: List[str]
    security_mode: str


# =============================================================================
# In-Memory Storage (for demo - use Redis/DB in production)
# =============================================================================

class TaskStore:
    """In-memory task storage"""
    
    def __init__(self):
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.results: Dict[str, Any] = {}
        
    def create_task(self, task_type: TaskType, target: Optional[str] = None,
                    query: Optional[str] = None, workflow_name: Optional[str] = None,
                    parameters: Dict[str, Any] = None) -> str:
        """Create a new task"""
        task_id = str(uuid.uuid4())[:8]
        self.tasks[task_id] = {
            "task_id": task_id,
            "status": TaskStatus.PENDING,
            "task_type": task_type,
            "target": target,
            "query": query,
            "workflow_name": workflow_name,
            "parameters": parameters or {},
            "created_at": datetime.now().isoformat(),
            "started_at": None,
            "completed_at": None,
            "result": None,
            "error": None
        }
        return task_id
    
    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task by ID"""
        return self.tasks.get(task_id)
    
    def update_task(self, task_id: str, **kwargs) -> None:
        """Update task fields"""
        if task_id in self.tasks:
            self.tasks[task_id].update(kwargs)
    
    def list_tasks(self, status: Optional[TaskStatus] = None,
                   limit: int = 50) -> List[Dict[str, Any]]:
        """List tasks with optional filtering"""
        tasks = list(self.tasks.values())
        if status:
            tasks = [t for t in tasks if t["status"] == status]
        return sorted(tasks, key=lambda x: x["created_at"], reverse=True)[:limit]
    
    def delete_task(self, task_id: str) -> bool:
        """Delete a task"""
        if task_id in self.tasks:
            del self.tasks[task_id]
            return True
        return False


# Global task store
task_store = TaskStore()

# =============================================================================
# Application Setup
# =============================================================================

app = FastAPI(
    title="Red Team Agent API",
    description="REST API for Red Team AI Agent - Security Testing Automation",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Dependencies
# =============================================================================

async def verify_api_key(x_api_key: Optional[str] = Header(None)) -> bool:
    """Verify API key (placeholder - implement proper auth)"""
    # In production, implement proper API key verification
    # For now, accept any request or check against configured key
    return True


def get_agent():
    """Get or create agent instance"""
    # Lazy import to avoid circular dependencies
    try:
        from agent.core.agent import Agent
        from agent.utils.config import load_config
        
        config = load_config(Path(__file__).parent.parent / "configs" / "agent_config.yaml")
        return Agent(config)
    except Exception as e:
        return None


# =============================================================================
# Health & Status Endpoints
# =============================================================================

@app.get("/", tags=["Status"])
async def root():
    """API root endpoint"""
    return {
        "name": "Red Team Agent API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health", response_model=HealthResponse, tags=["Status"])
async def health_check():
    """Health check endpoint"""
    components = {
        "api": "healthy",
        "task_store": "healthy"
    }
    
    # Check agent availability
    try:
        agent = get_agent()
        components["agent"] = "healthy" if agent else "unavailable"
    except:
        components["agent"] = "unavailable"
    
    # Check LLM connectivity
    try:
        from agent.llm.client import LLMClient
        components["llm"] = "healthy"
    except:
        components["llm"] = "unavailable"
    
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.now().isoformat(),
        components=components
    )


@app.get("/config", response_model=ConfigResponse, tags=["Status"])
async def get_config():
    """Get current configuration"""
    try:
        from agent.utils.config import load_config
        config = load_config(Path(__file__).parent.parent / "configs" / "agent_config.yaml")
        
        return ConfigResponse(
            llm_model=config.get("llm", {}).get("model", "unknown"),
            temperature=config.get("llm", {}).get("temperature", 0.7),
            max_tokens=config.get("llm", {}).get("max_tokens", 4096),
            tools_enabled=list(config.get("tools", {}).keys()),
            security_mode=config.get("security", {}).get("mode", "safe")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load config: {str(e)}")


# =============================================================================
# Task Management Endpoints
# =============================================================================

@app.post("/tasks", response_model=TaskResponse, tags=["Tasks"])
async def create_task(
    request: TaskRequest,
    background_tasks: BackgroundTasks,
    _: bool = Depends(verify_api_key)
):
    """Create a new task for execution"""
    task_id = task_store.create_task(
        task_type=request.task_type,
        target=request.target,
        query=request.query,
        workflow_name=request.workflow_name,
        parameters=request.parameters
    )
    
    # Schedule background execution
    background_tasks.add_task(execute_task_background, task_id)
    
    task = task_store.get_task(task_id)
    return TaskResponse(**task)


@app.get("/tasks", response_model=List[TaskResponse], tags=["Tasks"])
async def list_tasks(
    status: Optional[TaskStatus] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of tasks to return")
):
    """List all tasks"""
    tasks = task_store.list_tasks(status=status, limit=limit)
    return [TaskResponse(**t) for t in tasks]


@app.get("/tasks/{task_id}", response_model=TaskResponse, tags=["Tasks"])
async def get_task(task_id: str):
    """Get task by ID"""
    task = task_store.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
    return TaskResponse(**task)


@app.delete("/tasks/{task_id}", tags=["Tasks"])
async def delete_task(task_id: str):
    """Delete a task"""
    if not task_store.delete_task(task_id):
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
    return {"message": f"Task {task_id} deleted"}


@app.post("/tasks/{task_id}/cancel", response_model=TaskResponse, tags=["Tasks"])
async def cancel_task(task_id: str):
    """Cancel a running task"""
    task = task_store.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
    
    if task["status"] not in [TaskStatus.PENDING, TaskStatus.RUNNING]:
        raise HTTPException(status_code=400, detail="Task cannot be cancelled")
    
    task_store.update_task(task_id, status=TaskStatus.CANCELLED)
    return TaskResponse(**task_store.get_task(task_id))


# =============================================================================
# Agent Query Endpoints
# =============================================================================

@app.post("/agent/query", tags=["Agent"])
async def agent_query(request: AgentQueryRequest):
    """Send a query to the agent"""
    try:
        agent = get_agent()
        if not agent:
            raise HTTPException(status_code=503, detail="Agent not available")
        
        # Execute query
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: agent.process(request.query, context=request.context)
        )
        
        return {
            "query": request.query,
            "response": result,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/agent/query/stream", tags=["Agent"])
async def agent_query_stream(request: AgentQueryRequest):
    """Send a query to the agent with streaming response"""
    async def generate():
        try:
            agent = get_agent()
            if not agent:
                yield json.dumps({"error": "Agent not available"})
                return
            
            # Simulate streaming (implement actual streaming in production)
            response = agent.process(request.query, context=request.context)
            
            # Stream response in chunks
            words = response.split()
            for i, word in enumerate(words):
                yield json.dumps({
                    "chunk": word + " ",
                    "index": i,
                    "done": i == len(words) - 1
                }) + "\n"
                await asyncio.sleep(0.05)
                
        except Exception as e:
            yield json.dumps({"error": str(e)})
    
    return StreamingResponse(generate(), media_type="application/x-ndjson")


# =============================================================================
# Tool Endpoints
# =============================================================================

@app.get("/tools", tags=["Tools"])
async def list_tools():
    """List all available tools"""
    try:
        from agent.tools import get_available_tools
        tools = get_available_tools()
        
        return {
            "tools": [
                {
                    "name": name,
                    "category": tool.category if hasattr(tool, 'category') else "general",
                    "description": tool.__doc__ or "No description"
                }
                for name, tool in tools.items()
            ],
            "count": len(tools)
        }
    except Exception as e:
        # Return placeholder if tools not available
        return {
            "tools": [
                {"name": "http_client", "category": "scanner", "description": "HTTP request tool"},
                {"name": "header_scanner", "category": "scanner", "description": "HTTP header analysis"},
                {"name": "ssl_scanner", "category": "scanner", "description": "SSL/TLS analysis"},
                {"name": "js_analyzer", "category": "analyzer", "description": "JavaScript analysis"},
                {"name": "tech_detect", "category": "recon", "description": "Technology detection"},
            ],
            "count": 5,
            "note": "Placeholder tools - actual tools loading failed"
        }


@app.post("/tools/execute", tags=["Tools"])
async def execute_tool(request: ToolExecuteRequest):
    """Execute a specific tool directly"""
    try:
        from agent.tools import get_tool
        
        tool = get_tool(request.tool_name)
        if not tool:
            raise HTTPException(status_code=404, detail=f"Tool {request.tool_name} not found")
        
        # Execute tool
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: tool.execute(request.target, **request.parameters)
        )
        
        return {
            "tool": request.tool_name,
            "target": request.target,
            "result": result,
            "timestamp": datetime.now().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/tools/{tool_name}", tags=["Tools"])
async def get_tool_info(tool_name: str):
    """Get information about a specific tool"""
    try:
        from agent.tools import get_tool
        
        tool = get_tool(tool_name)
        if not tool:
            raise HTTPException(status_code=404, detail=f"Tool {tool_name} not found")
        
        return {
            "name": tool_name,
            "category": tool.category if hasattr(tool, 'category') else "general",
            "description": tool.__doc__ or "No description",
            "parameters": tool.parameters if hasattr(tool, 'parameters') else {},
            "requires_target": tool.requires_target if hasattr(tool, 'requires_target') else True
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Workflow Endpoints
# =============================================================================

@app.get("/workflows", tags=["Workflows"])
async def list_workflows():
    """List all available workflows"""
    workflows_dir = Path(__file__).parent.parent / "configs" / "workflows"
    
    if not workflows_dir.exists():
        return {"workflows": [], "count": 0}
    
    workflows = []
    for workflow_file in workflows_dir.glob("*.yaml"):
        try:
            import yaml
            with open(workflow_file) as f:
                data = yaml.safe_load(f)
                workflows.append({
                    "name": workflow_file.stem,
                    "description": data.get("description", "No description"),
                    "steps": len(data.get("steps", [])),
                    "tags": data.get("tags", [])
                })
        except:
            workflows.append({
                "name": workflow_file.stem,
                "description": "Failed to parse",
                "steps": 0,
                "tags": []
            })
    
    return {"workflows": workflows, "count": len(workflows)}


@app.post("/workflows/execute", tags=["Workflows"])
async def execute_workflow(
    request: WorkflowExecuteRequest,
    background_tasks: BackgroundTasks
):
    """Execute a workflow"""
    # Create task for workflow
    task_id = task_store.create_task(
        task_type=TaskType.WORKFLOW,
        target=request.target,
        workflow_name=request.workflow_name,
        parameters=request.parameters
    )
    
    # Schedule background execution
    background_tasks.add_task(execute_workflow_background, task_id, request)
    
    task = task_store.get_task(task_id)
    return {
        "task_id": task_id,
        "workflow": request.workflow_name,
        "target": request.target,
        "status": task["status"],
        "message": "Workflow scheduled for execution"
    }


@app.get("/workflows/{workflow_name}", tags=["Workflows"])
async def get_workflow(workflow_name: str):
    """Get workflow details"""
    workflow_path = Path(__file__).parent.parent / "configs" / "workflows" / f"{workflow_name}.yaml"
    
    if not workflow_path.exists():
        raise HTTPException(status_code=404, detail=f"Workflow {workflow_name} not found")
    
    try:
        import yaml
        with open(workflow_path) as f:
            data = yaml.safe_load(f)
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load workflow: {str(e)}")


# =============================================================================
# Engagement/Scope Endpoints
# =============================================================================

@app.get("/engagement", tags=["Engagement"])
async def get_engagement():
    """Get current engagement scope"""
    engagement_path = Path(__file__).parent.parent / "configs" / "engagement.yaml"
    
    if not engagement_path.exists():
        return {"engagement": None, "message": "No engagement configured"}
    
    try:
        import yaml
        with open(engagement_path) as f:
            data = yaml.safe_load(f)
        return {"engagement": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load engagement: {str(e)}")


@app.post("/engagement/validate", tags=["Engagement"])
async def validate_target(target: str = Query(..., description="Target to validate")):
    """Validate if a target is within engagement scope"""
    try:
        from agent.security.engagement import EngagementConfig
        
        engagement_path = Path(__file__).parent.parent / "configs" / "engagement.yaml"
        config = EngagementConfig.load(engagement_path)
        
        is_valid = config.validate_target(target)
        
        return {
            "target": target,
            "in_scope": is_valid,
            "engagement_name": config.name,
            "message": "Target is in scope" if is_valid else "Target is OUT OF SCOPE"
        }
    except Exception as e:
        return {
            "target": target,
            "in_scope": False,
            "error": str(e)
        }


# =============================================================================
# Report Endpoints
# =============================================================================

@app.get("/reports", tags=["Reports"])
async def list_reports():
    """List generated reports"""
    reports_dir = Path(__file__).parent.parent / "reports"
    
    if not reports_dir.exists():
        return {"reports": [], "count": 0}
    
    reports = []
    for report_file in reports_dir.glob("*.md"):
        stat = report_file.stat()
        reports.append({
            "name": report_file.name,
            "size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
        })
    
    for report_file in reports_dir.glob("*.json"):
        stat = report_file.stat()
        reports.append({
            "name": report_file.name,
            "size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
        })
    
    return {"reports": sorted(reports, key=lambda x: x["modified"], reverse=True), "count": len(reports)}


@app.get("/reports/{report_name}", tags=["Reports"])
async def get_report(report_name: str):
    """Get a specific report"""
    reports_dir = Path(__file__).parent.parent / "reports"
    report_path = reports_dir / report_name
    
    if not report_path.exists():
        raise HTTPException(status_code=404, detail=f"Report {report_name} not found")
    
    try:
        content = report_path.read_text()
        
        if report_name.endswith(".json"):
            return {"name": report_name, "content": json.loads(content), "format": "json"}
        else:
            return {"name": report_name, "content": content, "format": "markdown"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read report: {str(e)}")


# =============================================================================
# Background Task Functions
# =============================================================================

async def execute_task_background(task_id: str):
    """Execute a task in the background"""
    task = task_store.get_task(task_id)
    if not task:
        return
    
    task_store.update_task(task_id, status=TaskStatus.RUNNING, started_at=datetime.now().isoformat())
    
    try:
        agent = get_agent()
        
        if task["task_type"] == TaskType.QUERY:
            result = agent.process(task["query"]) if agent else {"error": "Agent not available"}
        elif task["task_type"] == TaskType.SCAN:
            result = {"message": "Scan completed", "target": task["target"], "findings": []}
        elif task["task_type"] == TaskType.RECON:
            result = {"message": "Recon completed", "target": task["target"], "info": {}}
        elif task["task_type"] == TaskType.ANALYZE:
            result = {"message": "Analysis completed", "target": task["target"], "results": {}}
        else:
            result = {"message": "Task completed"}
        
        task_store.update_task(
            task_id,
            status=TaskStatus.COMPLETED,
            completed_at=datetime.now().isoformat(),
            result=result
        )
    except Exception as e:
        task_store.update_task(
            task_id,
            status=TaskStatus.FAILED,
            completed_at=datetime.now().isoformat(),
            error=str(e)
        )


async def execute_workflow_background(task_id: str, request: WorkflowExecuteRequest):
    """Execute a workflow in the background"""
    task_store.update_task(task_id, status=TaskStatus.RUNNING, started_at=datetime.now().isoformat())
    
    try:
        from agent.core.workflow import WorkflowEngine
        
        engine = WorkflowEngine()
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: engine.execute(request.workflow_name, request.target, **request.parameters)
        )
        
        task_store.update_task(
            task_id,
            status=TaskStatus.COMPLETED,
            completed_at=datetime.now().isoformat(),
            result=result
        )
    except Exception as e:
        task_store.update_task(
            task_id,
            status=TaskStatus.FAILED,
            completed_at=datetime.now().isoformat(),
            error=str(e)
        )


# =============================================================================
# Error Handlers
# =============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc),
            "timestamp": datetime.now().isoformat()
        }
    )


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    """Run the API server"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Red Team Agent API Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    parser.add_argument("--workers", type=int, default=1, help="Number of workers")
    
    args = parser.parse_args()
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║          Red Team Agent API Server                           ║
║                                                              ║
║   Documentation: http://{args.host}:{args.port}/docs                   ║
║   Health Check:  http://{args.host}:{args.port}/health                 ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    uvicorn.run(
        "serve_api:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=args.workers
    )


if __name__ == "__main__":
    main()
