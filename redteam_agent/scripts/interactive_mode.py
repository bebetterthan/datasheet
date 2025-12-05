#!/usr/bin/env python3
"""
Interactive Mode for Red Team Agent
====================================

Multi-turn conversational interface for the agent.
"""

import asyncio
import sys
import os
import json
import readline
import atexit
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Try to import rich
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.markdown import Markdown
    from rich.syntax import Syntax
    from rich.live import Live
    from rich.spinner import Spinner
    from rich.text import Text
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from agent.core import RedTeamAgent
from agent.utils import load_config, get_logger
from agent.security import EngagementLoader

console = Console() if RICH_AVAILABLE else None
logger = get_logger(__name__)


class InteractiveMode:
    """
    Interactive chat-like interface for the Red Team Agent.
    
    Features:
    - Multi-turn conversation
    - Command shortcuts
    - History navigation
    - Context display
    - Real-time output
    """
    
    BANNER = """
╔══════════════════════════════════════════════════════════════╗
║           🔴 RED TEAM AI AGENT - Interactive Mode            ║
╠══════════════════════════════════════════════════════════════╣
║  Commands: /help, /tools, /clear, /history, /exit           ║
║  Type your task or question, then press Enter               ║
╚══════════════════════════════════════════════════════════════╝
"""
    
    HELP_TEXT = """
Available Commands:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  /help, /h           Show this help message
  /tools, /t          List available tools
  /tool <name>        Show tool details
  /scan <url>         Quick scan a target
  /workflow <name>    Run predefined workflow
  /context, /c        Show current context
  /clear              Clear context and history
  /history            Show command history
  /save <file>        Save findings to file
  /load <engagement>  Load engagement file
  /status             Show agent status
  /exit, /quit, /q    Exit interactive mode

Tips:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  • Type a natural language task like "Scan example.com for vulnerabilities"
  • Use ↑/↓ arrows to navigate command history
  • Press Ctrl+C to interrupt current operation
  • Press Ctrl+D to exit
"""
    
    def __init__(self, config=None, engagement_file: str = None):
        """Initialize interactive mode."""
        self.config = config or load_config()
        self.agent: Optional[RedTeamAgent] = None
        self.engagement = None
        self.history: List[str] = []
        self.findings: List[Dict] = []
        self.session_start = datetime.now()
        self.context: Dict[str, Any] = {}
        
        # Setup readline history
        self.history_file = Path.home() / ".redteam_agent_history"
        self._setup_readline()
        
        # Load engagement if provided
        if engagement_file:
            self._load_engagement(engagement_file)
    
    def _setup_readline(self):
        """Setup readline for history and completion."""
        try:
            if self.history_file.exists():
                readline.read_history_file(str(self.history_file))
            readline.set_history_length(1000)
            atexit.register(readline.write_history_file, str(self.history_file))
        except Exception:
            pass
        
        # Setup tab completion
        commands = [
            "/help", "/tools", "/tool", "/scan", "/workflow",
            "/context", "/clear", "/history", "/save", "/load",
            "/status", "/exit", "/quit"
        ]
        
        def completer(text, state):
            options = [c for c in commands if c.startswith(text)]
            if state < len(options):
                return options[state]
            return None
        
        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")
    
    def _load_engagement(self, filepath: str):
        """Load engagement file."""
        try:
            loader = EngagementLoader()
            self.engagement = loader.load_engagement(filepath)
            self._print_success(f"Loaded engagement: {self.engagement.id}")
        except Exception as e:
            self._print_error(f"Failed to load engagement: {e}")
    
    def _print_banner(self):
        """Print the banner."""
        if RICH_AVAILABLE:
            console.print(f"[bold red]{self.BANNER}[/bold red]")
        else:
            print(self.BANNER)
    
    def _print_prompt(self):
        """Print the input prompt."""
        # Build prompt with context info
        scope = ""
        if self.engagement:
            scope = f" [scope: {self.engagement.id}]"
        
        if RICH_AVAILABLE:
            console.print(f"\n[bold green]You{scope}[/bold green] > ", end="")
        else:
            print(f"\nYou{scope} > ", end="")
    
    def _print_success(self, msg: str):
        """Print success message."""
        if RICH_AVAILABLE:
            console.print(f"[bold green]✓[/bold green] {msg}")
        else:
            print(f"✓ {msg}")
    
    def _print_error(self, msg: str):
        """Print error message."""
        if RICH_AVAILABLE:
            console.print(f"[bold red]✗[/bold red] {msg}")
        else:
            print(f"✗ {msg}")
    
    def _print_info(self, msg: str):
        """Print info message."""
        if RICH_AVAILABLE:
            console.print(f"[bold blue]ℹ[/bold blue] {msg}")
        else:
            print(f"ℹ {msg}")
    
    def _print_warning(self, msg: str):
        """Print warning message."""
        if RICH_AVAILABLE:
            console.print(f"[bold yellow]⚠[/bold yellow] {msg}")
        else:
            print(f"⚠ {msg}")
    
    def _print_agent(self, msg: str):
        """Print agent response."""
        if RICH_AVAILABLE:
            console.print(f"\n[bold cyan]Agent[/bold cyan] > {msg}")
        else:
            print(f"\nAgent > {msg}")
    
    def _print_step(self, step: str, status: str = "running"):
        """Print execution step."""
        icons = {
            "running": "⏳",
            "success": "✓",
            "failed": "✗",
            "skipped": "⊘"
        }
        icon = icons.get(status, "•")
        
        if RICH_AVAILABLE:
            colors = {
                "running": "yellow",
                "success": "green",
                "failed": "red",
                "skipped": "dim"
            }
            color = colors.get(status, "white")
            console.print(f"  [{color}]{icon}[/{color}] {step}")
        else:
            print(f"  {icon} {step}")
    
    async def _init_agent(self):
        """Initialize the agent if not already done."""
        if self.agent is None:
            self._print_info("Initializing agent...")
            try:
                self.agent = RedTeamAgent()
                self._print_success("Agent ready")
            except Exception as e:
                self._print_error(f"Failed to initialize agent: {e}")
                return False
        return True
    
    async def _handle_command(self, command: str) -> bool:
        """
        Handle a slash command.
        
        Returns:
            True to continue, False to exit
        """
        parts = command.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else None
        
        if cmd in ["/exit", "/quit", "/q"]:
            self._print_info("Goodbye! 👋")
            return False
        
        elif cmd in ["/help", "/h"]:
            if RICH_AVAILABLE:
                console.print(Markdown(self.HELP_TEXT))
            else:
                print(self.HELP_TEXT)
        
        elif cmd in ["/tools", "/t"]:
            await self._cmd_tools()
        
        elif cmd == "/tool" and arg:
            await self._cmd_tool_info(arg)
        
        elif cmd == "/scan" and arg:
            await self._cmd_scan(arg)
        
        elif cmd == "/workflow" and arg:
            await self._cmd_workflow(arg)
        
        elif cmd in ["/context", "/c"]:
            self._cmd_context()
        
        elif cmd == "/clear":
            self._cmd_clear()
        
        elif cmd == "/history":
            self._cmd_history()
        
        elif cmd == "/save" and arg:
            self._cmd_save(arg)
        
        elif cmd == "/load" and arg:
            self._load_engagement(arg)
        
        elif cmd == "/status":
            self._cmd_status()
        
        else:
            self._print_error(f"Unknown command: {cmd}")
            self._print_info("Type /help for available commands")
        
        return True
    
    async def _cmd_tools(self):
        """List available tools."""
        from agent.tools.registry import ToolRegistry
        
        registry = ToolRegistry()
        registry.auto_discover()
        
        if RICH_AVAILABLE:
            table = Table(title="🔧 Available Tools", show_header=True)
            table.add_column("Tool", style="green")
            table.add_column("Category", style="cyan")
            table.add_column("Description")
            
            for name, tool in sorted(registry._tools.items()):
                table.add_row(
                    name,
                    getattr(tool, 'category', 'misc'),
                    getattr(tool, 'description', '-')[:40]
                )
            
            console.print(table)
        else:
            print("\n🔧 Available Tools:")
            for name, tool in sorted(registry._tools.items()):
                print(f"  • {name}: {getattr(tool, 'description', '-')}")
    
    async def _cmd_tool_info(self, tool_name: str):
        """Show tool information."""
        from agent.tools.registry import ToolRegistry
        
        registry = ToolRegistry()
        registry.auto_discover()
        
        tool = registry.get(tool_name)
        if not tool:
            self._print_error(f"Tool not found: {tool_name}")
            return
        
        if RICH_AVAILABLE:
            info = f"""
**Name:** {tool.name}
**Category:** {getattr(tool, 'category', 'misc')}
**Description:** {getattr(tool, 'description', 'No description')}

**Actions:** {', '.join(getattr(tool, 'actions', ['execute']))}
"""
            console.print(Panel(Markdown(info), title=f"🔧 {tool_name}"))
        else:
            print(f"\n🔧 {tool_name}")
            print(f"Category: {getattr(tool, 'category', 'misc')}")
            print(f"Description: {getattr(tool, 'description', 'No description')}")
    
    async def _cmd_scan(self, target: str):
        """Quick scan a target."""
        if not await self._init_agent():
            return
        
        # Validate target against engagement
        if self.engagement:
            result = self.engagement.validate_target(target)
            if not result['allowed']:
                self._print_error(f"Target not in scope: {result['reason']}")
                return
        
        self._print_agent(f"Starting quick scan of {target}...")
        
        try:
            result = await self.agent.run(f"Perform a quick security reconnaissance on {target}")
            
            if result.success:
                self._print_success("Scan complete")
                self.findings.extend(result.findings or [])
                self._show_findings(result.findings)
            else:
                self._print_error(f"Scan failed: {result.error}")
        except Exception as e:
            self._print_error(f"Error during scan: {e}")
    
    async def _cmd_workflow(self, workflow_name: str):
        """Run a predefined workflow."""
        if not await self._init_agent():
            return
        
        self._print_agent(f"Running workflow: {workflow_name}")
        
        # Get target from context or ask
        target = self.context.get('target')
        if not target:
            if RICH_AVAILABLE:
                target = console.input("[bold]Target URL:[/bold] ")
            else:
                target = input("Target URL: ")
            self.context['target'] = target
        
        try:
            result = await self.agent.run_workflow(workflow_name, target=target)
            
            if result.success:
                self._print_success(f"Workflow {workflow_name} complete")
                self.findings.extend(result.findings or [])
                self._show_findings(result.findings)
            else:
                self._print_error(f"Workflow failed: {result.error}")
        except Exception as e:
            self._print_error(f"Error: {e}")
    
    def _cmd_context(self):
        """Show current context."""
        if RICH_AVAILABLE:
            table = Table(title="📋 Current Context")
            table.add_column("Key", style="cyan")
            table.add_column("Value")
            
            table.add_row("Session Start", str(self.session_start))
            table.add_row("Commands Executed", str(len(self.history)))
            table.add_row("Findings Collected", str(len(self.findings)))
            
            if self.engagement:
                table.add_row("Engagement", self.engagement.id)
                table.add_row("Client", self.engagement.client_name)
            
            for key, value in self.context.items():
                table.add_row(key, str(value)[:50])
            
            console.print(table)
        else:
            print("\n📋 Current Context:")
            print(f"  Session Start: {self.session_start}")
            print(f"  Commands: {len(self.history)}")
            print(f"  Findings: {len(self.findings)}")
            if self.engagement:
                print(f"  Engagement: {self.engagement.id}")
    
    def _cmd_clear(self):
        """Clear context and history."""
        self.context = {}
        self.findings = []
        self._print_success("Context cleared")
    
    def _cmd_history(self):
        """Show command history."""
        if not self.history:
            self._print_info("No history yet")
            return
        
        if RICH_AVAILABLE:
            for i, cmd in enumerate(self.history[-20:], 1):
                console.print(f"[dim]{i:3}[/dim] {cmd}")
        else:
            for i, cmd in enumerate(self.history[-20:], 1):
                print(f"{i:3}. {cmd}")
    
    def _cmd_save(self, filepath: str):
        """Save findings to file."""
        if not self.findings:
            self._print_warning("No findings to save")
            return
        
        try:
            output = {
                "session_start": str(self.session_start),
                "session_end": str(datetime.now()),
                "engagement": self.engagement.id if self.engagement else None,
                "findings": self.findings,
                "context": self.context
            }
            
            with open(filepath, 'w') as f:
                json.dump(output, f, indent=2, default=str)
            
            self._print_success(f"Saved to {filepath}")
        except Exception as e:
            self._print_error(f"Failed to save: {e}")
    
    def _cmd_status(self):
        """Show agent status."""
        if RICH_AVAILABLE:
            status = "🟢 Ready" if self.agent else "🔴 Not initialized"
            engagement = self.engagement.id if self.engagement else "None"
            
            panel_content = f"""
**Agent Status:** {status}
**Engagement:** {engagement}
**Session Duration:** {datetime.now() - self.session_start}
**Findings:** {len(self.findings)}
**Memory Usage:** {self.agent.memory.get_token_count() if self.agent else 0} tokens
"""
            console.print(Panel(Markdown(panel_content), title="📊 Status"))
        else:
            print("\n📊 Status:")
            print(f"  Agent: {'Ready' if self.agent else 'Not initialized'}")
            print(f"  Engagement: {self.engagement.id if self.engagement else 'None'}")
            print(f"  Findings: {len(self.findings)}")
    
    def _show_findings(self, findings: List[Dict]):
        """Display findings."""
        if not findings:
            self._print_info("No findings")
            return
        
        if RICH_AVAILABLE:
            table = Table(title="🔍 Findings")
            table.add_column("Severity", style="bold")
            table.add_column("Type")
            table.add_column("Description")
            
            severity_colors = {
                "critical": "red",
                "high": "orange1",
                "medium": "yellow",
                "low": "blue",
                "info": "dim"
            }
            
            for f in findings[:10]:  # Show first 10
                sev = f.get('severity', 'info')
                color = severity_colors.get(sev, 'white')
                table.add_row(
                    f"[{color}]{sev.upper()}[/{color}]",
                    f.get('type', '-'),
                    f.get('description', '-')[:50]
                )
            
            console.print(table)
            
            if len(findings) > 10:
                console.print(f"[dim]... and {len(findings) - 10} more findings[/dim]")
        else:
            print("\n🔍 Findings:")
            for f in findings[:10]:
                print(f"  [{f.get('severity', 'info').upper()}] {f.get('type', '-')}: {f.get('description', '-')[:50]}")
    
    async def _process_task(self, task: str):
        """Process a natural language task."""
        if not await self._init_agent():
            return
        
        # Add target context if available
        if self.context.get('target') and 'target' not in task.lower():
            task = f"{task}\nTarget: {self.context['target']}"
        
        self._print_agent("Processing your request...")
        
        try:
            # Show thinking animation
            if RICH_AVAILABLE:
                with console.status("[bold cyan]Thinking...[/bold cyan]"):
                    result = await self.agent.run(task)
            else:
                print("Thinking...")
                result = await self.agent.run(task)
            
            # Display results
            if result.success:
                self._print_success("Task completed")
                
                # Show steps executed
                if result.steps:
                    print("\n📋 Steps executed:")
                    for step in result.steps:
                        status = "success" if step.get('success') else "failed"
                        self._print_step(f"{step.get('tool', 'unknown')}: {step.get('action', '')}", status)
                
                # Show findings
                if result.findings:
                    self.findings.extend(result.findings)
                    self._show_findings(result.findings)
                
                # Show agent's response/summary
                if result.summary:
                    if RICH_AVAILABLE:
                        console.print(Panel(result.summary, title="📝 Summary"))
                    else:
                        print(f"\n📝 Summary: {result.summary}")
            else:
                self._print_error(f"Task failed: {result.error}")
                
        except asyncio.CancelledError:
            self._print_warning("Task cancelled")
        except Exception as e:
            self._print_error(f"Error: {e}")
            logger.exception("Task processing error")
    
    def run(self) -> int:
        """Run the interactive mode."""
        self._print_banner()
        
        # Show engagement info if loaded
        if self.engagement:
            self._print_info(f"Engagement: {self.engagement.id}")
            self._print_info(f"Scope: {', '.join(self.engagement.scope.domains[:3])}...")
        
        # Main loop
        while True:
            try:
                self._print_prompt()
                user_input = input().strip()
                
                if not user_input:
                    continue
                
                # Add to history
                self.history.append(user_input)
                
                # Handle commands
                if user_input.startswith("/"):
                    should_continue = asyncio.run(self._handle_command(user_input))
                    if not should_continue:
                        break
                else:
                    # Process as natural language task
                    asyncio.run(self._process_task(user_input))
                    
            except EOFError:
                # Ctrl+D
                print("\n")
                self._print_info("Goodbye! 👋")
                break
            except KeyboardInterrupt:
                # Ctrl+C
                print("\n")
                self._print_warning("Interrupted. Type /exit to quit.")
                continue
            except Exception as e:
                self._print_error(f"Unexpected error: {e}")
                logger.exception("Interactive mode error")
        
        return 0


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Red Team Agent Interactive Mode")
    parser.add_argument("--config", "-c", type=str, help="Config file path")
    parser.add_argument("--engagement", "-e", type=str, help="Engagement file path")
    args = parser.parse_args()
    
    config = load_config(args.config) if args.config else None
    interactive = InteractiveMode(config, args.engagement)
    return interactive.run()


if __name__ == "__main__":
    sys.exit(main())
