#!/usr/bin/env python3
"""
Red Team Agent Interactive Shell
=================================

Rich interactive interface for the Red Team Agent.
"""

import asyncio
import sys
import os
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.markdown import Markdown
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Prompt, Confirm
    from rich.syntax import Syntax
    from rich.tree import Tree
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    print("Rich library not installed. Run: pip install rich")

from agent.core import Agent, AgentConfig
from agent.utils import setup_logger, load_config
from agent.tools.registry import ToolRegistry


class InteractiveShell:
    """Rich interactive shell for the Red Team Agent."""
    
    def __init__(self, config_path: str = "configs/config.yaml"):
        self.console = Console() if HAS_RICH else None
        self.config_path = config_path
        self.agent = None
        self.history = []
        self.session_start = datetime.now()
        self.running = True
        
    async def initialize(self):
        """Initialize the agent."""
        if self.console:
            self.console.print(Panel.fit(
                "[bold cyan]🤖 Red Team AI Agent[/bold cyan]\n"
                "[dim]Initializing...[/dim]",
                border_style="cyan"
            ))
            
        # Load config
        config = {}
        if Path(self.config_path).exists():
            config = load_config(self.config_path)
            
        # Create agent
        agent_config = AgentConfig(**config)
        self.agent = Agent(config=agent_config)
        
        if self.console:
            self.console.print("[green]✓ Agent initialized[/green]\n")
            
    def show_welcome(self):
        """Display welcome message."""
        if not self.console:
            print("\n=== Red Team AI Agent ===\n")
            return
            
        welcome = """
[bold cyan]Red Team AI Agent[/bold cyan]
[dim]AI-Powered Security Assessment Framework[/dim]

[yellow]Commands:[/yellow]
  [green]help[/green]      - Show available commands
  [green]tools[/green]     - List available tools
  [green]status[/green]    - Show agent status
  [green]history[/green]   - View task history
  [green]clear[/green]     - Clear screen
  [green]exit[/green]      - Exit the shell

[yellow]Usage:[/yellow]
  Just type your task in natural language:
  • "Scan example.com for vulnerabilities"
  • "Check security headers for https://target.com"
  • "Analyze JavaScript for skimmers on checkout page"
        """
        
        self.console.print(Panel(welcome, title="Welcome", border_style="blue"))
        
    def show_tools(self):
        """Display available tools in a table."""
        registry = ToolRegistry()
        registry.auto_discover()
        
        if not self.console:
            print("\nAvailable Tools:")
            for name, tool in registry._tools.items():
                print(f"  - {name}: {getattr(tool, 'description', 'N/A')}")
            return
            
        # Create categorized tree
        tree = Tree("🔧 [bold]Available Tools[/bold]")
        
        categories = {}
        for name, tool in registry._tools.items():
            cat = getattr(tool, 'category', 'misc')
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(tool)
            
        for category, tools in sorted(categories.items()):
            branch = tree.add(f"[cyan]{category.upper()}[/cyan]")
            for tool in tools:
                desc = getattr(tool, 'description', 'No description')
                actions = getattr(tool, 'actions', [])
                tool_branch = branch.add(f"[green]{tool.name}[/green]: {desc}")
                if actions:
                    tool_branch.add(f"[dim]Actions: {', '.join(actions)}[/dim]")
                    
        self.console.print(tree)
        self.console.print(f"\n[dim]Total: {len(registry._tools)} tools[/dim]")
        
    def show_status(self):
        """Display agent status."""
        if not self.agent:
            print("Agent not initialized")
            return
            
        status = self.agent.get_status() if hasattr(self.agent, 'get_status') else {}
        
        if not self.console:
            print(f"\nAgent Status:")
            print(f"  State: {status.get('state', 'ready')}")
            print(f"  Tasks: {len(self.history)}")
            return
            
        table = Table(title="Agent Status", show_header=False)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("State", status.get('state', 'ready'))
        table.add_row("Tasks Completed", str(len(self.history)))
        table.add_row("Session Duration", str(datetime.now() - self.session_start).split('.')[0])
        table.add_row("Memory Items", str(status.get('memory_size', 0)))
        
        self.console.print(table)
        
    def show_history(self):
        """Display task history."""
        if not self.history:
            if self.console:
                self.console.print("[dim]No tasks in history[/dim]")
            else:
                print("No tasks in history")
            return
            
        if not self.console:
            print("\nTask History:")
            for i, h in enumerate(self.history, 1):
                status = "✓" if h.get("success") else "✗"
                print(f"  {i}. [{status}] {h['task'][:50]}...")
            return
            
        table = Table(title="Task History")
        table.add_column("#", style="dim")
        table.add_column("Status", justify="center")
        table.add_column("Task")
        table.add_column("Duration")
        
        for i, h in enumerate(self.history, 1):
            status = "[green]✓[/green]" if h.get("success") else "[red]✗[/red]"
            duration = h.get("duration", "N/A")
            table.add_row(str(i), status, h['task'][:60] + "...", str(duration))
            
        self.console.print(table)
        
    def show_help(self):
        """Display help message."""
        if not self.console:
            print("""
Commands:
  help      - Show this help
  tools     - List available tools
  status    - Show agent status
  history   - View task history
  clear     - Clear screen
  exit      - Exit

Example tasks:
  scan example.com
  check headers https://target.com
  detect skimmers on https://shop.com
            """)
            return
            
        help_text = """
## Commands

| Command | Description |
|---------|-------------|
| `help` | Show this help message |
| `tools` | List available security tools |
| `status` | Show agent status |
| `history` | View completed tasks |
| `clear` | Clear the screen |
| `exit` | Exit the shell |

## Example Tasks

- **Reconnaissance**: `scan example.com for open ports`
- **Security Headers**: `check security headers for https://target.com`
- **Vulnerability Scan**: `run nuclei scan on https://target.com`
- **Skimmer Detection**: `detect Magecart skimmers on https://shop.example.com`
- **Technology Detection**: `identify CMS and frameworks on https://target.com`
- **SSL Analysis**: `analyze SSL configuration for target.com`

## Tips

- Be specific about your target
- Use full URLs when appropriate
- Start with reconnaissance before scanning
        """
        
        self.console.print(Markdown(help_text))
        
    async def process_task(self, task: str):
        """Process a user task."""
        start_time = datetime.now()
        
        if self.console:
            self.console.print(f"\n[bold]📋 Task:[/bold] {task}")
            self.console.print("[dim]─" * 50 + "[/dim]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
                transient=True
            ) as progress:
                task_id = progress.add_task("Processing...", total=None)
                
                try:
                    result = await self.agent.run(task)
                except Exception as e:
                    result = {"status": "error", "error": str(e)}
        else:
            print(f"\nTask: {task}")
            print("Processing...")
            try:
                result = await self.agent.run(task)
            except Exception as e:
                result = {"status": "error", "error": str(e)}
                
        duration = datetime.now() - start_time
        
        # Record in history
        self.history.append({
            "task": task,
            "success": result.get("status") != "error",
            "duration": duration,
            "result": result
        })
        
        # Display results
        self.display_result(result, duration)
        
    def display_result(self, result: dict, duration):
        """Display task result."""
        if not self.console:
            print(f"\nResult: {result.get('status', 'unknown')}")
            if result.get("error"):
                print(f"Error: {result['error']}")
            return
            
        self.console.print("\n[bold]📊 Results:[/bold]")
        self.console.print("[dim]─" * 50 + "[/dim]")
        
        status = result.get("status", "unknown")
        if status == "success":
            self.console.print("[green]✓ Task completed successfully[/green]")
        elif status == "error":
            self.console.print(f"[red]✗ Error: {result.get('error', 'Unknown error')}[/red]")
        else:
            self.console.print(f"[yellow]? Status: {status}[/yellow]")
            
        # Show findings
        findings = result.get("findings", [])
        if findings:
            self.console.print(f"\n[bold]🔍 Findings ({len(findings)}):[/bold]")
            
            table = Table(show_header=True)
            table.add_column("Severity", width=10)
            table.add_column("Title")
            table.add_column("Details", width=40)
            
            severity_styles = {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "green",
                "info": "blue"
            }
            
            for f in findings[:10]:  # Limit to 10
                severity = f.get("severity", "info")
                style = severity_styles.get(severity, "white")
                table.add_row(
                    f"[{style}]{severity.upper()}[/{style}]",
                    f.get("title", "Unknown"),
                    f.get("description", "")[:80]
                )
                
            self.console.print(table)
            
        # Show summary
        summary = result.get("summary", "")
        if summary:
            self.console.print(f"\n[bold]📝 Summary:[/bold]")
            self.console.print(Panel(summary, border_style="dim"))
            
        self.console.print(f"\n[dim]Duration: {duration}[/dim]")
        
    async def run(self):
        """Main shell loop."""
        await self.initialize()
        self.show_welcome()
        
        while self.running:
            try:
                if self.console:
                    user_input = Prompt.ask("\n[bold cyan]🔹[/bold cyan]").strip()
                else:
                    user_input = input("\n> ").strip()
                    
                if not user_input:
                    continue
                    
                # Handle commands
                cmd = user_input.lower()
                
                if cmd in ["exit", "quit", "q"]:
                    if self.console:
                        if Confirm.ask("Are you sure you want to exit?"):
                            self.console.print("\n[bold]👋 Goodbye![/bold]")
                            self.running = False
                    else:
                        self.running = False
                        
                elif cmd == "help":
                    self.show_help()
                    
                elif cmd == "tools":
                    self.show_tools()
                    
                elif cmd == "status":
                    self.show_status()
                    
                elif cmd == "history":
                    self.show_history()
                    
                elif cmd == "clear":
                    if self.console:
                        self.console.clear()
                    else:
                        os.system('cls' if os.name == 'nt' else 'clear')
                    self.show_welcome()
                    
                else:
                    # Treat as a task
                    await self.process_task(user_input)
                    
            except KeyboardInterrupt:
                if self.console:
                    self.console.print("\n[yellow]Interrupted. Type 'exit' to quit.[/yellow]")
                else:
                    print("\nInterrupted. Type 'exit' to quit.")
            except EOFError:
                break
                
        # Cleanup
        if self.agent:
            await self.agent.shutdown()


async def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Red Team Agent Interactive Shell")
    parser.add_argument(
        "--config", "-c",
        type=str,
        default="configs/config.yaml",
        help="Path to configuration file"
    )
    
    args = parser.parse_args()
    
    shell = InteractiveShell(config_path=args.config)
    await shell.run()


if __name__ == "__main__":
    if not HAS_RICH:
        print("Warning: Rich library not installed. Using basic interface.")
        print("Install with: pip install rich")
        
    asyncio.run(main())
