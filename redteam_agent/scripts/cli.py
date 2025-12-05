#!/usr/bin/env python3
"""
Red Team Agent CLI Runner (Enhanced)
====================================

Full-featured command-line interface for the Red Team AI Agent.
Supports multiple commands, rich output, and progress tracking.
"""

import argparse
import asyncio
import sys
import os
import json
import signal
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Try to import rich for better output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.syntax import Syntax
    from rich.markdown import Markdown
    from rich.tree import Tree
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None

from agent.core import RedTeamAgent, AgentConfig
from agent.utils import load_config, get_logger
from agent.tools.registry import ToolRegistry
from agent.security import EngagementLoader


# Initialize console
console = Console() if RICH_AVAILABLE else None
logger = get_logger(__name__)


# =============================================================================
# CLI STYLING
# =============================================================================

class CLIStyle:
    """CLI styling utilities."""
    
    BANNER = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     ██████╗ ███████╗██████╗ ████████╗███████╗ █████╗ ███╗   ███╗   ║
║     ██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗████╗ ████║   ║
║     ██████╔╝█████╗  ██║  ██║   ██║   █████╗  ███████║██╔████╔██║   ║
║     ██╔══██╗██╔══╝  ██║  ██║   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║   ║
║     ██║  ██║███████╗██████╔╝   ██║   ███████╗██║  ██║██║ ╚═╝ ██║   ║
║     ╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝   ║
║                                                              ║
║              🔴 AI-Powered Red Team Agent 🔴                 ║
║                        v1.0.0                                ║
╚══════════════════════════════════════════════════════════════╝
"""
    
    MINI_BANNER = "🔴 RedTeam Agent v1.0.0"
    
    @staticmethod
    def print_banner(mini: bool = False):
        """Print the banner."""
        if mini:
            if RICH_AVAILABLE:
                console.print(f"\n[bold red]{CLIStyle.MINI_BANNER}[/bold red]\n")
            else:
                print(f"\n{CLIStyle.MINI_BANNER}\n")
        else:
            if RICH_AVAILABLE:
                console.print(f"[bold red]{CLIStyle.BANNER}[/bold red]")
            else:
                print(CLIStyle.BANNER)
    
    @staticmethod
    def print_success(msg: str):
        """Print success message."""
        if RICH_AVAILABLE:
            console.print(f"[bold green]✓[/bold green] {msg}")
        else:
            print(f"✓ {msg}")
    
    @staticmethod
    def print_error(msg: str):
        """Print error message."""
        if RICH_AVAILABLE:
            console.print(f"[bold red]✗[/bold red] {msg}")
        else:
            print(f"✗ {msg}")
    
    @staticmethod
    def print_warning(msg: str):
        """Print warning message."""
        if RICH_AVAILABLE:
            console.print(f"[bold yellow]⚠[/bold yellow] {msg}")
        else:
            print(f"⚠ {msg}")
    
    @staticmethod
    def print_info(msg: str):
        """Print info message."""
        if RICH_AVAILABLE:
            console.print(f"[bold blue]ℹ[/bold blue] {msg}")
        else:
            print(f"ℹ {msg}")
    
    @staticmethod
    def print_step(step: int, total: int, msg: str):
        """Print step progress."""
        if RICH_AVAILABLE:
            console.print(f"[bold cyan][{step}/{total}][/bold cyan] {msg}")
        else:
            print(f"[{step}/{total}] {msg}")


# =============================================================================
# ARGUMENT PARSING
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="redteam-agent",
        description="AI-Powered Red Team Security Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--version", "-V",
        action="version",
        version="RedTeam Agent v1.0.0"
    )
    
    parser.add_argument(
        "--config", "-c",
        type=str,
        default="configs/agent_config.yaml",
        help="Path to configuration file"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv, -vvv)"
    )
    
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress non-essential output"
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Run command
    run_parser = subparsers.add_parser("run", help="Run a security task")
    run_parser.add_argument("task", type=str, help="Task description")
    run_parser.add_argument("--target", "-t", type=str, help="Target URL or IP")
    run_parser.add_argument("--engagement", "-e", type=str, help="Engagement file")
    run_parser.add_argument("--output", "-o", type=str, help="Output file for report")
    run_parser.add_argument("--format", "-f", choices=["json", "markdown", "html"], default="json")
    run_parser.add_argument("--max-iterations", type=int, default=20)
    run_parser.add_argument("--timeout", type=int, default=600, help="Task timeout in seconds")
    run_parser.add_argument("--dry-run", action="store_true", help="Plan only, don't execute")
    run_parser.add_argument("--workflow", "-w", type=str, help="Use predefined workflow")
    
    # Scan command (shortcut for common scans)
    scan_parser = subparsers.add_parser("scan", help="Quick security scan")
    scan_parser.add_argument("target", type=str, help="Target URL")
    scan_parser.add_argument("--type", "-t", choices=["quick", "full", "api", "payment"], default="quick")
    scan_parser.add_argument("--output", "-o", type=str, help="Output file")
    scan_parser.add_argument("--engagement", "-e", type=str, help="Engagement file")
    
    # Tools command
    tools_parser = subparsers.add_parser("tools", help="Manage tools")
    tools_sub = tools_parser.add_subparsers(dest="tools_command")
    tools_sub.add_parser("list", help="List available tools")
    tools_info = tools_sub.add_parser("info", help="Show tool details")
    tools_info.add_argument("tool_name", type=str, help="Tool name")
    tools_sub.add_parser("test", help="Test all tools")
    
    # Config command
    config_parser = subparsers.add_parser("config", help="Configuration management")
    config_sub = config_parser.add_subparsers(dest="config_command")
    config_sub.add_parser("show", help="Show current configuration")
    config_sub.add_parser("validate", help="Validate configuration")
    config_init = config_sub.add_parser("init", help="Initialize new configuration")
    config_init.add_argument("--path", type=str, default="configs/", help="Config directory")
    
    # Engagement command
    eng_parser = subparsers.add_parser("engagement", help="Engagement management")
    eng_sub = eng_parser.add_subparsers(dest="engagement_command")
    eng_sub.add_parser("validate", help="Validate engagement file")
    eng_sub.add_parser("show", help="Show engagement details")
    eng_create = eng_sub.add_parser("create", help="Create new engagement")
    eng_create.add_argument("--output", "-o", type=str, required=True)
    
    # Interactive command
    interactive_parser = subparsers.add_parser("interactive", help="Interactive mode")
    interactive_parser.add_argument("--engagement", "-e", type=str, help="Engagement file")
    
    # Report command
    report_parser = subparsers.add_parser("report", help="Report management")
    report_sub = report_parser.add_subparsers(dest="report_command")
    report_convert = report_sub.add_parser("convert", help="Convert report format")
    report_convert.add_argument("input", type=str, help="Input file")
    report_convert.add_argument("--format", "-f", choices=["json", "markdown", "html"], required=True)
    report_convert.add_argument("--output", "-o", type=str, help="Output file")
    
    return parser


# =============================================================================
# COMMAND HANDLERS
# =============================================================================

async def cmd_run(args, config):
    """Handle 'run' command."""
    CLIStyle.print_banner(mini=True)
    
    # Load engagement if provided
    engagement = None
    if args.engagement:
        try:
            loader = EngagementLoader()
            engagement = loader.load_engagement(args.engagement)
            CLIStyle.print_success(f"Loaded engagement: {engagement.id}")
        except Exception as e:
            CLIStyle.print_error(f"Failed to load engagement: {e}")
            return 1
    
    # Validate target against engagement
    if engagement and args.target:
        result = engagement.validate_target(args.target)
        if not result['allowed']:
            CLIStyle.print_error(f"Target not in scope: {result['reason']}")
            return 1
    
    # Initialize agent
    CLIStyle.print_info("Initializing agent...")
    
    try:
        agent = RedTeamAgent(
            config_path=args.config if hasattr(args, 'config') else None
        )
        CLIStyle.print_success("Agent initialized")
    except Exception as e:
        CLIStyle.print_error(f"Failed to initialize agent: {e}")
        return 1
    
    # Build task context
    task = args.task
    if args.target:
        task = f"{task}\nTarget: {args.target}"
    
    # Show task info
    if RICH_AVAILABLE:
        console.print(Panel(
            f"[bold]{task}[/bold]",
            title="🎯 Task",
            border_style="cyan"
        ))
    else:
        print(f"\n🎯 Task: {task}\n")
    
    # Dry run - only show plan
    if args.dry_run:
        CLIStyle.print_info("Dry run mode - showing plan only")
        plan = await agent.plan(task)
        
        if RICH_AVAILABLE:
            tree = Tree("📋 Execution Plan")
            for i, step in enumerate(plan.steps, 1):
                tree.add(f"[cyan]Step {i}[/cyan]: {step.tool} - {step.action}")
            console.print(tree)
        else:
            print("\n📋 Execution Plan:")
            for i, step in enumerate(plan.steps, 1):
                print(f"  {i}. {step.tool} - {step.action}")
        
        return 0
    
    # Execute task
    CLIStyle.print_info("Starting execution...")
    
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            main_task = progress.add_task("Running agent...", total=args.max_iterations)
            
            # Callback for progress updates
            def on_step(step_num, step_info):
                progress.update(main_task, advance=1)
                progress.update(main_task, description=f"Step {step_num}: {step_info.get('tool', 'processing')}")
            
            result = await agent.run(
                task,
                max_iterations=args.max_iterations,
                on_step_callback=on_step
            )
    else:
        result = await agent.run(task, max_iterations=args.max_iterations)
    
    # Display results
    print("\n")
    if result.success:
        CLIStyle.print_success("Task completed successfully")
    else:
        CLIStyle.print_warning(f"Task completed with issues: {result.error}")
    
    # Show findings summary
    if result.findings:
        print_findings_summary(result.findings)
    
    # Save report
    if args.output:
        save_report(result, args.output, args.format)
        CLIStyle.print_success(f"Report saved to {args.output}")
    
    return 0 if result.success else 1


async def cmd_scan(args, config):
    """Handle 'scan' command (quick scan shortcut)."""
    CLIStyle.print_banner(mini=True)
    
    # Map scan types to workflows
    workflow_map = {
        "quick": "quick_recon",
        "full": "full_assessment",
        "api": "api_security",
        "payment": "payment_assessment"
    }
    
    workflow_name = workflow_map.get(args.type, "quick_recon")
    
    CLIStyle.print_info(f"Starting {args.type} scan on {args.target}")
    CLIStyle.print_info(f"Using workflow: {workflow_name}")
    
    # Initialize agent
    agent = RedTeamAgent()
    
    # Run workflow
    result = await agent.run_workflow(
        workflow_name,
        target=args.target
    )
    
    # Show results
    if result.success:
        CLIStyle.print_success("Scan completed")
        if result.findings:
            print_findings_summary(result.findings)
    else:
        CLIStyle.print_error(f"Scan failed: {result.error}")
    
    # Save output
    if args.output:
        save_report(result, args.output, "json")
    
    return 0 if result.success else 1


def cmd_tools_list(args, config):
    """List available tools."""
    CLIStyle.print_banner(mini=True)
    
    registry = ToolRegistry()
    registry.auto_discover()
    
    if RICH_AVAILABLE:
        table = Table(title="🔧 Available Tools", show_header=True, header_style="bold cyan")
        table.add_column("Category", style="dim")
        table.add_column("Tool", style="green")
        table.add_column("Description")
        table.add_column("Actions", style="yellow")
        
        # Group by category
        categories: Dict[str, list] = {}
        for name, tool in registry._tools.items():
            cat = getattr(tool, 'category', 'misc')
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(tool)
        
        for category in sorted(categories.keys()):
            for i, tool in enumerate(categories[category]):
                desc = getattr(tool, 'description', '-')[:50]
                actions = ", ".join(getattr(tool, 'actions', [])[:3])
                table.add_row(
                    category if i == 0 else "",
                    tool.name,
                    desc,
                    actions
                )
        
        console.print(table)
        console.print(f"\n[dim]Total: {len(registry._tools)} tools[/dim]")
    else:
        print("\n🔧 Available Tools:\n")
        print("-" * 70)
        for name, tool in sorted(registry._tools.items()):
            print(f"  {name}: {getattr(tool, 'description', '-')}")
        print("-" * 70)
        print(f"Total: {len(registry._tools)} tools")
    
    return 0


def cmd_tools_info(args, config):
    """Show tool information."""
    registry = ToolRegistry()
    registry.auto_discover()
    
    tool = registry.get(args.tool_name)
    if not tool:
        CLIStyle.print_error(f"Tool not found: {args.tool_name}")
        return 1
    
    if RICH_AVAILABLE:
        console.print(Panel(
            f"""
[bold]Name:[/bold] {tool.name}
[bold]Category:[/bold] {getattr(tool, 'category', 'misc')}
[bold]Description:[/bold] {getattr(tool, 'description', 'No description')}

[bold]Actions:[/bold]
{chr(10).join('  • ' + a for a in getattr(tool, 'actions', []))}

[bold]Parameters:[/bold]
{json.dumps(getattr(tool, 'parameters', {}), indent=2)}
            """,
            title=f"🔧 Tool: {args.tool_name}",
            border_style="cyan"
        ))
    else:
        print(f"\n🔧 Tool: {args.tool_name}")
        print(f"Category: {getattr(tool, 'category', 'misc')}")
        print(f"Description: {getattr(tool, 'description', 'No description')}")
        print(f"Actions: {getattr(tool, 'actions', [])}")
    
    return 0


def cmd_config_show(args, config):
    """Show current configuration."""
    CLIStyle.print_banner(mini=True)
    
    if RICH_AVAILABLE:
        syntax = Syntax(
            json.dumps(config.to_dict(), indent=2),
            "json",
            theme="monokai",
            line_numbers=True
        )
        console.print(Panel(syntax, title="📄 Configuration", border_style="green"))
    else:
        print("\n📄 Configuration:")
        print(json.dumps(config.to_dict(), indent=2))
    
    return 0


def cmd_config_validate(args, config):
    """Validate configuration."""
    errors = config.validate()
    
    if errors:
        CLIStyle.print_error("Configuration validation failed:")
        for error in errors:
            print(f"  • {error}")
        return 1
    else:
        CLIStyle.print_success("Configuration is valid")
        return 0


def cmd_engagement_show(args, config):
    """Show engagement details."""
    eng_file = getattr(args, 'engagement', None) or config.get("security.engagement_file")
    
    if not eng_file or not Path(eng_file).exists():
        CLIStyle.print_error("No engagement file found")
        return 1
    
    loader = EngagementLoader()
    engagement = loader.load_engagement(eng_file)
    
    if RICH_AVAILABLE:
        # Build scope tree
        tree = Tree(f"[bold]📋 Engagement: {engagement.id}[/bold]")
        
        info = tree.add("ℹ️ Info")
        info.add(f"Client: {engagement.client_name}")
        info.add(f"Type: {engagement.assessment_type}")
        info.add(f"Active: {engagement.start_date} to {engagement.end_date}")
        info.add(f"Status: {'[green]Active[/green]' if engagement.is_active() else '[red]Inactive[/red]'}")
        
        scope = tree.add("🎯 Scope")
        for domain in engagement.scope.domains[:5]:
            scope.add(f"[green]{domain}[/green]")
        if len(engagement.scope.domains) > 5:
            scope.add(f"[dim]... and {len(engagement.scope.domains) - 5} more[/dim]")
        
        excluded = tree.add("🚫 Excluded")
        for excl in engagement.scope.exclude_domains[:3]:
            excluded.add(f"[red]{excl}[/red]")
        
        console.print(tree)
    else:
        print(f"\n📋 Engagement: {engagement.id}")
        print(f"Client: {engagement.client_name}")
        print(f"Active: {engagement.start_date} to {engagement.end_date}")
        print(f"Scope domains: {engagement.scope.domains}")
    
    return 0


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def print_findings_summary(findings: list):
    """Print findings summary."""
    if not findings:
        return
    
    # Count by severity
    severity_counts = {}
    for f in findings:
        sev = f.get('severity', 'info')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    if RICH_AVAILABLE:
        table = Table(title="📊 Findings Summary", show_header=True)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        
        severity_colors = {
            "critical": "red",
            "high": "orange1",
            "medium": "yellow",
            "low": "blue",
            "info": "dim"
        }
        
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                color = severity_colors.get(sev, "white")
                table.add_row(f"[{color}]{sev.upper()}[/{color}]", str(count))
        
        console.print(table)
    else:
        print("\n📊 Findings Summary:")
        for sev, count in sorted(severity_counts.items()):
            print(f"  {sev.upper()}: {count}")


def save_report(result, output_path: str, format: str):
    """Save report to file."""
    from agent.tools.reporter.report_generator import ReportGenerator, ScanResult
    
    generator = ReportGenerator()
    
    # Convert result to ScanResult
    scan_result = ScanResult(
        target=result.target or "unknown",
        scan_type=result.task_type or "scan",
        start_time=result.start_time,
        end_time=result.end_time,
        findings=result.findings,
        summary=result.summary
    )
    
    # Generate report
    if format == "json":
        content = generator.generate_json(scan_result)
    elif format == "markdown":
        content = generator.generate_markdown(scan_result)
    elif format == "html":
        content = generator.generate_html(scan_result)
    else:
        content = generator.generate_json(scan_result)
    
    # Save to file
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Load config
    config_path = getattr(args, 'config', 'configs/agent_config.yaml')
    config = load_config(config_path)
    
    # Handle no command
    if not args.command:
        CLIStyle.print_banner()
        parser.print_help()
        return 0
    
    # Setup signal handlers
    def signal_handler(sig, frame):
        print("\n")
        CLIStyle.print_warning("Interrupted by user")
        sys.exit(130)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Route to command handler
    try:
        if args.command == "run":
            return asyncio.run(cmd_run(args, config))
        
        elif args.command == "scan":
            return asyncio.run(cmd_scan(args, config))
        
        elif args.command == "tools":
            if args.tools_command == "list" or not args.tools_command:
                return cmd_tools_list(args, config)
            elif args.tools_command == "info":
                return cmd_tools_info(args, config)
        
        elif args.command == "config":
            if args.config_command == "show" or not args.config_command:
                return cmd_config_show(args, config)
            elif args.config_command == "validate":
                return cmd_config_validate(args, config)
        
        elif args.command == "engagement":
            if args.engagement_command == "show" or not args.engagement_command:
                return cmd_engagement_show(args, config)
        
        elif args.command == "interactive":
            # Import and run interactive mode
            from interactive import InteractiveMode
            interactive = InteractiveMode(config, args.engagement if hasattr(args, 'engagement') else None)
            return interactive.run()
        
        else:
            parser.print_help()
            return 0
            
    except Exception as e:
        CLIStyle.print_error(f"Error: {e}")
        if args.verbose > 1:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
