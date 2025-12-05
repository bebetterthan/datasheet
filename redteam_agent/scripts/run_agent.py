#!/usr/bin/env python3
"""
Red Team Agent CLI Runner
=========================

Command-line interface to run the Red Team Agent.
"""

import argparse
import asyncio
import sys
import os
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.core import Agent, AgentConfig
from agent.utils import setup_logger, load_config


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Red Team AI Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Run a single task
    python run_agent.py --task "Scan example.com for vulnerabilities"
    
    # Interactive mode
    python run_agent.py --interactive
    
    # Run with specific config
    python run_agent.py --config configs/custom.yaml --task "..."
    
    # Verbose output
    python run_agent.py -v --task "..."
    
    # Save report
    python run_agent.py --task "..." --output report.json
        """
    )
    
    parser.add_argument(
        "--task", "-t",
        type=str,
        help="Task description for the agent"
    )
    
    parser.add_argument(
        "--target",
        type=str,
        help="Target URL or IP"
    )
    
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Run in interactive mode"
    )
    
    parser.add_argument(
        "--config", "-c",
        type=str,
        default="configs/config.yaml",
        help="Path to configuration file"
    )
    
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file for report (JSON format)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Plan only, don't execute"
    )
    
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=10,
        help="Maximum agent iterations"
    )
    
    parser.add_argument(
        "--model",
        type=str,
        help="Override model path"
    )
    
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="List available tools and exit"
    )
    
    return parser.parse_args()


def list_tools():
    """List all available tools."""
    from agent.tools.registry import ToolRegistry
    
    registry = ToolRegistry()
    registry.auto_discover()
    
    print("\n🔧 Available Tools:\n")
    print("-" * 60)
    
    categories = {}
    for name, tool in registry._tools.items():
        cat = getattr(tool, 'category', 'misc')
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(tool)
        
    for category, tools in sorted(categories.items()):
        print(f"\n📁 {category.upper()}")
        for tool in tools:
            desc = getattr(tool, 'description', 'No description')
            actions = getattr(tool, 'actions', [])
            print(f"   • {tool.name}: {desc}")
            if actions:
                print(f"     Actions: {', '.join(actions)}")
                
    print("\n" + "-" * 60)
    print(f"Total: {len(registry._tools)} tools")


async def run_single_task(agent: Agent, task: str, target: str = None, dry_run: bool = False):
    """Run a single task."""
    print(f"\n🎯 Task: {task}")
    if target:
        print(f"🔗 Target: {target}")
    print("-" * 50)
    
    if dry_run:
        print("\n📋 Planning (dry run)...")
        plan = await agent.plan(task, {"target": target} if target else {})
        print("\nGenerated Plan:")
        for i, step in enumerate(plan.get("steps", []), 1):
            print(f"  {i}. {step.get('action', 'Unknown')}: {step.get('description', '')}")
        return plan
        
    # Full execution
    print("\n⚡ Executing...")
    result = await agent.run(task, {"target": target} if target else {})
    
    return result


async def interactive_mode(agent: Agent):
    """Run in interactive mode."""
    print("\n" + "=" * 60)
    print("🤖 Red Team AI Agent - Interactive Mode")
    print("=" * 60)
    print("\nCommands:")
    print("  /help     - Show help")
    print("  /status   - Show agent status")
    print("  /history  - Show task history")
    print("  /clear    - Clear history")
    print("  /tools    - List available tools")
    print("  /exit     - Exit")
    print("\nEnter your task or command:")
    print("-" * 60)
    
    history = []
    
    while True:
        try:
            user_input = input("\n🔹 You: ").strip()
            
            if not user_input:
                continue
                
            if user_input.startswith("/"):
                cmd = user_input[1:].lower().split()[0]
                
                if cmd in ["exit", "quit", "q"]:
                    print("\n👋 Goodbye!")
                    break
                    
                elif cmd == "help":
                    print("""
Commands:
  /help     - Show this help
  /status   - Show agent status
  /history  - Show task history
  /clear    - Clear history
  /tools    - List available tools
  /exit     - Exit

Just type your task in natural language:
  "Scan example.com for vulnerabilities"
  "Check security headers for https://target.com"
  "Find payment skimmers on https://shop.example.com"
                    """)
                    
                elif cmd == "status":
                    status = agent.get_status()
                    print(f"\n📊 Agent Status:")
                    print(f"   State: {status.get('state', 'unknown')}")
                    print(f"   Tasks completed: {len(history)}")
                    print(f"   Memory items: {status.get('memory_size', 0)}")
                    
                elif cmd == "history":
                    if not history:
                        print("\n📜 No tasks in history")
                    else:
                        print("\n📜 Task History:")
                        for i, h in enumerate(history, 1):
                            status = "✅" if h.get("success") else "❌"
                            print(f"   {i}. {status} {h['task'][:50]}...")
                            
                elif cmd == "clear":
                    history.clear()
                    agent.clear_memory()
                    print("\n🗑️ History cleared")
                    
                elif cmd == "tools":
                    list_tools()
                    
                else:
                    print(f"❓ Unknown command: {cmd}")
                    
            else:
                # It's a task
                print("\n⚡ Processing...")
                
                # Check for target in the task
                target = None
                
                try:
                    result = await agent.run(user_input, {"target": target} if target else {})
                    
                    history.append({
                        "task": user_input,
                        "success": result.get("status") == "success",
                        "result": result
                    })
                    
                    # Display result
                    print("\n" + "=" * 50)
                    print("📋 Result:")
                    print("-" * 50)
                    
                    if result.get("status") == "success":
                        print("✅ Task completed successfully")
                        
                        # Show findings if any
                        findings = result.get("findings", [])
                        if findings:
                            print(f"\n🔍 Findings ({len(findings)}):")
                            for f in findings[:5]:  # Limit display
                                severity = f.get("severity", "info")
                                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
                                print(f"   {emoji} [{severity.upper()}] {f.get('title', 'Unknown')}")
                                
                        # Show summary
                        summary = result.get("summary", "")
                        if summary:
                            print(f"\n📝 Summary:\n   {summary}")
                            
                    else:
                        print(f"❌ Task failed: {result.get('error', 'Unknown error')}")
                        
                except Exception as e:
                    print(f"\n❌ Error: {str(e)}")
                    history.append({
                        "task": user_input,
                        "success": False,
                        "error": str(e)
                    })
                    
        except KeyboardInterrupt:
            print("\n\n⚠️ Interrupted. Type /exit to quit.")
            continue
        except EOFError:
            break
            
    return history


async def main():
    """Main entry point."""
    args = parse_args()
    
    # Setup logging
    log_level = "DEBUG" if args.verbose else "INFO"
    logger = setup_logger("agent", level=log_level)
    
    # List tools and exit
    if args.list_tools:
        list_tools()
        return 0
        
    # Load configuration
    config_path = Path(args.config)
    if config_path.exists():
        config = load_config(str(config_path))
    else:
        logger.warning(f"Config file not found: {config_path}, using defaults")
        config = {}
        
    # Override model if specified
    if args.model:
        config["model_path"] = args.model
        
    # Create agent configuration
    agent_config = AgentConfig(
        max_iterations=args.max_iterations,
        **config
    )
    
    # Initialize agent
    logger.info("Initializing Red Team Agent...")
    agent = Agent(config=agent_config)
    
    try:
        if args.interactive:
            # Interactive mode
            result = await interactive_mode(agent)
            
        elif args.task:
            # Single task mode
            result = await run_single_task(
                agent,
                args.task,
                args.target,
                args.dry_run
            )
            
            # Save report if requested
            if args.output and result:
                output_path = Path(args.output)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(output_path, "w") as f:
                    json.dump(result, f, indent=2, default=str)
                    
                print(f"\n📄 Report saved to: {output_path}")
                
        else:
            print("Error: Either --task or --interactive is required")
            print("Use --help for usage information")
            return 1
            
    except KeyboardInterrupt:
        print("\n\n⚠️ Interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Agent error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    finally:
        # Cleanup
        await agent.shutdown()
        
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
