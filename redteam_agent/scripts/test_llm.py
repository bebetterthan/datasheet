"""
Test LLM Provider Connection
=============================

Quick test script to validate LLM provider connection and functionality.

Usage:
    python scripts/test_llm.py --provider local
    python scripts/test_llm.py --provider api --api-url http://localhost:8000/v1
    python scripts/test_llm.py --provider openai --api-key sk-...
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import argparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from agent.llm.provider import create_llm_provider, LocalLLMProvider, APILLMProvider, OpenAIProvider
from agent.utils.config import Config


console = Console()


def test_provider_info(provider):
    """Test getting provider information."""
    console.print("\n[bold cyan]📋 Provider Information:[/bold cyan]")
    
    info = provider.get_info()
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Property", style="dim")
    table.add_column("Value")
    
    for key, value in info.items():
        table.add_row(key, str(value))
    
    console.print(table)
    return True


def test_health_check(provider):
    """Test provider health check."""
    console.print("\n[bold cyan]🏥 Health Check:[/bold cyan]")
    
    try:
        healthy = provider.is_healthy()
        if healthy:
            console.print("✅ Provider is [bold green]healthy[/bold green]")
            return True
        else:
            console.print("⚠️  Provider is [bold yellow]not healthy[/bold yellow]")
            return False
    except Exception as e:
        console.print(f"❌ Health check failed: [bold red]{e}[/bold red]")
        return False


def test_simple_generation(provider):
    """Test simple text generation."""
    console.print("\n[bold cyan]🧪 Testing Simple Generation:[/bold cyan]")
    
    test_prompt = "What is a SQL injection vulnerability? Explain in 2 sentences."
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Generating response...", total=None)
            
            response = provider.generate(
                prompt=test_prompt,
                max_tokens=200,
                temperature=0.7
            )
            
            progress.update(task, completed=True)
        
        console.print(Panel(
            f"[bold]Prompt:[/bold]\n{test_prompt}\n\n[bold]Response:[/bold]\n{response}",
            title="Generation Test",
            border_style="green"
        ))
        return True
        
    except Exception as e:
        console.print(f"❌ Generation failed: [bold red]{e}[/bold red]")
        return False


def test_chat_generation(provider):
    """Test chat-style generation."""
    console.print("\n[bold cyan]💬 Testing Chat Generation:[/bold cyan]")
    
    messages = [
        {"role": "system", "content": "You are a cybersecurity expert."},
        {"role": "user", "content": "What is XSS?"},
    ]
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Generating chat response...", total=None)
            
            response = provider.chat(
                messages=messages,
                max_tokens=200,
                temperature=0.7
            )
            
            progress.update(task, completed=True)
        
        console.print(Panel(
            f"[bold]Messages:[/bold]\n{messages}\n\n[bold]Response:[/bold]\n{response}",
            title="Chat Test",
            border_style="green"
        ))
        return True
        
    except Exception as e:
        console.print(f"❌ Chat failed: [bold red]{e}[/bold red]")
        return False


def test_security_task(provider):
    """Test with security-specific task."""
    console.print("\n[bold cyan]🔒 Testing Security Task:[/bold cyan]")
    
    prompt = """Analyze this HTTP response header:
    
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff

Are there any security concerns?"""
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Analyzing security headers...", total=None)
            
            response = provider.generate(
                prompt=prompt,
                system_prompt="You are a penetration tester analyzing security headers.",
                max_tokens=300,
                temperature=0.5
            )
            
            progress.update(task, completed=True)
        
        console.print(Panel(
            f"[bold]Prompt:[/bold]\n{prompt}\n\n[bold]Analysis:[/bold]\n{response}",
            title="Security Task Test",
            border_style="green"
        ))
        return True
        
    except Exception as e:
        console.print(f"❌ Security task failed: [bold red]{e}[/bold red]")
        return False


def main():
    parser = argparse.ArgumentParser(description="Test LLM Provider")
    parser.add_argument(
        "--provider",
        choices=["local", "api", "openai"],
        default="api",
        help="Provider type to test"
    )
    parser.add_argument("--api-url", help="API URL (for api provider)")
    parser.add_argument("--api-key", help="API key")
    parser.add_argument("--model-name", help="Model name")
    parser.add_argument("--skip-load", action="store_true", help="Skip model loading (for local)")
    
    args = parser.parse_args()
    
    console.print(Panel.fit(
        "[bold cyan]🤖 Red Team Agent - LLM Provider Test[/bold cyan]",
        border_style="cyan"
    ))
    
    # Create config
    config = Config()
    config.set("llm.provider", args.provider)
    
    if args.api_url:
        config.set("llm.api_url", args.api_url)
    if args.api_key:
        config.set("llm.api_key", args.api_key)
    if args.model_name:
        config.set("llm.model_name", args.model_name)
    
    # Create provider
    try:
        console.print(f"\n[bold]Creating {args.provider} provider...[/bold]")
        provider = create_llm_provider(config)
        console.print(f"✅ Provider created: [green]{provider.__class__.__name__}[/green]")
        
        # Load model for local provider
        if isinstance(provider, LocalLLMProvider) and not args.skip_load:
            console.print("\n[bold]Loading model...[/bold]")
            console.print("[yellow]⚠️  This may take a few minutes on first run[/yellow]")
            provider.load()
            console.print("✅ Model loaded successfully!")
        
    except Exception as e:
        console.print(f"\n❌ [bold red]Failed to create provider:[/bold red] {e}")
        return 1
    
    # Run tests
    tests = [
        ("Provider Info", test_provider_info),
        ("Health Check", test_health_check),
        ("Simple Generation", test_simple_generation),
        ("Chat Generation", test_chat_generation),
        ("Security Task", test_security_task),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func(provider)
            results.append((test_name, result))
        except Exception as e:
            console.print(f"\n❌ [bold red]Test '{test_name}' crashed:[/bold red] {e}")
            results.append((test_name, False))
    
    # Summary
    console.print("\n" + "="*60)
    console.print("[bold cyan]📊 Test Summary:[/bold cyan]\n")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Test", style="dim")
    table.add_column("Result", justify="center")
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        style = "green" if result else "red"
        table.add_row(test_name, f"[{style}]{status}[/{style}]")
        if result:
            passed += 1
    
    console.print(table)
    console.print(f"\n[bold]Results: {passed}/{len(results)} tests passed[/bold]")
    
    if passed == len(results):
        console.print("\n[bold green]🎉 All tests passed! Provider is ready to use.[/bold green]")
        return 0
    else:
        console.print("\n[bold yellow]⚠️  Some tests failed. Check the output above.[/bold yellow]")
        return 1


if __name__ == "__main__":
    sys.exit(main())
