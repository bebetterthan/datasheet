#!/usr/bin/env python3
"""
Security Dataset Scraper - Main CLI Interface
Comprehensive tool for collecting security/pentesting datasets for LLM fine-tuning.
"""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from src.utils.config import ScrapingConfig, load_config, save_config, Config
from src.utils.logger import get_logger, create_scraping_tracker
from src.scrapers import SCRAPER_REGISTRY, list_scrapers, get_scraper
from src.processors.format_converter import FormatConverter, AlpacaSample
from src.processors.deduplicator import Deduplicator
from src.processors.quality_checker import QualityChecker
from src.processors.category_classifier import CategoryClassifier
from src.generators.qa_generator import QAGenerator

console = Console()
logger = get_logger(__name__)


# ============================================================================
# CLI Application
# ============================================================================

@click.group()
@click.version_option(version='1.0.0', prog_name='security-dataset-scraper')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--config', '-c', type=click.Path(), default='config/config.yaml', help='Config file path')
@click.pass_context
def cli(ctx, verbose: bool, config: str):
    """
    Security Dataset Scraper - Collect security knowledge for LLM fine-tuning.
    
    This tool scrapes various security resources and converts them into
    training datasets in Alpaca format for fine-tuning Red Team AI agents.
    """
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['config_path'] = config
    
    # Load or create default config
    config_path = Path(config)
    try:
        if config_path.exists():
            full_config = load_config(config_path)
            ctx.obj['full_config'] = full_config
            ctx.obj['config'] = full_config.scraping  # ScrapingConfig
        else:
            ctx.obj['config'] = ScrapingConfig()
            ctx.obj['full_config'] = None
    except Exception as e:
        # Fallback to default config
        ctx.obj['config'] = ScrapingConfig()
        ctx.obj['full_config'] = None
        if verbose:
            console.print(f"[yellow]Warning: Could not load config: {e}[/yellow]")


# ============================================================================
# Scrape Command
# ============================================================================

@cli.command()
@click.option('--source', '-s', multiple=True, help='Specific sources to scrape (can be used multiple times)')
@click.option('--all', 'scrape_all', is_flag=True, help='Scrape all available sources')
@click.option('--limit', '-l', type=int, default=None, help='Limit items per source')
@click.option('--output', '-o', type=click.Path(), default='data/raw', help='Output directory')
@click.option('--resume', is_flag=True, help='Resume from last checkpoint')
@click.option('--dry-run', is_flag=True, help='Show what would be scraped without actually scraping')
@click.option('--proxy', type=str, default=None, help='Proxy URL to use')
@click.pass_context
def scrape(ctx, source: tuple, scrape_all: bool, limit: Optional[int], 
           output: str, resume: bool, dry_run: bool, proxy: Optional[str]):
    """
    Scrape security content from specified sources.
    
    Examples:
    
        security-scraper scrape --source hacktricks --source owasp
        
        security-scraper scrape --all --limit 100
        
        security-scraper scrape -s exploit_db --resume
    """
    config: ScrapingConfig = ctx.obj['config']
    verbose: bool = ctx.obj['verbose']
    
    # Determine sources to scrape
    if scrape_all:
        sources = list_scrapers()
    elif source:
        sources = list(source)
    else:
        console.print("[yellow]No sources specified. Use --source or --all[/yellow]")
        console.print(f"\nAvailable sources: {', '.join(list_scrapers())}")
        return
    
    # Validate sources
    invalid_sources = [s for s in sources if s not in SCRAPER_REGISTRY]
    if invalid_sources:
        console.print(f"[red]Invalid sources: {', '.join(invalid_sources)}[/red]")
        console.print(f"Available: {', '.join(list_scrapers())}")
        return
    
    # Create output directory
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Dry run
    if dry_run:
        _show_scrape_plan(sources, limit, output_path)
        return
    
    # Run scraping
    console.print(Panel.fit(
        f"[bold blue]Security Dataset Scraper[/bold blue]\n"
        f"Sources: {', '.join(sources)}\n"
        f"Output: {output_path}\n"
        f"Resume: {resume}",
        title="Starting Scrape"
    ))
    
    asyncio.run(_run_scrape(sources, limit, output_path, resume, proxy, config, verbose))


async def _run_scrape(sources: List[str], limit: Optional[int], output_path: Path,
                      resume: bool, proxy: Optional[str], config: ScrapingConfig, verbose: bool):
    """Run the scraping process."""
    all_items = []
    
    for source_name in sources:
        scraper_class = get_scraper(source_name)
        if not scraper_class:
            continue
        
        console.print(f"\n[cyan]Scraping {source_name}...[/cyan]")
        
        try:
            async with scraper_class(
                config=config,
                output_dir=output_path / source_name,
                resume=resume,
            ) as scraper:
                # Discover URLs
                urls = await scraper.discover_urls()
                
                if limit:
                    urls = urls[:limit]
                
                console.print(f"  Found {len(urls)} items to scrape")
                
                # Scrape with progress
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    console=console,
                ) as progress:
                    task = progress.add_task(f"Scraping {source_name}", total=len(urls))
                    
                    # Collect items from async generator
                    items = []
                    async for item in scraper.scrape_all(max_pages=limit):
                        items.append(item)
                        progress.advance(task)
                    
                    all_items.extend(items)
                
                console.print(f"  [green]✓ Scraped {len(items)} items from {source_name}[/green]")
        
        except Exception as e:
            console.print(f"  [red]✗ Error scraping {source_name}: {e}[/red]")
            if verbose:
                console.print_exception()
    
    # Save raw data (append to existing if present)
    raw_output = output_path / 'all_scraped.json'
    existing_items = []
    if raw_output.exists():
        try:
            with open(raw_output, 'r', encoding='utf-8') as f:
                existing_items = json.load(f)
            console.print(f"  [dim]Loaded {len(existing_items)} existing items[/dim]")
        except Exception:
            pass
    
    # Merge and deduplicate by URL
    new_items = [item.__dict__ for item in all_items]
    existing_urls = {item.get('url') for item in existing_items}
    unique_new = [item for item in new_items if item.get('url') not in existing_urls]
    
    all_merged = existing_items + unique_new
    
    with open(raw_output, 'w', encoding='utf-8') as f:
        json.dump(all_merged, f, ensure_ascii=False, indent=2, default=str)
    
    console.print(f"\n[bold green]Scraping complete![/bold green]")
    console.print(f"  New items: {len(unique_new)}")
    console.print(f"  Total items: {len(all_merged)}")
    console.print(f"Raw data saved to: {raw_output}")


def _show_scrape_plan(sources: List[str], limit: Optional[int], output_path: Path):
    """Show what would be scraped in dry-run mode."""
    table = Table(title="Scrape Plan (Dry Run)")
    table.add_column("Source", style="cyan")
    table.add_column("Scraper Class", style="green")
    table.add_column("Limit", style="yellow")
    
    for source in sources:
        scraper_class = get_scraper(source)
        table.add_row(
            source,
            scraper_class.__name__ if scraper_class else "N/A",
            str(limit) if limit else "No limit"
        )
    
    console.print(table)
    console.print(f"\nOutput directory: {output_path}")


# ============================================================================
# Process Command
# ============================================================================

@cli.command()
@click.option('--input', '-i', 'input_path', type=click.Path(exists=True), required=True, help='Input file or directory')
@click.option('--output', '-o', type=click.Path(), default='data/processed', help='Output directory')
@click.option('--dedupe/--no-dedupe', default=True, help='Remove duplicates')
@click.option('--quality-check/--no-quality-check', default=True, help='Filter low-quality items')
@click.option('--min-quality', type=float, default=0.5, help='Minimum quality score (0-1)')
@click.pass_context
def process(ctx, input_path: str, output: str, dedupe: bool, quality_check: bool, min_quality: float):
    """
    Process scraped data - clean, deduplicate, and classify.
    
    Examples:
    
        security-scraper process -i data/raw -o data/processed
        
        security-scraper process -i data/raw/all_scraped.json --dedupe --min-quality 0.7
    """
    input_path = Path(input_path)
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    
    console.print(Panel.fit(
        f"[bold blue]Processing Data[/bold blue]\n"
        f"Input: {input_path}\n"
        f"Deduplication: {dedupe}\n"
        f"Quality Check: {quality_check} (min: {min_quality})",
        title="Processing"
    ))
    
    # Load data
    if input_path.is_file():
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    else:
        # Load all JSON files from directory
        data = []
        for json_file in input_path.glob('**/*.json'):
            with open(json_file, 'r', encoding='utf-8') as f:
                data.extend(json.load(f))
    
    console.print(f"Loaded {len(data)} items")
    
    # Initialize processors
    deduplicator = Deduplicator() if dedupe else None
    quality_checker = QualityChecker() if quality_check else None
    classifier = CategoryClassifier()
    
    processed_items = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Processing items", total=len(data))
        
        for item in data:
            progress.advance(task)
            
            # Quality check
            if quality_checker:
                quality_result = quality_checker.check_quality(item.get('content', ''))
                if quality_result.overall_score < min_quality:
                    continue
                item['quality_score'] = quality_result.overall_score
            
            # Classify
            if 'category' not in item or not item['category']:
                classification = classifier.classify(item.get('content', ''), item.get('title', ''))
                item['category'] = classification.category
                item['classification_confidence'] = classification.confidence
            
            processed_items.append(item)
    
    # Deduplicate
    if deduplicator and processed_items:
        console.print("Deduplicating...")
        unique_items = deduplicator.deduplicate([i.get('content', '') for i in processed_items])
        processed_items = [processed_items[i] for i in unique_items]
    
    # Save processed data
    output_file = output_path / 'processed_data.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(processed_items, f, ensure_ascii=False, indent=2)
    
    console.print(f"\n[bold green]Processing complete![/bold green]")
    console.print(f"Input items: {len(data)}")
    console.print(f"Output items: {len(processed_items)}")
    console.print(f"Saved to: {output_file}")


# ============================================================================
# Generate Command
# ============================================================================

@cli.command()
@click.option('--input', '-i', 'input_path', type=click.Path(exists=True), required=True, help='Input processed data')
@click.option('--output', '-o', type=click.Path(), default='data/dataset', help='Output directory')
@click.option('--format', '-f', 'output_format', type=click.Choice(['alpaca', 'sharegpt', 'openai', 'jsonl']), 
              default='alpaca', help='Output format')
@click.option('--split/--no-split', default=True, help='Split into train/val/test')
@click.option('--train-ratio', type=float, default=0.8, help='Training set ratio')
@click.option('--augment/--no-augment', default=False, help='Augment data')
@click.pass_context
def generate(ctx, input_path: str, output: str, output_format: str, 
             split: bool, train_ratio: float, augment: bool):
    """
    Generate training dataset from processed data.
    
    Examples:
    
        security-scraper generate -i data/processed/processed_data.json -f alpaca
        
        security-scraper generate -i data/processed -f sharegpt --augment
    """
    input_path = Path(input_path)
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    
    console.print(Panel.fit(
        f"[bold blue]Generating Dataset[/bold blue]\n"
        f"Format: {output_format}\n"
        f"Split: {split} (train ratio: {train_ratio})\n"
        f"Augmentation: {augment}",
        title="Generation"
    ))
    
    # Load processed data
    if input_path.is_file():
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    else:
        data = []
        for json_file in input_path.glob('**/*.json'):
            with open(json_file, 'r', encoding='utf-8') as f:
                data.extend(json.load(f))
    
    console.print(f"Loaded {len(data)} items")
    
    # Initialize generators
    qa_generator = QAGenerator()
    converter = FormatConverter()
    
    # Generate Q&A pairs
    all_samples = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Generating Q&A pairs", total=len(data))
        
        for item in data:
            progress.advance(task)
            
            # Generate Q&A pairs
            qa_pairs = qa_generator.generate_from_content(
                content=item.get('content', ''),
                title=item.get('title', ''),
                category=item.get('category', ''),
                source=item.get('url', ''),
                code_blocks=item.get('code_blocks'),
            )
            
            for qa in qa_pairs:
                sample = AlpacaSample(
                    instruction=qa.instruction,
                    input=qa.input_context,
                    output=qa.output,
                    category=qa.metadata.get('category', item.get('category', '')),
                    source=qa.metadata.get('source', item.get('url', '')),
                    difficulty=qa.metadata.get('difficulty', 'intermediate'),
                    tags=qa.metadata.get('tags', []),
                )
                all_samples.append(sample)
    
    console.print(f"Generated {len(all_samples)} Q&A pairs")
    
    # Convert samples to dict format
    if output_format == 'alpaca':
        output_data = [s.model_dump() for s in all_samples]
    elif output_format == 'sharegpt':
        output_data = [converter.to_sharegpt(
            instruction=s.instruction,
            output=s.output,
            input_text=s.input,
            source=s.source,
            category=s.category
        ) for s in all_samples]
    elif output_format == 'openai':
        output_data = [converter.to_openai(
            instruction=s.instruction,
            output=s.output,
            input_text=s.input
        ) for s in all_samples]
    else:
        output_data = [s.model_dump() for s in all_samples]
    
    # Split if requested
    if split:
        import random
        random.shuffle(output_data)
        
        train_size = int(len(output_data) * train_ratio)
        val_size = int(len(output_data) * (1 - train_ratio) / 2)
        
        train_data = output_data[:train_size]
        val_data = output_data[train_size:train_size + val_size]
        test_data = output_data[train_size + val_size:]
        
        # Save splits
        for name, split_data in [('train', train_data), ('val', val_data), ('test', test_data)]:
            split_file = output_path / f'{name}.json'
            with open(split_file, 'w', encoding='utf-8') as f:
                json.dump(split_data, f, ensure_ascii=False, indent=2)
            console.print(f"  {name}: {len(split_data)} samples -> {split_file}")
    else:
        output_file = output_path / f'dataset.{output_format}.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)
        console.print(f"Saved to: {output_file}")
    
    console.print(f"\n[bold green]Dataset generation complete![/bold green]")
    console.print(f"Total samples: {len(all_samples)}")


# ============================================================================
# Run Command (Full Pipeline)
# ============================================================================

@cli.command()
@click.option('--sources', '-s', multiple=True, help='Sources to scrape')
@click.option('--all', 'scrape_all', is_flag=True, help='Scrape all sources')
@click.option('--limit', '-l', type=int, default=None, help='Limit items per source')
@click.option('--output', '-o', type=click.Path(), default='data', help='Base output directory')
@click.option('--format', '-f', 'output_format', type=click.Choice(['alpaca', 'sharegpt', 'openai']), 
              default='alpaca', help='Output format')
@click.pass_context
def run(ctx, sources: tuple, scrape_all: bool, limit: Optional[int], output: str, output_format: str):
    """
    Run the full pipeline: scrape, process, and generate.
    
    Examples:
    
        security-scraper run --all --limit 100
        
        security-scraper run -s hacktricks -s owasp -f alpaca
    """
    config: ScrapingConfig = ctx.obj['config']
    output_path = Path(output)
    
    # Determine sources
    if scrape_all:
        source_list = list_scrapers()
    elif sources:
        source_list = list(sources)
    else:
        console.print("[yellow]No sources specified. Use --sources or --all[/yellow]")
        return
    
    console.print(Panel.fit(
        f"[bold blue]Full Pipeline Execution[/bold blue]\n"
        f"Sources: {', '.join(source_list)}\n"
        f"Limit: {limit or 'No limit'}\n"
        f"Format: {output_format}",
        title="Running Pipeline"
    ))
    
    # Step 1: Scrape
    console.print("\n[bold cyan]Step 1: Scraping[/bold cyan]")
    ctx.invoke(scrape, source=sources, scrape_all=scrape_all, limit=limit, 
               output=str(output_path / 'raw'), resume=False, dry_run=False, proxy=None)
    
    # Step 2: Process
    console.print("\n[bold cyan]Step 2: Processing[/bold cyan]")
    ctx.invoke(process, input_path=str(output_path / 'raw'), 
               output=str(output_path / 'processed'), dedupe=True, 
               quality_check=True, min_quality=0.5)
    
    # Step 3: Generate
    console.print("\n[bold cyan]Step 3: Generating Dataset[/bold cyan]")
    ctx.invoke(generate, input_path=str(output_path / 'processed'), 
               output=str(output_path / 'dataset'), output_format=output_format,
               split=True, train_ratio=0.8, augment=False)
    
    console.print("\n[bold green]Pipeline complete![/bold green]")


# ============================================================================
# Stats Command
# ============================================================================

@cli.command()
@click.option('--input', '-i', 'input_path', type=click.Path(exists=True), help='Dataset path')
@click.option('--detailed', is_flag=True, help='Show detailed statistics')
@click.pass_context
def stats(ctx, input_path: Optional[str], detailed: bool):
    """
    Show statistics about the dataset.
    
    Examples:
    
        security-scraper stats -i data/dataset/train.json
        
        security-scraper stats -i data/dataset --detailed
    """
    if not input_path:
        input_path = 'data/dataset'
    
    input_path = Path(input_path)
    
    # Load data
    data = []
    if input_path.is_file():
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    else:
        for json_file in input_path.glob('*.json'):
            with open(json_file, 'r', encoding='utf-8') as f:
                file_data = json.load(f)
                if isinstance(file_data, list):
                    data.extend(file_data)
    
    if not data:
        console.print("[yellow]No data found[/yellow]")
        return
    
    # Calculate stats
    total_samples = len(data)
    
    # Category distribution
    categories = {}
    difficulties = {}
    sources = {}
    
    for item in data:
        cat = item.get('category', 'unknown')
        categories[cat] = categories.get(cat, 0) + 1
        
        diff = item.get('difficulty', 'unknown')
        difficulties[diff] = difficulties.get(diff, 0) + 1
        
        src = item.get('source', 'unknown')
        # Extract domain from source
        if 'http' in str(src):
            import urllib.parse
            parsed = urllib.parse.urlparse(str(src))
            src = parsed.netloc
        sources[src] = sources.get(src, 0) + 1
    
    # Display stats
    console.print(Panel.fit(f"[bold]Dataset Statistics[/bold]\n\nTotal Samples: {total_samples}", title="Overview"))
    
    # Category table
    cat_table = Table(title="Categories")
    cat_table.add_column("Category", style="cyan")
    cat_table.add_column("Count", style="green")
    cat_table.add_column("Percentage", style="yellow")
    
    for cat, count in sorted(categories.items(), key=lambda x: -x[1])[:15]:
        pct = count / total_samples * 100
        cat_table.add_row(cat, str(count), f"{pct:.1f}%")
    
    console.print(cat_table)
    
    # Difficulty table
    diff_table = Table(title="Difficulty Distribution")
    diff_table.add_column("Difficulty", style="cyan")
    diff_table.add_column("Count", style="green")
    diff_table.add_column("Percentage", style="yellow")
    
    for diff, count in sorted(difficulties.items(), key=lambda x: -x[1]):
        pct = count / total_samples * 100
        diff_table.add_row(diff, str(count), f"{pct:.1f}%")
    
    console.print(diff_table)
    
    if detailed:
        # Source table
        src_table = Table(title="Top Sources")
        src_table.add_column("Source", style="cyan")
        src_table.add_column("Count", style="green")
        
        for src, count in sorted(sources.items(), key=lambda x: -x[1])[:10]:
            src_table.add_row(src[:50], str(count))
        
        console.print(src_table)


# ============================================================================
# Validate Command
# ============================================================================

@cli.command()
@click.option('--input', '-i', 'input_path', type=click.Path(exists=True), required=True, help='Dataset to validate')
@click.option('--fix', is_flag=True, help='Attempt to fix issues')
@click.pass_context
def validate(ctx, input_path: str, fix: bool):
    """
    Validate dataset format and quality.
    
    Examples:
    
        security-scraper validate -i data/dataset/train.json
        
        security-scraper validate -i data/dataset/train.json --fix
    """
    input_path = Path(input_path)
    
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    console.print(f"Validating {len(data)} samples...")
    
    issues = []
    valid_count = 0
    fixed_count = 0
    
    required_fields = ['instruction', 'output']
    
    for i, item in enumerate(data):
        item_issues = []
        
        # Check required fields
        for field in required_fields:
            if field not in item or not item[field]:
                item_issues.append(f"Missing or empty '{field}'")
        
        # Check content length
        instruction = item.get('instruction', '')
        output = item.get('output', '')
        
        if len(instruction) < 10:
            item_issues.append("Instruction too short")
        if len(output) < 20:
            item_issues.append("Output too short")
        if len(output) > 8000:
            item_issues.append("Output too long")
        
        if item_issues:
            issues.append((i, item_issues))
            
            if fix:
                # Attempt fixes
                if len(output) > 8000:
                    data[i]['output'] = output[:8000] + "..."
                    fixed_count += 1
        else:
            valid_count += 1
    
    # Display results
    console.print(f"\n[bold]Validation Results[/bold]")
    console.print(f"  Valid samples: [green]{valid_count}[/green]")
    console.print(f"  Issues found: [yellow]{len(issues)}[/yellow]")
    
    if fix:
        console.print(f"  Fixed: [cyan]{fixed_count}[/cyan]")
        
        # Save fixed data
        fixed_path = input_path.with_suffix('.fixed.json')
        with open(fixed_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        console.print(f"  Saved to: {fixed_path}")
    
    if issues and ctx.obj.get('verbose'):
        console.print("\n[bold]Issue Details[/bold]")
        for idx, item_issues in issues[:10]:
            console.print(f"  Sample {idx}: {', '.join(item_issues)}")


# ============================================================================
# List Command
# ============================================================================

@cli.command('list')
def list_sources():
    """
    List all available data sources.
    """
    table = Table(title="Available Sources")
    table.add_column("Name", style="cyan")
    table.add_column("Scraper Class", style="green")
    table.add_column("Description", style="white")
    
    descriptions = {
        'hacktricks': 'HackTricks security documentation',
        'ctf_writeups': 'CTF writeups from CTFTime, 0xdf',
        'exploit_db': 'Exploit Database public exploits',
        'cve': 'CVE details from NVD and GitHub',
        'nuclei_templates': 'Nuclei security templates',
        'payloads': 'PayloadsAllTheThings repository',
        'owasp': 'OWASP CheatSheets, WSTG, Top 10',
    }
    
    for name in list_scrapers():
        scraper_class = get_scraper(name)
        table.add_row(
            name,
            scraper_class.__name__ if scraper_class else 'N/A',
            descriptions.get(name, '')
        )
    
    console.print(table)


# ============================================================================
# Export Command
# ============================================================================

@cli.command()
@click.option('--input', '-i', 'input_path', type=click.Path(exists=True), required=True, help='Input dataset')
@click.option('--output', '-o', type=click.Path(), default='data/exports', help='Output directory')
@click.option('--format', '-f', 'output_format', 
              type=click.Choice(['alpaca', 'sharegpt', 'openai', 'llama_factory', 'axolotl']),
              default='alpaca', help='Export format')
@click.option('--stratify', type=str, default=None, help='Field to stratify split by (e.g., category)')
@click.pass_context
def export(ctx, input_path: str, output: str, output_format: str, stratify: Optional[str]):
    """
    Export dataset to various fine-tuning formats.
    
    Supports: Alpaca, ShareGPT, OpenAI, LLaMA-Factory, Axolotl
    
    Examples:
    
        security-scraper export -i data/dataset/train.json -f axolotl
        
        security-scraper export -i data/dataset -f llama_factory --stratify category
    """
    from src.processors.dataset_exporter import DatasetExporter
    
    input_path = Path(input_path)
    
    # Load data
    if input_path.is_file():
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    else:
        data = []
        for json_file in input_path.glob('*.json'):
            with open(json_file, 'r', encoding='utf-8') as f:
                file_data = json.load(f)
                if isinstance(file_data, list):
                    data.extend(file_data)
    
    console.print(f"Loaded {len(data)} samples")
    
    exporter = DatasetExporter(output_dir=output)
    
    # Export
    output_files = exporter.export(
        samples=data,
        format_name=output_format,
        filename=f"security_dataset_{output_format}",
        split=True,
        stratify_by=stratify,
    )
    
    console.print(f"\n[bold green]Export complete![/bold green]")
    for split_name, filepath in output_files.items():
        console.print(f"  {split_name}: {filepath}")


# ============================================================================
# Analyze Command
# ============================================================================

@cli.command()
@click.option('--input', '-i', 'input_path', type=click.Path(exists=True), required=True, help='Dataset to analyze')
@click.option('--output', '-o', type=click.Path(), default=None, help='Output report file')
@click.option('--format', '-f', 'report_format', type=click.Choice(['markdown', 'json']), default='markdown')
@click.pass_context
def analyze(ctx, input_path: str, output: Optional[str], report_format: str):
    """
    Analyze dataset and generate quality report.
    
    Examples:
    
        security-scraper analyze -i data/dataset/train.json
        
        security-scraper analyze -i data/dataset -o report.md
    """
    from src.utils.analytics import DatasetAnalyzer, analyze_dataset_file
    
    input_path = Path(input_path)
    
    # Load data
    if input_path.is_file():
        with open(input_path, 'r', encoding='utf-8') as f:
            if input_path.suffix == '.jsonl':
                data = [json.loads(line) for line in f]
            else:
                data = json.load(f)
    else:
        data = []
        for json_file in input_path.glob('*.json'):
            with open(json_file, 'r', encoding='utf-8') as f:
                file_data = json.load(f)
                if isinstance(file_data, list):
                    data.extend(file_data)
    
    # Analyze
    analyzer = DatasetAnalyzer()
    analytics = analyzer.analyze(data)
    report = analyzer.generate_report(analytics, report_format)
    
    if output:
        with open(output, 'w', encoding='utf-8') as f:
            f.write(report)
        console.print(f"Report saved to: {output}")
    else:
        console.print(report)


# ============================================================================
# Clean Cache Command
# ============================================================================

@cli.command('clean')
@click.option('--cache', is_flag=True, help='Clear scraper cache')
@click.option('--progress', is_flag=True, help='Clear progress database')
@click.option('--all', 'clean_all', is_flag=True, help='Clear everything')
@click.confirmation_option(prompt='Are you sure you want to clean?')
def clean(cache: bool, progress: bool, clean_all: bool):
    """
    Clean cache and temporary files.
    """
    import shutil
    
    cleaned = []
    
    if cache or clean_all:
        cache_dir = Path('.cache')
        if cache_dir.exists():
            shutil.rmtree(cache_dir)
            cleaned.append('cache')
    
    if progress or clean_all:
        progress_db = Path('data/progress.db')
        if progress_db.exists():
            progress_db.unlink()
            cleaned.append('progress database')
    
    if cleaned:
        console.print(f"[green]Cleaned: {', '.join(cleaned)}[/green]")
    else:
        console.print("[yellow]Nothing to clean. Use --cache, --progress, or --all[/yellow]")


# ============================================================================
# Augment Command
# ============================================================================

@cli.command()
@click.option('--input', '-i', 'input_path', type=click.Path(exists=True), required=True, help='Input dataset')
@click.option('--output', '-o', type=click.Path(), default=None, help='Output file')
@click.option('--multiplier', '-m', type=float, default=2.0, help='Target dataset size multiplier')
@click.option('--types', '-t', multiple=True, 
              type=click.Choice(['paraphrase', 'context_variation', 'difficulty_scaling']),
              help='Augmentation types to apply')
@click.pass_context
def augment(ctx, input_path: str, output: Optional[str], multiplier: float, types: tuple):
    """
    Augment dataset with variations.
    
    Examples:
    
        security-scraper augment -i data/dataset/train.json -m 2.0
        
        security-scraper augment -i train.json -t paraphrase -t context_variation
    """
    from src.processors.data_augmenter import DataAugmenter, AugmentationType
    
    input_path = Path(input_path)
    output_path = Path(output) if output else input_path.with_suffix('.augmented.json')
    
    # Load data
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    console.print(f"Loaded {len(data)} samples")
    console.print(f"Target multiplier: {multiplier}x")
    
    # Determine augmentation types
    aug_types = None
    if types:
        aug_types = [AugmentationType(t) for t in types]
    
    # Augment
    augmenter = DataAugmenter()
    augmented_data = augmenter.augment_dataset(
        samples=data,
        augmentation_types=aug_types,
        target_multiplier=multiplier,
    )
    
    # Save
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(augmented_data, f, ensure_ascii=False, indent=2)
    
    console.print(f"\n[bold green]Augmentation complete![/bold green]")
    console.print(f"Original: {len(data)} samples")
    console.print(f"Augmented: {len(augmented_data)} samples (+{len(augmented_data) - len(data)})")
    console.print(f"Saved to: {output_path}")


# ============================================================================
# Quality Check Command
# ============================================================================

@cli.command('quality')
@click.option('--input', '-i', 'input_path', type=click.Path(exists=True), required=True, help='Dataset to check')
@click.option('--output', '-o', type=click.Path(), default=None, help='Output report file')
@click.option('--fix', is_flag=True, help='Auto-fix issues where possible')
@click.option('--strict', is_flag=True, help='Use strict validation rules')
@click.pass_context
def quality_check(ctx, input_path: str, output: Optional[str], fix: bool, strict: bool):
    """
    Run comprehensive quality check on dataset.
    
    Examples:
    
        security-scraper quality -i data/dataset/train.json
        
        security-scraper quality -i train.json --fix --output quality_report.md
    """
    from src.processors.data_validator import DataValidator, ValidationSeverity
    
    input_path = Path(input_path)
    
    # Load data
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    console.print(f"Checking {len(data)} samples...")
    
    # Configure validator
    validator = DataValidator(
        min_instruction_length=30 if strict else 20,
        min_output_length=100 if strict else 50,
        require_category=strict,
    )
    
    # Validate
    report = validator.validate_dataset(data)
    
    # Display summary
    console.print(Panel.fit(
        f"[bold]Quality Report[/bold]\n\n"
        f"Total Samples: {report.total_samples}\n"
        f"Valid: [green]{report.valid_samples}[/green] ({report.valid_samples/report.total_samples*100:.1f}%)\n"
        f"Invalid: [red]{report.invalid_samples}[/red]\n"
        f"Avg Quality Score: {report.avg_quality_score:.3f}\n"
        f"Errors: {report.total_errors}\n"
        f"Warnings: {report.total_warnings}",
        title="Summary"
    ))
    
    # Issues table
    if report.issues_by_field:
        issues_table = Table(title="Issues by Field")
        issues_table.add_column("Field", style="cyan")
        issues_table.add_column("Count", style="red")
        
        for field, count in sorted(report.issues_by_field.items(), key=lambda x: -x[1]):
            issues_table.add_row(field, str(count))
        
        console.print(issues_table)
    
    # Fix if requested
    if fix:
        fixed_count = 0
        for i, result in enumerate(report.sample_results):
            if not result.is_valid:
                # Simple fixes
                sample = data[i]
                
                # Truncate long outputs
                if len(sample.get('output', '')) > 10000:
                    sample['output'] = sample['output'][:9900] + '\n\n[Truncated]'
                    fixed_count += 1
                
                # Add default category if missing
                if 'category' not in sample:
                    sample['category'] = 'general'
                    fixed_count += 1
        
        if fixed_count > 0:
            fixed_path = input_path.with_suffix('.fixed.json')
            with open(fixed_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            console.print(f"\n[cyan]Fixed {fixed_count} issues -> {fixed_path}[/cyan]")
    
    # Save report if requested
    if output:
        report_content = report.to_markdown()
        with open(output, 'w', encoding='utf-8') as f:
            f.write(report_content)
        console.print(f"\nReport saved to: {output}")


# ============================================================================
# Entry Point
# ============================================================================

def main():
    """Main entry point."""
    try:
        cli(obj={})
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == '__main__':
    main()
