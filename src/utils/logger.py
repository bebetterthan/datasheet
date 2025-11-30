"""
Logging module with rich formatting support.
Provides beautiful console output with progress tracking.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
    MofNCompleteColumn,
)
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme

# Custom theme for security-related output
SECURITY_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "critical": "bold white on red",
    "source": "magenta",
    "url": "blue underline",
    "count": "bold cyan",
    "category": "green",
    "progress": "cyan",
})

# Global console instance
console = Console(theme=SECURITY_THEME)

# Logger instances cache
_loggers: dict = {}


class SecurityDatasetFormatter(logging.Formatter):
    """Custom formatter for security dataset scraper logs."""
    
    def __init__(self):
        super().__init__()
        self.datefmt = "%Y-%m-%d %H:%M:%S"
    
    def format(self, record: logging.LogRecord) -> str:
        # Add custom attributes if not present
        if not hasattr(record, 'source'):
            record.source = 'main'
        if not hasattr(record, 'url'):
            record.url = ''
        
        return super().format(record)


def setup_logger(
    name: str = "security_dataset",
    level: Union[int, str] = logging.INFO,
    log_file: Optional[Union[str, Path]] = None,
    rich_output: bool = True,
) -> logging.Logger:
    """
    Set up a logger with rich formatting and optional file output.
    
    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        rich_output: Whether to use rich formatting for console output
        
    Returns:
        Configured logger instance
    """
    # Convert string level to int if necessary
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    if rich_output:
        # Rich console handler with beautiful formatting
        rich_handler = RichHandler(
            console=console,
            show_time=True,
            show_level=True,
            show_path=False,
            rich_tracebacks=True,
            tracebacks_show_locals=True,
            markup=True,
        )
        rich_handler.setLevel(level)
        logger.addHandler(rich_handler)
    else:
        # Standard console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(SecurityDatasetFormatter())
        logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_path, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)  # Always log everything to file
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(file_handler)
    
    # Cache the logger
    _loggers[name] = logger
    
    return logger


def get_logger(name: str = "security_dataset") -> logging.Logger:
    """
    Get an existing logger or create a new one.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    if name in _loggers:
        return _loggers[name]
    return setup_logger(name)


def create_progress_bar(
    description: str = "Processing",
    total: Optional[int] = None,
    transient: bool = False,
) -> Progress:
    """
    Create a rich progress bar for tracking scraping progress.
    
    Args:
        description: Description text for the progress bar
        total: Total number of items (None for indeterminate)
        transient: Whether to remove progress bar when complete
        
    Returns:
        Rich Progress instance
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=transient,
    )


def print_header(title: str, subtitle: Optional[str] = None) -> None:
    """Print a styled header panel."""
    content = Text(title, style="bold cyan")
    if subtitle:
        content.append(f"\n{subtitle}", style="dim")
    
    panel = Panel(
        content,
        title="🔐 Security Dataset Scraper",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)


def print_stats_table(stats: dict, title: str = "Scraping Statistics") -> None:
    """Print a statistics table with rich formatting."""
    table = Table(title=title, show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="green", justify="right")
    
    for key, value in stats.items():
        # Format the key nicely
        formatted_key = key.replace('_', ' ').title()
        
        # Format the value based on type
        if isinstance(value, float):
            formatted_value = f"{value:.2f}"
        elif isinstance(value, int) and value > 1000:
            formatted_value = f"{value:,}"
        else:
            formatted_value = str(value)
        
        table.add_row(formatted_key, formatted_value)
    
    console.print(table)


def print_source_summary(sources: dict) -> None:
    """Print a summary table of all data sources and their status."""
    table = Table(title="📊 Data Sources", show_header=True, header_style="bold magenta")
    table.add_column("Source", style="cyan", no_wrap=True)
    table.add_column("Status", style="green")
    table.add_column("Items", justify="right")
    table.add_column("Errors", justify="right", style="red")
    
    for source_name, source_data in sources.items():
        status = "✅ Complete" if source_data.get('completed', False) else "⏳ Pending"
        items = str(source_data.get('items', 0))
        errors = str(source_data.get('errors', 0))
        
        table.add_row(source_name, status, items, errors)
    
    console.print(table)


def print_category_breakdown(categories: dict) -> None:
    """Print a breakdown of content by category."""
    table = Table(title="📁 Category Breakdown", show_header=True, header_style="bold green")
    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Count", justify="right", style="green")
    table.add_column("Percentage", justify="right", style="yellow")
    
    total = sum(categories.values())
    
    for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total * 100) if total > 0 else 0
        table.add_row(category, str(count), f"{percentage:.1f}%")
    
    console.print(table)


def print_error_summary(errors: list) -> None:
    """Print a summary of errors encountered during scraping."""
    if not errors:
        console.print("[success]✅ No errors encountered![/success]")
        return
    
    table = Table(title="❌ Error Summary", show_header=True, header_style="bold red")
    table.add_column("Source", style="cyan", no_wrap=True)
    table.add_column("URL", style="blue", max_width=50)
    table.add_column("Error", style="red", max_width=40)
    
    for error in errors[:20]:  # Show only first 20 errors
        table.add_row(
            error.get('source', 'Unknown'),
            error.get('url', 'N/A')[:50],
            error.get('message', 'Unknown error')[:40]
        )
    
    if len(errors) > 20:
        console.print(f"[dim]... and {len(errors) - 20} more errors[/dim]")
    
    console.print(table)


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[success]✅ {message}[/success]")


def print_warning(message: str) -> None:
    """Print a warning message."""
    console.print(f"[warning]⚠️ {message}[/warning]")


def print_error(message: str) -> None:
    """Print an error message."""
    console.print(f"[error]❌ {message}[/error]")


def print_info(message: str) -> None:
    """Print an info message."""
    console.print(f"[info]ℹ️ {message}[/info]")


class ScrapingProgressTracker:
    """Context manager for tracking scraping progress with rich output."""
    
    def __init__(
        self,
        source_name: str,
        total_urls: Optional[int] = None,
        description: Optional[str] = None,
    ):
        self.source_name = source_name
        self.total_urls = total_urls
        self.description = description or f"Scraping {source_name}"
        self.progress: Optional[Progress] = None
        self.task_id = None
        self.success_count = 0
        self.error_count = 0
        self.start_time: Optional[datetime] = None
    
    def __enter__(self):
        self.start_time = datetime.now()
        self.progress = create_progress_bar(self.description)
        self.progress.start()
        self.task_id = self.progress.add_task(
            self.description,
            total=self.total_urls
        )
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.progress:
            self.progress.stop()
        
        # Print summary
        elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        print_stats_table({
            "Source": self.source_name,
            "Successful": self.success_count,
            "Errors": self.error_count,
            "Total Processed": self.success_count + self.error_count,
            "Duration (seconds)": round(elapsed, 2),
            "Rate (items/sec)": round((self.success_count + self.error_count) / elapsed, 2) if elapsed > 0 else 0,
        })
        
        return False
    
    def advance(self, success: bool = True, message: str = "") -> None:
        """Advance the progress bar by one step."""
        if success:
            self.success_count += 1
        else:
            self.error_count += 1
        
        if self.progress and self.task_id is not None:
            self.progress.advance(self.task_id)
    
    def update_total(self, total: int) -> None:
        """Update the total count for the progress bar."""
        self.total_urls = total
        if self.progress and self.task_id is not None:
            self.progress.update(self.task_id, total=total)
    
    def set_description(self, description: str) -> None:
        """Update the progress description."""
        if self.progress and self.task_id is not None:
            self.progress.update(self.task_id, description=description)


def create_scraping_tracker(
    source_name: str,
    total_urls: Optional[int] = None,
    description: Optional[str] = None,
) -> ScrapingProgressTracker:
    """
    Create a scraping progress tracker.
    
    Args:
        source_name: Name of the source being scraped
        total_urls: Total number of URLs to scrape (optional)
        description: Description for the progress bar
        
    Returns:
        ScrapingProgressTracker instance
    """
    return ScrapingProgressTracker(
        source_name=source_name,
        total_urls=total_urls,
        description=description,
    )
