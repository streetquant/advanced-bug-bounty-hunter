#!/usr/bin/env python3
"""Main entry point for the Advanced Bug Bounty Hunter tool."""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .core.config import ConfigManager
from .agents.orchestrator import SecurityTestingOrchestrator
from .utils.logging import setup_logging

app = typer.Typer(
    name="bbhunter",
    help="Advanced AI-Powered Bug Bounty Hunter",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(
        ..., help="Target URL or domain to scan (e.g., https://example.com)"
    ),
    config_file: Optional[Path] = typer.Option(
        None, 
        "--config", 
        "-c",
        help="Path to configuration file (default: config/default.yaml)"
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o", 
        help="Output directory for reports and evidence"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", 
        help="Enable verbose logging"
    ),
    aggressive: bool = typer.Option(
        False, "--aggressive", 
        help="Enable aggressive testing mode"
    ),
    stealth: bool = typer.Option(
        False, "--stealth", 
        help="Enable stealth mode with enhanced evasion"
    ),
) -> None:
    """Start a comprehensive security scan of the target.
    
    This will deploy multiple specialized security testing agents to analyze
    the target application for vulnerabilities using AI-powered techniques.
    """
    
    # Display banner
    banner = Text("Advanced Bug Bounty Hunter", style="bold magenta")
    subtitle = Text("AI-Powered Security Testing Platform", style="dim")
    panel = Panel.fit(
        f"{banner}\n{subtitle}", 
        border_style="magenta",
        padding=(1, 2)
    )
    console.print(panel)
    
    # Setup logging
    log_level = "DEBUG" if verbose else "INFO"
    setup_logging(log_level)
    
    # Load configuration
    config_manager = ConfigManager(config_file)
    config = config_manager.load_config()
    
    # Override config with CLI parameters
    if output_dir:
        config.output.directory = str(output_dir)
    if aggressive:
        config.testing_strategy.aggressiveness = "aggressive"
    if stealth:
        config.stealth.enabled = True
    
    # Validate target URL
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    
    config.target.primary_url = target
    
    # Start the scan
    console.print(f"🎯 Starting scan of: [bold cyan]{target}[/bold cyan]")
    
    try:
        asyncio.run(_run_scan(config))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error during scan: {e}[/red]")
        sys.exit(1)


async def _run_scan(config) -> None:
    """Run the actual security scan."""
    orchestrator = SecurityTestingOrchestrator(config)
    await orchestrator.initialize()
    
    try:
        results = await orchestrator.run_comprehensive_scan()
        
        # Display summary
        console.print("\n" + "="*60)
        console.print("[bold green]Scan Complete![/bold green]")
        console.print(f"Vulnerabilities found: [red]{len(results.vulnerabilities)}[/red]")
        console.print(f"Evidence collected: {len(results.evidence_files)}")
        console.print(f"Report saved to: [cyan]{results.report_path}[/cyan]")
        
    finally:
        await orchestrator.cleanup()


@app.command()
def config(
    init: bool = typer.Option(
        False, "--init", 
        help="Initialize a new configuration file"
    ),
    validate: Optional[Path] = typer.Option(
        None, "--validate", 
        help="Validate an existing configuration file"
    ),
) -> None:
    """Manage configuration files."""
    
    if init:
        config_manager = ConfigManager()
        config_path = config_manager.create_default_config()
        console.print(f"[green]Default configuration created at:[/green] {config_path}")
    
    elif validate:
        config_manager = ConfigManager(validate)
        if config_manager.validate_config():
            console.print(f"[green]Configuration file is valid:[/green] {validate}")
        else:
            console.print(f"[red]Configuration file has errors:[/red] {validate}")
    else:
        console.print("[yellow]Use --init to create a new config or --validate to check an existing one[/yellow]")


@app.command()
def version() -> None:
    """Show version information."""
    from . import __version__, __author__
    
    console.print(f"Advanced Bug Bounty Hunter v{__version__}")
    console.print(f"Author: {__author__}")


def main() -> None:
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()
