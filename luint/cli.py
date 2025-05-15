"""
Command-line interface for LUINT.
Handles argument parsing and command execution.
"""
import os
import sys
import time
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
import yaml

from luint.utils.logger import setup_logger, get_logger
from luint.core.scanner import Scanner
from luint.utils.api_key_manager import APIKeyManager
from luint.config import load_config
from luint.constants import BANNER, VERSION_INFO


# Initialize console for rich output
console = Console()
logger = get_logger()


def display_banner():
    """Display the ASCII art banner and version information."""
    console.print(Panel.fit(BANNER, border_style="cyan", padding=(1, 2)))
    console.print(VERSION_INFO, style="bold green")
    console.print("\n")


def validate_target(ctx, param, value):
    """Validate the target parameter to ensure it's a domain or IP."""
    if not value:
        return value
    # Simple validation - could be expanded with regex for proper domain/IP validation
    if not any(c.isalnum() for c in value):
        raise click.BadParameter("Target must be a valid domain or IP address")
    return value


@click.group(help="LUINT - A comprehensive modular OSINT tool for network reconnaissance and security analysis.")
@click.version_option(version="1.0.0")
def cli():
    """Main command group for LUINT."""
    setup_logger()
    display_banner()


@cli.command(help="Scan a target domain or IP")
@click.argument('target', callback=validate_target, required=True)
@click.option('--output', '-o', help='Output file path for results')
@click.option('--format', '-f', type=click.Choice(['json', 'csv', 'txt']), default='json', 
              help='Output format (default: json)')
@click.option('--module', '-m', multiple=True, 
              help='Specify modules to run (can be used multiple times)')
@click.option('--all', '-a', is_flag=True, help='Run all modules')
@click.option('--config', '-c', help='Path to custom configuration file')
@click.option('--proxy', '-p', help='Proxy to use (format: http://user:pass@host:port)')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--quiet', '-q', is_flag=True, help='Suppress all output except final results')
@click.option('--no-cache', is_flag=True, help='Disable caching of results')
@click.option('--recursive', '-r', is_flag=True, help='Enable recursive scanning')
@click.option('--depth', '-d', type=int, default=1, help='Depth level for recursive scanning (default: 1)')
def scan(target, output, format, module, all, config, proxy, verbose, quiet, no_cache, recursive, depth):
    """Scan a target using specified modules."""
    try:
        # Load configuration
        config_path = config if config else os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config.yaml')
        config_data = load_config(config_path)
        
        # Setup API keys
        api_key_manager = APIKeyManager(config_data.get('api_keys', {}))
        
        # Create scanner instance
        scanner = Scanner(
            target=target,
            modules=list(module) if module and not all else None,
            run_all=all,
            config=config_data,
            api_key_manager=api_key_manager,
            proxy=proxy,
            verbose=verbose,
            quiet=quiet,
            use_cache=not no_cache,
            recursive=recursive,
            depth=depth,
            output_format=format,
            output_file=output
        )
        
        # Start scanning
        if not quiet:
            console.print(f"[bold green]Starting scan on target:[/bold green] [bold cyan]{target}[/bold cyan]")
        
        start_time = time.time()
        results = scanner.run()
        end_time = time.time()
        
        if not quiet:
            # Display summary
            console.print(f"\n[bold green]Scan completed in {end_time - start_time:.2f} seconds[/bold green]")
            
            # Display results summary table
            summary_table = Table(title="Scan Results Summary", box=box.ROUNDED)
            summary_table.add_column("Module", style="cyan")
            summary_table.add_column("Status", style="green")
            summary_table.add_column("Findings", style="yellow")
            
            for module_name, module_results in results.items():
                findings_count = len(module_results) if isinstance(module_results, list) else "N/A"
                summary_table.add_row(
                    module_name,
                    "✓ Completed" if module_results else "⚠ No findings",
                    str(findings_count)
                )
            
            console.print(summary_table)
            
            if output:
                console.print(f"[bold green]Results saved to:[/bold green] [bold cyan]{output}[/bold cyan]")
        
        return results
        
    except Exception as e:
        logger.error(f"Error during scanning: {str(e)}", exc_info=True)
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


@cli.command(help="List available modules")
@click.option('--detailed', '-d', is_flag=True, help='Show detailed information for each module')
@click.option('--module', '-m', help='Show detailed information for a specific module')
def modules(detailed, module):
    """List all available modules and their descriptions."""
    from luint.core.plugin_manager import PluginManager
    from rich.panel import Panel
    
    plugin_manager = PluginManager()
    available_modules = plugin_manager.list_modules()
    
    if not available_modules:
        console.print("[yellow]No modules found.[/yellow]")
        return
    
    # If a specific module is requested
    if module:
        # Find the module
        module_info = None
        for m in available_modules:
            if m['name'] == module:
                module_info = m
                break
        
        if not module_info:
            console.print(f"[red]Module '{module}' not found.[/red]")
            return
        
        # Display detailed information for this module
        console.print(Panel(f"[bold cyan]{module_info['name']}[/bold cyan] Module", subtitle=f"Category: {module_info.get('category', 'Uncategorized')}"))
        console.print("\n[bold]Description:[/bold]")
        console.print(f"  {module_info.get('description', 'No description available')}")
        
        if module_info.get('detailed_description'):
            console.print("\n[bold]Details:[/bold]")
            console.print(f"  {module_info['detailed_description']}")
        
        # Show capabilities
        capabilities = module_info.get('capabilities', [])
        if capabilities:
            console.print("\n[bold]Capabilities:[/bold]")
            cap_table = Table(box=box.SIMPLE)
            cap_table.add_column("Function", style="cyan")
            cap_table.add_column("Description", style="green")
            
            for cap in capabilities:
                cap_table.add_row(
                    cap['name'],
                    cap.get('description', 'No description')
                )
            
            console.print(cap_table)
        
        # Show example usage
        console.print("\n[bold]Example Usage:[/bold]")
        example = f"luint scan example.com --module {module_info['name']}"
        console.print(f"  [cyan]{example}[/cyan]")
        
        return
    
    # Create and display modules table
    modules_table = Table(title="Available Modules", box=box.ROUNDED)
    modules_table.add_column("Module", style="cyan")
    modules_table.add_column("Description", style="green")
    modules_table.add_column("Category", style="yellow")
    modules_table.add_column("Capabilities", style="magenta")
    
    for module_info in available_modules:
        modules_table.add_row(
            module_info.get('name', 'Unknown'),
            module_info.get('description', 'No description available'),
            module_info.get('category', 'Uncategorized'),
            str(len(module_info.get('capabilities', [])))
        )
    
    console.print(modules_table)
    
    # If detailed info is requested, show capabilities summary
    if detailed:
        console.print("\n[bold]Module Details:[/bold]\n")
        
        for module_info in available_modules:
            module_panel = Panel(
                f"[bold]{module_info.get('description', 'No description')}[/bold]\n\n" +
                f"{module_info.get('detailed_description', '')}\n\n" +
                f"[italic]Capabilities: {len(module_info.get('capabilities', []))} functions[/italic]",
                title=f"[cyan]{module_info['name']}[/cyan]",
                subtitle=f"Category: {module_info.get('category', 'Uncategorized')}",
                border_style="blue"
            )
            console.print(module_panel)
    
    # Display help footer
    console.print("\n[bold]For detailed information on a specific module:[/bold]")
    console.print("  [cyan]luint modules -m <module_name>[/cyan]")


@cli.command(help="Check and verify API keys configuration")
def check_api_keys():
    """Check if API keys are properly configured."""
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config.yaml')
    config_data = load_config(config_path)
    
    api_key_manager = APIKeyManager(config_data.get('api_keys', {}))
    api_keys = api_key_manager.list_keys()
    
    if not api_keys:
        console.print("[yellow]No API keys configured.[/yellow]")
        return
    
    # Create and display API keys table
    keys_table = Table(title="API Keys Configuration", box=box.ROUNDED)
    keys_table.add_column("Service", style="cyan")
    keys_table.add_column("Status", style="green")
    
    for service, key in api_keys.items():
        if key:
            # Mask the key for display
            masked_key = key[:4] + "*" * (len(key) - 8) + key[-4:] if len(key) > 8 else "****"
            status = f"Configured [dim]({masked_key})[/dim]"
            style = "green"
        else:
            status = "Not configured"
            style = "red"
            
        keys_table.add_row(service, status)
    
    console.print(keys_table)


@cli.command(help="Generate an HTML report from JSON results")
@click.argument('json_file', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True))
@click.option('--output', '-o', help='Output HTML file path', required=True)
def report(json_file, output):
    """Generate an HTML report from JSON scan results."""
    try:
        from luint.utils.html_report import HTMLReportGenerator
        
        console.print(f"[bold green]Generating HTML report from:[/bold green] [bold cyan]{json_file}[/bold cyan]")
        
        # Generate the report
        HTMLReportGenerator.from_json_file(json_file, output)
        
        console.print(f"[bold green]HTML report saved to:[/bold green] [bold cyan]{output}[/bold cyan]")
        
    except Exception as e:
        logger.error(f"Error generating HTML report: {str(e)}", exc_info=True)
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
