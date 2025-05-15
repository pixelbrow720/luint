"""
Output Manager for formatting and saving results.
"""
import os
import sys
import json
import csv
import time
from typing import Dict, List, Any, Optional, Union
from contextlib import contextmanager

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich import box

from luint.utils.logger import get_logger
from luint.utils.helpers import save_to_file

# Initialize console for rich output
console = Console()
logger = get_logger()


class OutputManager:
    """
    Manages the output of scan results in various formats.
    """
    
    def __init__(self, output_file: Optional[str] = None, output_format: str = 'json', pretty_print: bool = True):
        """
        Initialize the output manager.
        
        Args:
            output_file (str, optional): File path to save output to
            output_format (str): Output format ('json', 'csv', 'txt')
            pretty_print (bool): Whether to use pretty-printing for console output
        """
        self.output_file = output_file
        self.output_format = output_format.lower()
        self.pretty_print = pretty_print
        self.scan_start_time = time.time()
        self.results = {}
    
    def add_result(self, module: str, data: Any):
        """
        Add a result from a module.
        
        Args:
            module (str): Module name
            data (any): Module results
        """
        self.results[module] = data
    
    def update_result(self, module: str, data: Any):
        """
        Update an existing result from a module.
        
        Args:
            module (str): Module name
            data (any): Module results to update with
        """
        if module in self.results:
            if isinstance(self.results[module], dict) and isinstance(data, dict):
                self.results[module].update(data)
            elif isinstance(self.results[module], list) and isinstance(data, list):
                self.results[module].extend(data)
            else:
                self.results[module] = data
        else:
            self.add_result(module, data)
    
    def get_results(self) -> Dict[str, Any]:
        """
        Get all scan results.
        
        Returns:
            dict: All scan results
        """
        return self.results
    
    def get_module_result(self, module: str) -> Any:
        """
        Get results for a specific module.
        
        Args:
            module (str): Module name
            
        Returns:
            any: Module results or None if module not found
        """
        return self.results.get(module)
    
    def clear_results(self):
        """Clear all scan results."""
        self.results = {}
        self.scan_start_time = time.time()
    
    def print_summary(self, target: str):
        """
        Print a summary of the scan results.
        
        Args:
            target (str): Target domain or IP
        """
        if not self.pretty_print:
            return
        
        scan_time = time.time() - self.scan_start_time
        
        # Create summary table
        table = Table(title=f"Scan Summary for {target}", box=box.ROUNDED)
        table.add_column("Module", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Findings", style="yellow")
        
        total_findings = 0
        modules_with_findings = 0
        
        for module, result in self.results.items():
            count = 0
            status = "✓"
            
            if isinstance(result, list):
                count = len(result)
            elif isinstance(result, dict):
                count = len(result)
            elif result:
                count = 1
                
            if count > 0:
                modules_with_findings += 1
                total_findings += count
                status_style = "green"
            else:
                status = "☐"
                status_style = "dim"
                
            table.add_row(
                module,
                f"[{status_style}]{status}[/{status_style}]",
                str(count) if count > 0 else "-"
            )
        
        console.print("\n")
        console.print(Panel(
            f"Scan completed in [bold cyan]{scan_time:.2f}[/bold cyan] seconds\n"
            f"[bold green]{modules_with_findings}[/bold green] modules returned findings\n"
            f"[bold yellow]{total_findings}[/bold yellow] total findings",
            title="Scan Statistics",
            border_style="green"
        ))
        console.print(table)
        
        if self.output_file:
            console.print(f"Results saved to: [bold cyan]{self.output_file}[/bold cyan]")
    
    def print_module_result(self, module: str, data: Any):
        """
        Print results for a specific module in a nice format.
        
        Args:
            module (str): Module name
            data (any): Module results
        """
        if not self.pretty_print:
            return
            
        console.print(f"\n[bold cyan]{module} Results[/bold cyan]")
        
        if isinstance(data, list):
            if not data:
                console.print("[yellow]No results found[/yellow]")
                return
                
            if all(isinstance(item, dict) for item in data):
                # Create table from list of dictionaries
                table = Table(box=box.ROUNDED)
                
                # Get all possible keys for columns
                columns = set()
                for item in data:
                    columns.update(item.keys())
                
                # Add columns to table
                for column in sorted(columns):
                    table.add_column(column)
                
                # Add rows to table
                for item in data:
                    row_values = [str(item.get(column, "")) for column in sorted(columns)]
                    table.add_row(*row_values)
                
                console.print(table)
            else:
                # Simple list output
                for i, item in enumerate(data, 1):
                    console.print(f"  {i}. {item}")
        
        elif isinstance(data, dict):
            if not data:
                console.print("[yellow]No results found[/yellow]")
                return
                
            # Create table from dictionary
            table = Table(box=box.ROUNDED)
            table.add_column("Key", style="cyan")
            table.add_column("Value", style="green")
            
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, indent=2)
                table.add_row(str(key), str(value))
            
            console.print(table)
        
        else:
            console.print(str(data))
    
    def save(self) -> bool:
        """
        Save results to the specified output file.
        
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.output_file:
            return False
            
        # Create metadata
        metadata = {
            "timestamp": time.time(),
            "scan_duration": time.time() - self.scan_start_time,
            "modules_run": list(self.results.keys())
        }
        
        # Prepare data with metadata
        data_to_save = {
            "metadata": metadata,
            "results": self.results
        }
        
        # Ensure directory exists
        output_dir = os.path.dirname(self.output_file)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
            except OSError as e:
                logger.error(f"Failed to create directory for output file: {e}")
                return False
        
        try:
            return save_to_file(data_to_save, self.output_file, self.output_format)
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
            return False


@contextmanager
def progress_bar(description: str = "Processing", unit: str = "items"):
    """
    Context manager for displaying a progress bar.
    
    Args:
        description (str): Description of the progress
        unit (str): Unit of measurement
        
    Yields:
        rich.progress.Progress: Progress object
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold green]{task.description}"),
        BarColumn(),
        TextColumn("[bold cyan]{task.completed}/{task.total}"),
        TextColumn("[yellow]{task.percentage:>3.0f}%"),
        TimeElapsedColumn()
    ) as progress:
        # Create a task
        task = progress.add_task(description, total=None)
        
        # Yield a wrapper object that includes the progress and task
        class ProgressWrapper:
            def __init__(self, progress, task):
                self.progress = progress
                self.task = task
            
            def update(self, advance=None, total=None, description=None):
                update_kwargs = {}
                if advance is not None:
                    update_kwargs["advance"] = advance
                if total is not None:
                    update_kwargs["total"] = total
                if description is not None:
                    update_kwargs["description"] = description
                self.progress.update(self.task, **update_kwargs)
                
        yield ProgressWrapper(progress, task)


def print_info(message: str):
    """
    Print an information message.
    
    Args:
        message (str): Message to print
    """
    console.print(f"[bold blue]ℹ[/bold blue] {message}")


def print_success(message: str):
    """
    Print a success message.
    
    Args:
        message (str): Message to print
    """
    console.print(f"[bold green]✓[/bold green] {message}")


def print_warning(message: str):
    """
    Print a warning message.
    
    Args:
        message (str): Message to print
    """
    console.print(f"[bold yellow]⚠[/bold yellow] {message}")


def print_error(message: str):
    """
    Print an error message.
    
    Args:
        message (str): Message to print
    """
    console.print(f"[bold red]✗[/bold red] {message}")


def print_debug(message: str):
    """
    Print a debug message.
    
    Args:
        message (str): Message to print
    """
    console.print(f"[dim]🔍 {message}[/dim]")
