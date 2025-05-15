"""
Scanner module for LUINT.
Handles orchestration of scanning modules and consolidation of results.
"""
import os
import time
import importlib
import concurrent.futures
from typing import Dict, List, Any, Optional, Union, Type

from luint.utils.logger import get_logger, LoggerAdapter
from luint.utils.cache_manager import CacheManager
from luint.utils.rate_limiter import ApiRateLimiter
from luint.utils.proxy_manager import ProxyManager
from luint.utils.output_manager import OutputManager
from luint.core.plugin_manager import PluginManager


logger = get_logger()


class Scanner:
    """
    Main scanner class for LUINT.
    Orchestrates the scanning process using various modules.
    """
    
    def __init__(self, target: str, modules: Optional[List[str]] = None, run_all: bool = False,
                 config: Optional[Dict[str, Any]] = None, api_key_manager=None, proxy: Optional[str] = None, 
                 verbose: bool = False, quiet: bool = False, use_cache: bool = True, 
                 recursive: bool = False, depth: int = 1, output_format: str = 'json',
                 output_file: Optional[str] = None):
        """
        Initialize the scanner.
        
        Args:
            target (str): Target domain or IP to scan
            modules (list, optional): List of module names to run
            run_all (bool): Whether to run all available modules
            config (dict, optional): Configuration dictionary
            api_key_manager: API key manager instance
            proxy (str, optional): Proxy to use for HTTP requests
            verbose (bool): Whether to enable verbose output
            quiet (bool): Whether to suppress output
            use_cache (bool): Whether to use caching
            recursive (bool): Whether to scan recursively
            depth (int): Depth for recursive scanning
            output_format (str): Output format ('json', 'csv', 'txt')
            output_file (str, optional): File to save output to
        """
        self.target = target
        self.module_names = modules
        self.run_all = run_all
        # Ensure config is a dictionary
        self.config = {} if config is None else config
        self.api_key_manager = api_key_manager
        self.proxy = proxy
        self.verbose = verbose
        self.quiet = quiet
        self.use_cache = use_cache
        self.recursive = recursive
        self.depth = depth
        
        # Setup logger
        self.logger = LoggerAdapter(logger, module_name='scanner', target=target)
        
        # Setup utility managers
        self.setup_managers()
        
        # Setup output manager
        self.output_manager = OutputManager(
            output_file=output_file,
            output_format=output_format,
            pretty_print=not quiet
        )
        
        # Setup plugin manager
        self.plugin_manager = PluginManager()
        
        # List of targets for recursive scanning
        self.targets = [target]
        self.scanned_targets = set()
    
    def setup_managers(self):
        """Setup the utility managers (cache, rate limiter, proxy)."""
        # Setup cache manager
        cache_enabled = self.use_cache
        cache_duration = self.config.get('general', {}).get('cache_duration', 3600)
        self.cache_manager = CacheManager(enabled=cache_enabled, default_ttl=cache_duration)
        
        # Setup rate limiter
        self.rate_limiter = ApiRateLimiter(self.config)
        
        # Setup proxy manager
        if self.proxy:
            self.proxy_manager = ProxyManager(self.proxy)
            # Test proxy connection
            proxy_ok, proxy_msg = self.proxy_manager.test_proxy()
            if proxy_ok:
                self.logger.info(f"Proxy configured successfully: {proxy_msg}")
            else:
                self.logger.warning(f"Proxy test failed: {proxy_msg}. Continuing without proxy.")
                self.proxy_manager = ProxyManager()
        else:
            self.proxy_manager = ProxyManager()
    
    def run(self) -> Dict[str, Any]:
        """
        Run the scan with selected modules.
        
        Returns:
            dict: Consolidated scan results
        """
        start_time = time.time()
        all_results = {}
        
        # Get available modules
        available_modules = self.plugin_manager.list_modules()
        available_module_names = [m['name'] for m in available_modules]
        
        # Determine which modules to run
        modules_to_run = []
        if self.run_all:
            modules_to_run = available_module_names
        elif self.module_names:
            # Check if specified modules exist
            for module_name in self.module_names:
                if module_name in available_module_names:
                    modules_to_run.append(module_name)
                else:
                    self.logger.warning(f"Module '{module_name}' not found, skipping")
        else:
            # Default modules if none specified
            default_modules = ['dns_info', 'server_info']
            modules_to_run = [m for m in default_modules if m in available_module_names]
        
        if not modules_to_run:
            self.logger.error("No valid modules to run")
            return all_results
        
        self.logger.info(f"Starting scan on {self.target} with modules: {', '.join(modules_to_run)}")
        
        # Determine if we should run modules in parallel or sequentially
        # Modules with high resource usage or that modify shared state should not run in parallel
        parallel_safe_modules = ['dns_info', 'server_info', 'subdomain_enum', 'content_discovery']
        sequential_modules = ['email_recon', 'security_checks']  # These modules may interact with shared resources
        
        # Get max_threads from config or use default
        max_threads = self.config.get('general', {}).get('threads', 10)
        
        # Filter modules that can run in parallel
        parallel_modules = [m for m in modules_to_run if m in parallel_safe_modules]
        seq_modules = [m for m in modules_to_run if m not in parallel_safe_modules]
        
        if parallel_modules and max_threads > 1:
            # Run parallel-safe modules concurrently
            self.logger.info(f"Running {len(parallel_modules)} modules in parallel with {max_threads} threads")
            from concurrent.futures import ThreadPoolExecutor, as_completed
            
            # Function to run a single module
            def run_module(module_name):
                try:
                    # Get the module class
                    module_info = next((m for m in available_modules if m['name'] == module_name), None)
                    if not module_info or 'class' not in module_info:
                        self.logger.warning(f"Module {module_name} not found or has no class, skipping")
                        return module_name, {"error": "Module not found"}
                    
                    module_class = module_info['class']
                    self.logger.info(f"Running module: {module_name}")
                    
                    # Initialize the module
                    module_instance = module_class(
                        target=self.target,
                        config=self.config,
                        cache_manager=self.cache_manager if self.use_cache else None,
                        rate_limiter=self.rate_limiter,
                        api_key_manager=self.api_key_manager
                    )
                    
                    # Run the module scan
                    module_results = module_instance.scan()
                    return module_name, module_results
                
                except Exception as e:
                    self.logger.error(f"Error running module {module_name}: {str(e)}", exc_info=self.verbose)
                    return module_name, {"error": str(e)}
            
            # Create a thread pool and execute modules in parallel
            with ThreadPoolExecutor(max_workers=min(max_threads, len(parallel_modules))) as executor:
                # Submit all tasks
                future_to_module = {executor.submit(run_module, module_name): module_name for module_name in parallel_modules}
                
                # Process completed tasks as they finish
                for future in as_completed(future_to_module):
                    module_name, module_results = future.result()
                    
                    # Add results to output manager
                    self.output_manager.add_result(module_name, module_results)
                    all_results[module_name] = module_results
                    
                    # Print module results if not quiet
                    if not self.quiet:
                        self.output_manager.print_module_result(module_name, module_results)
                    
                    # Handle recursive scanning
                    if self.recursive and self.depth > 1:
                        self.process_recursive_targets(module_name, module_results)
        
        # Run sequential modules one by one
        for module_name in seq_modules:
            try:
                # Get the module class
                module_info = next((m for m in available_modules if m['name'] == module_name), None)
                if not module_info or 'class' not in module_info:
                    self.logger.warning(f"Module {module_name} not found or has no class, skipping")
                    continue
                
                module_class = module_info['class']
                self.logger.info(f"Running module: {module_name}")
                
                # Initialize the module
                module_instance = module_class(
                    target=self.target,
                    config=self.config,
                    cache_manager=self.cache_manager if self.use_cache else None,
                    rate_limiter=self.rate_limiter,
                    api_key_manager=self.api_key_manager
                )
                
                # Run the module scan
                module_results = module_instance.scan()
                
                # Add results to output manager
                self.output_manager.add_result(module_name, module_results)
                all_results[module_name] = module_results
                
                # Print module results if not quiet
                if not self.quiet:
                    self.output_manager.print_module_result(module_name, module_results)
                
                # Handle recursive scanning
                if self.recursive and self.depth > 1:
                    self.process_recursive_targets(module_name, module_results)
            
            except Exception as e:
                self.logger.error(f"Error running module {module_name}: {str(e)}", exc_info=self.verbose)
                all_results[module_name] = {"error": str(e)}
        
        # Handle recursive scanning of discovered targets
        if self.recursive and self.depth > 1:
            recursive_results = self.run_recursive_scans()
            if recursive_results:
                all_results['recursive_scans'] = recursive_results
        
        # Save results to file if output file specified
        if self.output_manager.output_file:
            self.output_manager.save()
        
        # Print summary if not quiet
        if not self.quiet:
            self.output_manager.print_summary(self.target)
        
        end_time = time.time()
        self.logger.info(f"Scan completed in {end_time - start_time:.2f} seconds")
        
        return all_results
    
    def process_recursive_targets(self, module_name: str, module_results: Dict[str, Any]):
        """
        Process results from a module to find additional targets for recursive scanning.
        
        Args:
            module_name (str): Name of the module
            module_results (dict): Results from the module
        """
        new_targets = set()
        
        # Extract targets based on module type
        if module_name == 'subdomain_enum' and 'subdomains' in module_results:
            new_targets.update(module_results['subdomains'])
        
        elif module_name == 'dns_info' and 'dns_records' in module_results:
            # Add A records
            if 'A' in module_results['dns_records']:
                new_targets.update(module_results['dns_records']['A'])
            
            # Add NS records
            if 'NS' in module_results['dns_records']:
                ns_records = module_results['dns_records']['NS']
                new_targets.update([str(ns) for ns in ns_records])
        
        # Add new targets to the list, excluding already scanned ones
        for target in new_targets:
            if target not in self.scanned_targets and target != self.target:
                self.targets.append(target)
    
    def run_recursive_scans(self) -> Dict[str, Any]:
        """
        Run recursive scans on discovered targets.
        
        Returns:
            dict: Results of recursive scans
        """
        recursive_results = {}
        current_depth = 2  # Start at depth 2
        
        while current_depth <= self.depth:
            depth_targets = []
            
            # Get targets for this depth level
            for target in self.targets:
                if target not in self.scanned_targets:
                    depth_targets.append(target)
                    self.scanned_targets.add(target)
            
            if not depth_targets:
                break
                
            self.logger.info(f"Running depth {current_depth} scans on {len(depth_targets)} targets")
            
            # Run scans on targets at this depth
            for target in depth_targets:
                # Create a new scanner for this target
                recursive_scanner = Scanner(
                    target=target,
                    modules=self.module_names,
                    run_all=self.run_all,
                    config=self.config,
                    api_key_manager=self.api_key_manager,
                    proxy=self.proxy,
                    verbose=self.verbose,
                    quiet=True,  # Always quiet for recursive scans
                    use_cache=self.use_cache,
                    recursive=False,  # No further recursion
                    depth=1,
                    output_format='json',
                    output_file=None
                )
                
                # Run the scan
                recursive_scanner_results = recursive_scanner.run()
                
                # Add results to recursive results
                recursive_results[target] = recursive_scanner_results
                
                # Process new targets for next depth
                for module_name, module_results in recursive_scanner_results.items():
                    self.process_recursive_targets(module_name, module_results)
            
            current_depth += 1
        
        return recursive_results