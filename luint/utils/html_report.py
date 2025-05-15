"""
HTML Report Generation Module for LUINT.
Handles the generation of HTML reports from scan results.
"""

import os
import json
import datetime
from typing import Dict, Any, Optional
import jinja2

from luint.constants import VERSION

class HTMLReportGenerator:
    """
    HTML Report Generator for LUINT.
    Generates HTML reports from scan results using Jinja2 templates.
    """
    
    def __init__(self):
        """Initialize the HTML Report Generator."""
        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
        template_loader = jinja2.FileSystemLoader(searchpath=template_dir)
        self.template_env = jinja2.Environment(loader=template_loader)
        self.template = self.template_env.get_template('html_report_template.html')
    
    def generate_report(self, 
                        target: str, 
                        results: Dict[str, Any], 
                        scan_duration: float, 
                        modules: list, 
                        output_file: Optional[str] = None) -> str:
        """
        Generate an HTML report from scan results.
        
        Args:
            target (str): Target of the scan
            results (dict): Scan results
            scan_duration (float): Duration of the scan in seconds
            modules (list): List of modules used in the scan
            output_file (str, optional): File to save the report to
            
        Returns:
            str: HTML report content
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Calculate total findings
        total_findings = 0
        for module_name, module_data in results.items():
            if module_data and 'findings' in module_data:
                total_findings += len(module_data['findings']) if module_data['findings'] else 0
        
        # Prepare template context
        context = {
            'target': target,
            'timestamp': timestamp,
            'duration': f"{scan_duration:.2f}",
            'modules': modules,
            'total_findings': total_findings,
            'version': VERSION,
            'results': results
        }
        
        # Render the template
        html_content = self.template.render(**context)
        
        # Save to file if specified
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
        return html_content
    
    @staticmethod
    def from_json_file(json_file: str, output_file: Optional[str] = None) -> str:
        """
        Generate an HTML report from a JSON results file.
        
        Args:
            json_file (str): Path to JSON results file
            output_file (str, optional): File to save the report to
            
        Returns:
            str: HTML report content
        """
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        generator = HTMLReportGenerator()
        target = data.get('target', 'Unknown')
        results = data.get('results', {})
        scan_duration = data.get('scan_duration', 0)
        modules = list(results.keys())
        
        return generator.generate_report(target, results, scan_duration, modules, output_file)