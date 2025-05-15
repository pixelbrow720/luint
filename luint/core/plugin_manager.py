"""
Plugin Manager module for LUINT.
Manages the loading and registration of scanner modules.
"""
import os
import sys
import importlib
import inspect
import pkgutil
from typing import Dict, List, Any, Type, Optional

from luint.utils.logger import get_logger
from luint.constants import MODULE_CATEGORIES

logger = get_logger()


class PluginManager:
    """
    Manages the loading and registration of scanner modules.
    Discovers modules in the luint.modules package.
    """
    
    def __init__(self):
        """Initialize the plugin manager."""
        self.modules = []
        self._discover_modules()
    
    def _discover_modules(self):
        """Discover and load available modules."""
        try:
            # Import the modules package
            import luint.modules
            
            # Get the package path
            package_path = os.path.dirname(luint.modules.__file__)
            
            # Find all modules in the package
            for _, module_name, is_pkg in pkgutil.iter_modules([package_path]):
                if is_pkg or module_name.startswith('__'):
                    continue
                
                # Import the module
                module = importlib.import_module(f"luint.modules.{module_name}")
                
                # Find scanner classes in the module
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if name.endswith('Scanner') and hasattr(obj, 'scan'):
                        # This looks like a scanner class
                        
                        # Extract docstring and process it to get a proper description
                        module_docstring = module.__doc__ if module.__doc__ else f"{name} module"
                        class_docstring = obj.__doc__ if obj.__doc__ else ""
                        
                        # Get the short description from the first line
                        short_desc = module_docstring.split('\n')[0].strip()
                        
                        # Get a more detailed description if available (first paragraph after the title)
                        detailed_desc = ""
                        if module_docstring and len(module_docstring.split('\n\n')) > 1:
                            detailed_desc = module_docstring.split('\n\n')[1].strip()
                        
                        # Extract capabilities from class methods
                        capabilities = []
                        for method_name, method in inspect.getmembers(obj, inspect.isfunction):
                            if method_name != '__init__' and method_name != 'scan' and not method_name.startswith('_'):
                                method_doc = method.__doc__.split('\n')[0].strip() if method.__doc__ else method_name
                                capabilities.append({
                                    'name': method_name,
                                    'description': method_doc
                                })
                                
                        # Create the module information dictionary
                        module_info = {
                            'name': module_name,
                            'class_name': name,
                            'class': obj,
                            'category': MODULE_CATEGORIES.get(module_name, 'Uncategorized'),
                            'description': short_desc,
                            'detailed_description': detailed_desc,
                            'capabilities': capabilities
                        }
                        
                        self.modules.append(module_info)
                        logger.debug(f"Discovered module: {module_name} ({name}) with {len(capabilities)} capabilities")
            
            logger.info(f"Discovered {len(self.modules)} modules")
            
        except (ImportError, AttributeError) as e:
            logger.error(f"Error discovering modules: {str(e)}")
    
    def list_modules(self) -> List[Dict[str, Any]]:
        """
        Get a list of all available modules.
        
        Returns:
            list: List of module information dictionaries
        """
        return self.modules
    
    def get_module(self, module_name: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific module.
        
        Args:
            module_name (str): Name of the module
            
        Returns:
            dict or None: Module information or None if not found
        """
        for module in self.modules:
            if module['name'] == module_name:
                return module
        return None
    
    def get_module_class(self, module_name: str) -> Optional[Type]:
        """
        Get the scanner class for a specific module.
        
        Args:
            module_name (str): Name of the module
            
        Returns:
            class or None: Scanner class or None if not found
        """
        module_info = self.get_module(module_name)
        if module_info and 'class' in module_info:
            return module_info['class']
        return None