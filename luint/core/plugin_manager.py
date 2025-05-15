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


class ScannerMetadata:
    """Base class for scanner metadata attributes."""
    MODULE_CATEGORY = "Uncategorized"
    MODULE_DESCRIPTION = "No description provided"
    CAPABILITIES = {}


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
            import luint.modules
            package_path = os.path.dirname(luint.modules.__file__)

            for _, module_name, is_pkg in pkgutil.iter_modules([package_path]):
                if is_pkg or module_name.startswith('__'):
                    logger.debug(f"Skipping {module_name}: {'is package' if is_pkg else 'internal module'}")
                    continue

                try:
                    module = importlib.import_module(f"luint.modules.{module_name}")
                    logger.debug(f"Examining module: {module_name}")

                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if not name.endswith('Scanner'):
                            continue

                        if not hasattr(obj, 'scan'):
                            logger.warning(f"Class {name} in {module_name} lacks scan method, skipping")
                            continue

                        # Get metadata from class attributes or fallback to docstring
                        category = getattr(obj, 'MODULE_CATEGORY', 
                                        MODULE_CATEGORIES.get(module_name, 'Uncategorized'))

                        description = getattr(obj, 'MODULE_DESCRIPTION', 
                                          module.__doc__.split('\n')[0].strip() if module.__doc__ 
                                          else f"{name} module")

                        capabilities = getattr(obj, 'CAPABILITIES', {})
                        if not capabilities:
                            # Fallback to method inspection
                            for method_name, method in inspect.getmembers(obj, inspect.isfunction):
                                if method_name not in ('__init__', 'scan') and not method_name.startswith('_'):
                                    doc = method.__doc__.split('\n')[0].strip() if method.__doc__ else method_name
                                    capabilities[method_name] = doc

                        module_info = {
                            'name': module_name,
                            'class_name': name,
                            'class': obj,
                            'category': category,
                            'description': description,
                            'capabilities': [{'name': k, 'description': v} for k, v in capabilities.items()]
                        }

                        self.modules.append(module_info)
                        logger.info(f"Loaded module: {module_name} ({name}) with {len(capabilities)} capabilities")

                except Exception as e:
                    logger.error(f"Error loading module {module_name}: {str(e)}")

            logger.info(f"Successfully loaded {len(self.modules)} modules")

        except (ImportError, AttributeError) as e:
            logger.error(f"Critical error during module discovery: {str(e)}")

    def list_modules(self) -> List[Dict[str, Any]]:
        """Get a list of all available modules."""
        return self.modules

    def get_module(self, module_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific module."""
        return next((m for m in self.modules if m['name'] == module_name), None)

    def get_module_class(self, module_name: str) -> Optional[Type]:
        """Get the scanner class for a specific module."""
        module_info = self.get_module(module_name)
        return module_info['class'] if module_info and 'class' in module_info else None