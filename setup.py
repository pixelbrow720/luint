
#!/usr/bin/env python
"""
Compatibility shim for setuptools.
This file exists only to support legacy build systems.
All package metadata and configuration is managed in pyproject.toml
"""

from setuptools import setup

if __name__ == "__main__":
    try:
        setup(
            # All metadata is managed in pyproject.toml
            packages=["luint"],
            package_data={
                "luint": ["py.typed"],
            },
            exclude_package_data={
                "": ["*.log", "*.pyc"],
            },
        )
    except Exception as e:
        print(f"Error during setup: {e}")
        raise
