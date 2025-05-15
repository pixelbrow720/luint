#!/usr/bin/env python
from setuptools import setup

if __name__ == "__main__":
    try:
        setup(
            # Metadata dikelola dalam pyproject.toml
            # Ini hanya file penunjang untuk kompatibilitas
            packages=["luint"],
            package_dir={"luint": "luint"},
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