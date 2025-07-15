#!/usr/bin/env python3
"""
NightStalker Framework Setup
Advanced offensive security framework installation script
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

# Read requirements
requirements = []
with open("requirements.txt", "r") as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith("#"):
            requirements.append(line)

setup(
    name="nightstalker",
    version="1.0.0",
    author="Security Research Team",
    author_email="research@nightstalker.local",
    description="Advanced Offensive Security Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/nightstalker/framework",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "nightstalker=nightstalker.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "nightstalker": [
            "config/*.yaml",
            "config/*.json",
            "wordlists/*.txt",
            "templates/*.py",
        ],
    },
    keywords="security penetration-testing red-team offensive-security",
    project_urls={
        "Bug Reports": "https://github.com/nightstalker/framework/issues",
        "Source": "https://github.com/nightstalker/framework",
        "Documentation": "https://nightstalker.readthedocs.io/",
    },
) 