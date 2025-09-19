#!/usr/bin/env python3
"""Setup script for Advanced Bug Bounty Hunter."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

# Read requirements from pyproject.toml (simplified approach)
requirements = [
    "playwright>=1.40.0",
    "langchain>=0.1.0",
    "langgraph>=0.1.0",
    "google-generativeai>=0.3.0",
    "aiohttp[speedups]>=3.9.0",
    "requests[security]>=2.31.0",
    "beautifulsoup4>=4.12.0",
    "sqlalchemy>=2.0.0",
    "psycopg2-binary>=2.9.0",
    "fastapi>=0.104.0",
    "uvicorn[standard]>=0.24.0",
    "typer>=0.9.0",
    "rich>=13.7.0",
    "pydantic>=2.5.0",
    "pydantic-settings>=2.1.0",
    "pyyaml>=6.0.1",
    "structlog>=23.2.0",
]

dev_requirements = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.21.0",
    "pytest-cov>=4.1.0",
    "black>=23.12.0",
    "isort>=5.13.0",
    "flake8>=6.1.0",
    "mypy>=1.8.0",
    "pre-commit>=3.6.0",
]

setup(
    name="advanced-bug-bounty-hunter",
    version="0.1.0",
    author="Shayan Banerjee",
    author_email="your.email@example.com",
    description="AI-powered bug bounty hunting tool that emulates human security researcher behavior",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/streetquant/advanced-bug-bounty-hunter",
    project_urls={
        "Bug Tracker": "https://github.com/streetquant/advanced-bug-bounty-hunter/issues",
        "Documentation": "https://github.com/streetquant/advanced-bug-bounty-hunter#readme",
        "Source Code": "https://github.com/streetquant/advanced-bug-bounty-hunter",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.11",
    install_requires=requirements,
    extras_require={
        "dev": dev_requirements,
        "test": ["pytest>=7.4.0", "pytest-asyncio>=0.21.0", "pytest-cov>=4.1.0"],
    },
    entry_points={
        "console_scripts": [
            "bbhunter=advanced_bug_bounty_hunter.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "advanced_bug_bounty_hunter": ["config/*.yaml"],
    },
    zip_safe=False,
    keywords="security, bug-bounty, penetration-testing, vulnerability-scanner, ai, automation",
)
