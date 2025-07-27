#!/usr/bin/env python3
"""Setup script for XSS Vibes scanner."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = (
    readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""
)

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    requirements = [
        line.strip()
        for line in requirements_path.read_text(encoding="utf-8").split("\n")
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="xss-vibes",
    version="2.0.0",
    author="Faiyaz Ahmad",
    author_email="",
    description="Modern XSS Scanner with async support and enhanced features",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/faiyazahmad07/xss_vibes",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "enhanced": [
            "beautifulsoup4>=4.12.0",
            "lxml>=4.9.0",
            "tqdm>=4.65.0",
        ],
        "build": [
            "pyinstaller>=5.0.0",
            "setuptools>=65.0.0",
            "wheel>=0.37.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "xss-vibes=xss_vibes.cli:main",
            "xss-scanner=xss_vibes.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.json", "*.txt", "*.md"],
    },
)
