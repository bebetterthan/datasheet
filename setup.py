"""
Setup script for Security Dataset Scraper.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    requirements = [
        line.strip() 
        for line in requirements_path.read_text().split('\n')
        if line.strip() and not line.startswith('#')
    ]

setup(
    name="security-dataset-scraper",
    version="1.0.0",
    author="Security Dataset Team",
    author_email="security-dataset@example.com",
    description="Comprehensive tool for collecting security/pentesting datasets for LLM fine-tuning",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/security-dataset/scraper",
    packages=find_packages(exclude=["tests*"]),
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=[
        "httpx>=0.25.0",
        "aiohttp>=3.9.0",
        "aiofiles>=23.2.1",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
        "selectolax>=0.3.17",
        "click>=8.1.0",
        "rich>=13.7.0",
        "pydantic>=2.5.0",
        "pydantic-settings>=2.1.0",
        "tenacity>=8.2.0",
        "pyyaml>=6.0.1",
        "tiktoken>=0.5.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.12.0",
            "isort>=5.13.0",
            "flake8>=6.1.0",
            "mypy>=1.7.0",
        ],
        "browser": [
            "playwright>=1.40.0",
        ],
        "semantic": [
            "sentence-transformers>=2.2.0",
        ],
        "all": [
            "playwright>=1.40.0",
            "sentence-transformers>=2.2.0",
            "diskcache>=5.6.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "security-scraper=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    keywords="security, pentesting, dataset, llm, fine-tuning, scraper, red-team",
)
