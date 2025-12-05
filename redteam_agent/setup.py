"""
Red Team Agent Framework
========================

AI-powered security assessment agent.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="redteam-agent",
    version="0.1.0",
    author="Red Team AI Project",
    author_email="",
    description="AI-powered Red Team security assessment agent",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/bebetterthan/redteam-agent",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
    python_requires=">=3.10",
    install_requires=[
        "torch>=2.0.0",
        "transformers>=4.36.0",
        "peft>=0.7.0",
        "accelerate>=0.25.0",
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "mypy>=1.7.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "redteam-agent=agent.cli:main",
        ],
    },
)
