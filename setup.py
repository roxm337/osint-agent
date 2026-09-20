"""Setup script for OSINT Agent."""

from setuptools import setup, find_packages

setup(
    name="osint-agent",
    version="1.0.0",
    description="LLM-Orchestrated OSINT Reconnaissance Pipeline",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
    packages=find_packages(),
    py_modules=["orchestrator"],
    install_requires=[
        "pyyaml>=6.0",
        "litellm>=1.60",
        "python-dotenv>=1.0",
        "PySide6>=6.7",
        "gravis==0.1.0",
        "setuptools<81",
    ],
    extras_require={
        "full": [
            "aiohttp>=3.8",
            "dnspython>=2.0",
            "python-whois>=0.8",
            "beautifulsoup4>=4.11",
            "lxml>=4.9",
            "playwright>=1.45",
        ],
    },
    entry_points={
        "console_scripts": [
            "osint-agent=orchestrator:cli",
            "osint-agent-gui=gui.app:main",
        ],
    },
    python_requires=">=3.10",
)
