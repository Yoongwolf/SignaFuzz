# setup.py

from setuptools import setup, find_packages
import os

# Read version from app/__init__.py
with open(os.path.join('app', '__init__.py'), 'r') as f:
    for line in f:
        if line.startswith('__version__'):
            version = line.strip().split('=')[1].strip(' \'"')
            break
    else:
        version = '0.0.1'

# Read long description from README.md
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="ss7-security-tool",
    version=version,
    description="A Python-based SS7 security research tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Your Name",
    author_email="your.email@example.com",
    url="https://github.com/yourusername/ss7-security-tool",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.4.5",
        "pysctp>=0.7.2",
        "pyyaml>=6.0",
        "colorama>=0.4.4",
    ],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Telecommunications Industry",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: Communications",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "ss7-tool=main:main",
        ],
    },
)