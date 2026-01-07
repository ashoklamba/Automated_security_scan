"""Setup script for Security Report Automation Tools."""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="security-report-automation",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Automation tools to parse and consolidate SonarQube and Mend security reports",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/new-project",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "security-report=src.main:main",
        ],
    },
)
