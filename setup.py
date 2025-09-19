
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="secure-data-wiper",
    version="1.0.0",
    author="Secure Wiper Team",
    author_email="team@securewiper.com",
    description="NIST-compliant secure data wiping tool with tamper-proof certificates",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/securewiper/secure-data-wiper",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "reportlab>=4.0.4",
        "cryptography>=41.0.7",
    ],
    entry_points={
        "console_scripts": [
            "secure-wiper=main:main",
        ],
    },
)