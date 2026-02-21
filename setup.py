"""
AdaptiveAuth Framework - Setup Script
Production-ready Adaptive Authentication with Risk-Based Security
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="adaptiveauth",
    version="1.0.0",
    author="SAGAR AdaptiveAuth Team",
    author_email="contact@adaptiveauth.com",
    description="Advanced Adaptive Authentication Framework with Risk-Based Security",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/adaptiveauth",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Framework :: FastAPI",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP :: Session",
        "Topic :: Authentication/Authorization",
    ],
    python_requires=">=3.8",
    install_requires=[
        "fastapi>=0.104.0",
        "uvicorn[standard]>=0.24.0",
        "sqlalchemy>=2.0.0",
        "pydantic>=2.0.0",
        "pydantic-settings>=2.0.0",
        "python-jose[cryptography]>=3.3.0",
        "passlib[bcrypt]>=1.7.4",
        "bcrypt>=4.1.2",
        "python-multipart>=0.0.6",
        "pyotp>=2.9.0",
        "qrcode[pil]>=7.4.2",
        "fastapi-mail>=1.4.1",
        "httpx>=0.25.0",
        "python-dateutil>=2.8.2",
        "user-agents>=2.2.0",
        "aiofiles>=23.2.1",
        "twilio>=8.10.0",  # For SMS functionality
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "docs": [
            "mkdocs>=1.4.0",
            "mkdocs-material>=9.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "adaptiveauth=main:main",  # Command to run the server
        ],
    },
    keywords="authentication, security, adaptive-auth, risk-based, 2fa, oauth, jwt",
    project_urls={
        "Documentation": "https://adaptiveauth.readthedocs.io/",
        "Source": "https://github.com/yourusername/adaptiveauth",
        "Tracker": "https://github.com/yourusername/adaptiveauth/issues",
        "Changelog": "https://github.com/yourusername/adaptiveauth/releases",
    },
)
