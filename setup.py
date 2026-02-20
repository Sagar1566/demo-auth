"""
AdaptiveAuth Framework - Setup Script
Production-ready Adaptive Authentication with Risk-Based Security
"""
from setuptools import setup, find_packages

setup(
    name="adaptiveauth",
    version="1.0.0",
    packages=find_packages(),
    python_requires=">=3.9",
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
    ],
    author="AdaptiveAuth Team",
    author_email="team@adaptiveauth.dev",
    description="Production-ready Adaptive Authentication Framework with Risk-Based Security",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    url="https://github.com/adaptiveauth/adaptiveauth",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Framework :: FastAPI",
        "Topic :: Security",
    ],
)
