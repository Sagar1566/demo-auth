# SAGAR AdaptiveAuth Framework - Makefile
#
# This Makefile provides convenient commands for development,
# testing, and deployment of the AdaptiveAuth Framework.

# Variables
PYTHON := python
PIP := pip
VENV := venv
VENV_ACTIVATE := $(VENV)/bin/activate
PROJECT_NAME := adaptiveauth
PACKAGE_DIR := adaptiveauth

# Default target
.DEFAULT_GOAL := help

# Help target
help:
	@echo "SAGAR AdaptiveAuth Framework - Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make setup              - Setup development environment"
	@echo "  make install            - Install dependencies"
	@echo "  make dev                - Start development server"
	@echo "  make run                - Start production server"
	@echo "  make test               - Run tests"
	@echo "  make test-cov           - Run tests with coverage"
	@echo "  make lint               - Lint code with flake8"
	@echo "  make format             - Format code with black"
	@echo "  make check              - Check code quality (lint + format)"
	@echo "  make clean              - Clean build artifacts"
	@echo "  make clean-pyc          - Clean Python cache files"
	@echo "  make clean-build        - Clean build directory"
	@echo "  make clean-all          - Clean everything"
	@echo "  make build              - Build package"
	@echo "  make build-docker       - Build Docker image"
	@echo "  make run-docker         - Run with Docker"
	@echo "  make docker-up          - Start Docker services"
	@echo "  make docker-down        - Stop Docker services"
	@echo "  make docker-restart     - Restart Docker services"
	@echo "  make docker-logs        - Show Docker logs"
	@echo "  make publish            - Build and publish package"
	@echo "  make docs               - Build documentation"
	@echo "  make security-check     - Run security checks"
	@echo "  make help               - Show this help message"
	@echo ""

# Setup development environment
setup: clean-pyc
	@echo "Setting up development environment..."
	python -m venv $(VENV)
	@echo "Virtual environment created in $(VENV)"
	@echo "Installing dependencies..."
	$(MAKE) install
	@echo "Setup complete! Activate with: source $(VENV_ACTIVATE)"

# Install dependencies
install:
	@echo "Installing dependencies..."
	@$(PYTHON) -m pip install --upgrade pip
	@$(PIP) install -r requirements.txt
	@$(PIP) install -r requirements-dev.txt
	@echo "Dependencies installed successfully!"

# Start development server
dev:
	@echo "Starting development server..."
	@$(PYTHON) -m uvicorn main:app --reload --host 0.0.0.0 --port 8080

# Start production server
run:
	@echo "Starting production server..."
	@gunicorn --worker-class uvicorn.workers.UvicornWorker --workers 4 --bind 0.0.0.0:8080 --timeout 120 --keep-alive 5 main:app

# Run tests
test:
	@echo "Running tests..."
	@pytest

# Run tests with coverage
test-cov:
	@echo "Running tests with coverage..."
	@pytest --cov=$(PACKAGE_DIR) --cov-report=html --cov-report=term

# Lint code
lint:
	@echo "Linting code..."
	@flake8 $(PACKAGE_DIR)

# Format code
format:
	@echo "Formatting code..."
	@black $(PACKAGE_DIR)

# Check code quality
check: lint format
	@echo "Code quality check completed!"

# Clean Python cache files
clean-pyc:
	@echo "Cleaning Python cache files..."
	@find . -name '*.pyc' -exec rm -f {} +
	@find . -name '*.pyo' -exec rm -f {} +
	@find . -name '*~' -exec rm -f {} +
	@find . -name '__pycache__' -exec rm -fr {} +

# Clean build directory
clean-build:
	@echo "Cleaning build directory..."
	@rm -fr build/
	@rm -fr dist/
	@rm -fr *.egg-info/

# Clean everything
clean-all: clean-pyc clean-build
	@echo "Cleaning everything..."
	@rm -fr $(VENV)/

# Clean target
clean: clean-pyc clean-build
	@echo "Clean completed!"

# Build package
build:
	@echo "Building package..."
	@$(PYTHON) -m build

# Build Docker image
build-docker:
	@echo "Building Docker image..."
	@docker build -t adaptiveauth/framework:latest .

# Run with Docker
run-docker: build-docker
	@echo "Running with Docker..."
	@docker run -p 8080:8080 adaptiveauth/framework:latest

# Start Docker services
docker-up:
	@echo "Starting Docker services..."
	@docker-compose up -d

# Stop Docker services
docker-down:
	@echo "Stopping Docker services..."
	@docker-compose down

# Restart Docker services
docker-restart: docker-down docker-up
	@echo "Docker services restarted!"

# Show Docker logs
docker-logs:
	@echo "Showing Docker logs..."
	@docker-compose logs -f

# Publish package
publish: build
	@echo "Publishing package..."
	@$(PYTHON) -m twine upload dist/*

# Build documentation
docs:
	@echo "Building documentation..."
	@mkdocs build

# Run security checks
security-check:
	@echo "Running security checks..."
	@bandit -r $(PACKAGE_DIR)
	@safety check

# Phony targets
.PHONY: help setup install dev run test test-cov lint format check \
        clean clean-pyc clean-build clean-all build build-docker \
        run-docker docker-up docker-down docker-restart docker-logs \
        publish docs security-check