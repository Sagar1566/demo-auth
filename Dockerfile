# Use official Python runtime as base image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project requirements
COPY requirements.txt /app/

# Install Python dependencies
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install gunicorn

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser

# Copy project
COPY --chown=appuser:appuser . /app/

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
CMD ["gunicorn", "--worker-class", "uvicorn.workers.UvicornWorker", "--workers", "4", "--bind", "0.0.0.0:8080", "--timeout", "120", "--keep-alive", "5", "main:app"]