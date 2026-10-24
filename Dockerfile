# Dockerfile for TrustVault Secure Document Management Platform
FROM python:3.13-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TRUSTVAULT_PORT=8000

WORKDIR /app

# Install security patches & build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Create unprivileged service account
RUN useradd -m -u 1001 trustvault && \
    mkdir -p /app/storage_vault && \
    chown -R trustvault:trustvault /app

USER trustvault

# Initialize and seed database
RUN TRUSTVAULT_SECRET_KEY=build-only-not-used python seed_data.py

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://127.0.0.1:8000/health || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
