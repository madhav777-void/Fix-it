# Multi-stage or Python + OpenJDK image for full APK auditing
FROM python:3.12-slim-bookworm

# Install OpenJDK JRE for apktool
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy project files
COPY . .

# Download apktool into bin/ if not present
RUN python scripts/download_apktool.py

# Use /tmp for workspace (writable on all container platforms)
RUN mkdir -p /tmp/apk_audit_workspace

# Expose port (Railway overrides via $PORT)
EXPOSE 8080

ENV PORT=8080
ENV FLASK_ENV=production
# Store scan workspaces in /tmp (writable on Railway, Render, Fly.io, etc.)
ENV WORKSPACE_DIR=/tmp/apk_audit_workspace

# Run with Gunicorn: $PORT is set by Railway/Render at runtime (1 worker + threads to stay within 512MB RAM)
CMD gunicorn --bind 0.0.0.0:${PORT:-8080} --workers 1 --threads 4 --timeout 300 app:app
