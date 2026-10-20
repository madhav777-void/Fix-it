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

# Create workspace directory
RUN mkdir -p /app/workspace

# Expose port
EXPOSE 5000

ENV PORT=5000
ENV FLASK_ENV=production

# Run with Gunicorn WSGI server
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app:app"]
