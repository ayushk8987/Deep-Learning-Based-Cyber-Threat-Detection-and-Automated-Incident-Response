# ==============================================================================
# DEPLOYMENT PREPARATION: Multi-platform Production Dockerfile
# ==============================================================================
FROM python:3.13-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    HOST=0.0.0.0 \
    PORT=5050 \
    KERAS_HOME=/app/.keras \
    MPLCONFIGDIR=/app/.matplotlib_cache

# Set container working directory
WORKDIR /app

# Install minimal OS dependencies for health checking
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code and assets
COPY . .

# Create isolated runtime cache directories and assign non-root permissions
RUN mkdir -p /app/.keras /app/.matplotlib_cache /app/data /app/models/saved_model /app/artifacts \
    && useradd --create-home --shell /bin/bash socuser \
    && chown -R socuser:socuser /app

# Switch to unprivileged runtime user
USER socuser

# Expose the application listening port
EXPOSE 5050

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5050/api/health || exit 1

# Launch application server
CMD ["python", "app.py"]
