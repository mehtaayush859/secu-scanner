# Multi-stage build for SecuScan
FROM python:3.11-slim as base

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy CLI tools and core application
COPY cli_tool/ ./cli_tool/
COPY reports/ ./reports/
COPY data/ ./data/
COPY main.py .

# Web App Stage
FROM base as web-app

# Install web app dependencies
COPY web_app/backend/requirements.txt ./web_app/backend/
RUN pip install --no-cache-dir -r web_app/backend/requirements.txt

# Copy web app backend
COPY web_app/backend/ ./web_app/backend/

# Frontend build stage
FROM node:18-alpine as frontend-builder

WORKDIR /app/frontend
COPY web_app/frontend/package*.json ./
RUN npm ci --only=production

COPY web_app/frontend/ ./
RUN npm run build

# Final stage
FROM base as final

# Copy built frontend
COPY --from=frontend-builder /app/frontend/build ./web_app/frontend/build

# Create non-root user
RUN useradd -m -u 1000 secuscan && chown -R secuscan:secuscan /app
USER secuscan

# Expose ports
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

# Default command
CMD ["python", "-m", "uvicorn", "web_app.backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
