#!/bin/bash

# SecuScan Deployment Script
set -e

echo "🚀 Deploying SecuScan..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p data reports/html

# Download CVE data if not present
if [ ! -f "data/cve_cache.json" ]; then
    echo "📥 Downloading CVE data..."
    curl -L -o data/cve_cache.json.gz https://nvd.nist.gov/vuln/data-feeds/json/1.1/nvdcve-1.1-recent.json.gz
    gunzip data/cve_cache.json.gz
fi

# Build and start services
echo "🔨 Building Docker image..."
docker-compose build

echo "🚀 Starting services..."
docker-compose up -d

echo "⏳ Waiting for services to be ready..."
sleep 10

# Check if service is running
if curl -f http://localhost:8000/ > /dev/null 2>&1; then
    echo "✅ SecuScan is running successfully!"
    echo "🌐 Access the web interface at: http://localhost:8000"
    echo "📊 API documentation at: http://localhost:8000/docs"
else
    echo "❌ Service failed to start. Check logs with: docker-compose logs"
    exit 1
fi

echo "🎉 Deployment complete!" 