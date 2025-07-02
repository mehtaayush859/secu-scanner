#!/bin/bash

# SecuScan Development Startup Script
set -e

echo "🚀 Starting SecuScan in development mode..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8+ first."
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p data reports/html

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt
pip install -r web_app/backend/requirements.txt

# Install frontend dependencies and build
echo "📦 Installing frontend dependencies..."
cd web_app/frontend
npm install
npm run build
cd ../..

# Download CVE data if not present
if [ ! -f "data/cve_cache.json" ]; then
    echo "📥 Downloading CVE data..."
    curl -L -o data/cve_cache.json.gz https://nvd.nist.gov/vuln/data-feeds/json/1.1/nvdcve-1.1-recent.json.gz
    gunzip data/cve_cache.json.gz
fi

# Start the backend server
echo "🚀 Starting backend server..."
echo "🌐 Backend will be available at: http://localhost:8000"
echo "📊 API documentation at: http://localhost:8000/docs"
echo "🛑 Press Ctrl+C to stop the server"

cd web_app/backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000 