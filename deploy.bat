@echo off
REM SecuScan Deployment Script for Windows
setlocal enabledelayedexpansion

echo 🚀 Deploying SecuScan on Windows...

REM Check if Docker is installed
docker --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker is not installed. Please install Docker Desktop first.
    pause
    exit /b 1
)

REM Check if Docker Compose is installed
docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker Compose is not installed. Please install Docker Compose first.
    pause
    exit /b 1
)

REM Create necessary directories
echo 📁 Creating directories...
if not exist "data" mkdir data
if not exist "reports\html" mkdir reports\html

REM Download CVE data if not present
if not exist "data\cve_cache.json" (
    echo 📥 Downloading CVE data...
    powershell -Command "Invoke-WebRequest -Uri 'https://nvd.nist.gov/vuln/data-feeds/json/1.1/nvdcve-1.1-recent.json.gz' -OutFile 'data\cve_cache.json.gz'"
    powershell -Command "Expand-Archive -Path 'data\cve_cache.json.gz' -DestinationPath 'data' -Force"
    del "data\cve_cache.json.gz"
)

REM Build and start services
echo 🔨 Building Docker image...
docker-compose build

echo 🚀 Starting services...
docker-compose up -d

echo ⏳ Waiting for services to be ready...
timeout /t 10 /nobreak >nul

REM Check if service is running
curl -f http://localhost:8000/ >nul 2>&1
if errorlevel 1 (
    echo ❌ Service failed to start. Check logs with: docker-compose logs
    pause
    exit /b 1
) else (
    echo ✅ SecuScan is running successfully!
    echo 🌐 Access the web interface at: http://localhost:8000
    echo 📊 API documentation at: http://localhost:8000/docs
)

echo 🎉 Deployment complete!
pause 