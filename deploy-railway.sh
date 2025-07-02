#!/bin/bash

# SecuScan Railway Deployment Script
set -e

echo "🚀 Starting SecuScan deployment to Railway..."

# Check if Railway CLI is installed
if ! command -v railway &> /dev/null; then
    echo "❌ Railway CLI not found. Installing..."
    npm install -g @railway/cli
fi

# Check if user is logged in
if ! railway whoami &> /dev/null; then
    echo "🔐 Please login to Railway..."
    railway login
fi

# Initialize Railway project (if not already done)
if [ ! -f "railway.json" ]; then
    echo "📝 Initializing Railway project..."
    railway init
fi

# Deploy to Railway
echo "🚀 Deploying to Railway..."
railway up

echo "✅ Deployment completed!"
echo "🌐 Your app is now live at: https://your-app.railway.app"
echo "📝 Don't forget to:"
echo "   1. Update CORS origins in backend/main.py"
echo "   2. Set environment variables in Railway dashboard"
echo "   3. Update REACT_APP_API_URL in frontend" 