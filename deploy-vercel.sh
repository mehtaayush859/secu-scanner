#!/bin/bash

# SecuScan Vercel Deployment Script
set -e

echo "🚀 Starting SecuScan deployment to Vercel..."

# Check if Vercel CLI is installed
if ! command -v vercel &> /dev/null; then
    echo "❌ Vercel CLI not found. Installing..."
    npm install -g vercel
fi

# Check if user is logged in
if ! vercel whoami &> /dev/null; then
    echo "🔐 Please login to Vercel..."
    vercel login
fi

# Build frontend
echo "📦 Building frontend..."
cd web_app/frontend
npm install
npm run build
cd ../..

# Deploy to Vercel
echo "🚀 Deploying to Vercel..."
vercel --prod

echo "✅ Deployment completed!"
echo "🌐 Your app is now live at: https://your-app.vercel.app"
echo "📝 Don't forget to:"
echo "   1. Update CORS origins in backend/main.py"
echo "   2. Set environment variables in Vercel dashboard"
echo "   3. Update REACT_APP_API_URL in frontend" 