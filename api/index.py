# Vercel serverless function entry point
import sys
import os

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the FastAPI app
from web_app.backend.main import app

# Export for Vercel
handler = app 