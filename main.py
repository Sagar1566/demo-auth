"""
AdaptiveAuth - Main Application File
Quick start server for the AdaptiveAuth framework
"""

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from adaptiveauth import AdaptiveAuth, get_current_user, require_admin, User
import uvicorn
import os

# Get the directory of the current file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Create FastAPI app
app = FastAPI(
    title="SAGAR AdaptiveAuth API",
    description="Production-ready authentication framework with risk-based security",
    version="1.0.0"
)

# Initialize AdaptiveAuth framework
auth = AdaptiveAuth(
    database_url=os.getenv("DATABASE_URL", "sqlite:///./adaptiveauth.db"),
    secret_key=os.getenv("SECRET_KEY", "your-super-secret-key-change-in-production"),
    enable_2fa=True,
    enable_risk_assessment=True,
    enable_session_monitoring=True,
    cors_origins=["*"]  # Configure appropriately for production
)

# Mount static files (before auth routes)
static_path = os.path.join(BASE_DIR, "static")
app.mount("/static", StaticFiles(directory=static_path), name="static")

@app.get("/")
async def read_root():
    """Serve the HTML test interface."""
    return FileResponse(os.path.join(BASE_DIR, "static", "index.html"))

# Initialize the app with AdaptiveAuth (after root route)
auth.init_app(app, prefix="/api/v1")

@app.get("/api/info")
async def root():
    """Root endpoint with basic info about the service."""
    return {
        "message": "Welcome to SAGAR AdaptiveAuth Framework",
        "version": "1.0.0",
        "documentation": "/docs",
        "features": [
            "JWT Authentication",
            "Two-Factor Authentication (2FA)",
            "Risk-Based Adaptive Authentication",
            "Behavioral Analysis",
            "Admin Dashboard"
        ]
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "AdaptiveAuth"}

@app.get("/api/v1/protected")
async def protected_resource(current_user: User = Depends(get_current_user)):
    """Protected endpoint - requires valid JWT token."""
    return {
        "message": "Access granted to protected resource!",
        "user_email": current_user.email,
        "user_id": current_user.id,
        "role": current_user.role
    }

@app.get("/api/v1/admin-only")
async def admin_only(current_user: User = Depends(require_admin())):
    """Admin only endpoint."""
    return {
        "message": "Admin access granted!",
        "admin_email": current_user.email
    }

if __name__ == "__main__":
    # Run the server
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=False  # Set to False in production
    )