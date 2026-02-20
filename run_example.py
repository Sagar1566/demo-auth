"""
Example script to demonstrate how to use the AdaptiveAuth framework
"""

from fastapi import FastAPI
from adaptiveauth import AdaptiveAuth
import uvicorn

# Create a sample FastAPI application
app = FastAPI(title="Example App with AdaptiveAuth")

# Initialize the AdaptiveAuth framework
auth = AdaptiveAuth(
    database_url="sqlite:///./example_app.db",  # Local database for this example
    secret_key="super-secret-key-change-in-production",
    enable_2fa=True,
    enable_risk_assessment=True,
    enable_session_monitoring=True
)

# Integrate AdaptiveAuth with your application
auth.init_app(app, prefix="/auth")

@app.get("/")
async def root():
    return {
        "message": "Example app with AdaptiveAuth integration",
        "endpoints": {
            "docs": "/docs",
            "auth": "/auth/docs"
        }
    }

if __name__ == "__main__":
    print("Starting AdaptiveAuth example server...")
    print("Visit http://localhost:8000/docs for API documentation")
    print("Visit http://localhost:8000/auth/docs for authentication endpoints")
    
    uvicorn.run(
        "run_example:app",
        host="0.0.0.0",
        port=8000,
        reload=True  # Set to False in production
    )