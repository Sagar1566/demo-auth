"""
Live Test Application for AdaptiveAuth Framework
This application demonstrates all features of the AdaptiveAuth framework with interactive endpoints
"""

from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.security import HTTPBearer
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import Request
from typing import Optional
import uvicorn
import json

from adaptiveauth import AdaptiveAuth, get_current_user, get_current_active_user, require_admin
from adaptiveauth.models import User
from adaptiveauth.schemas import UserRegister, UserLogin
from adaptiveauth.core.security import hash_password, verify_password

# Create FastAPI application
app = FastAPI(
    title="AdaptiveAuth Framework Live Test Application",
    description="Interactive demonstration of all AdaptiveAuth features",
    version="1.0.0"
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize AdaptiveAuth framework
auth = AdaptiveAuth(
    database_url="sqlite:///./test_app.db",
    secret_key="test-application-secret-key-change-in-production",
    enable_2fa=True,
    enable_risk_assessment=True,
    enable_session_monitoring=True
)

# Initialize the app with AdaptiveAuth - mount directly without additional prefix
app.include_router(auth.router, prefix="")

# Security scheme
security = HTTPBearer()

# Sample unprotected endpoint
@app.get("/")
async def root():
    return {
        "message": "Welcome to AdaptiveAuth Framework Live Test Application!",
        "instructions": [
            "1. Register a user at POST /auth/register",
            "2. Login at POST /auth/login to get a token",
            "3. Access protected endpoints with Authorization header",
            "4. Try adaptive authentication at POST /auth/adaptive-login",
            "5. Enable 2FA at POST /auth/enable-2fa",
            "6. Access admin endpoints at /auth/admin (requires admin role)"
        ],
        "available_features": [
            "JWT Authentication",
            "Two-Factor Authentication",
            "Risk-Based Adaptive Authentication", 
            "User Management",
            "Admin Dashboard",
            "Session Monitoring",
            "Anomaly Detection"
        ],
        "test_interface": "Visit /static/index.html for interactive testing interface"
    }

@app.get("/test-interface")
async def test_interface():
    """Serve the test interface"""
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=open("static/index.html").read())

# Protected endpoint
@app.get("/protected")
async def protected_endpoint(current_user: User = Depends(get_current_user)):
    """Protected endpoint that requires authentication"""
    return {
        "message": f"Hello {current_user.email}, you accessed a protected resource!",
        "user_id": current_user.id,
        "email": current_user.email,
        "is_active": current_user.is_active,
        "role": current_user.role
    }

# Admin-only endpoint
@app.get("/admin-only")
async def admin_only_endpoint(current_user: User = Depends(require_admin)):
    """Admin-only endpoint that requires admin role"""
    return {
        "message": f"Hello admin {current_user.email}, you accessed an admin-only resource!",
        "user_id": current_user.id,
        "role": current_user.role
    }

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "Test Application"}

# Demo endpoint to show framework capabilities
@app.get("/demo/features")
async def demo_features():
    """Demonstrate all framework features"""
    return {
        "jwt_authentication": {
            "description": "Secure JWT token-based authentication",
            "endpoints": [
                "POST /auth/login",
                "POST /auth/refresh-token"
            ]
        },
        "two_factor_auth": {
            "description": "TOTP-based 2FA with QR codes",
            "endpoints": [
                "POST /auth/enable-2fa",
                "POST /auth/verify-2fa",
                "POST /auth/disable-2fa"
            ]
        },
        "risk_based_auth": {
            "description": "Adaptive authentication based on risk levels",
            "endpoints": [
                "POST /auth/adaptive-login",
                "POST /auth/assess-risk",
                "POST /auth/step-up"
            ]
        },
        "user_management": {
            "description": "Complete user management system",
            "endpoints": [
                "POST /auth/register",
                "GET /user/profile",
                "PUT /user/profile",
                "POST /user/change-password"
            ]
        },
        "admin_dashboard": {
            "description": "Admin tools and analytics",
            "endpoints": [
                "GET /auth/admin/users",
                "GET /auth/admin/statistics",
                "GET /auth/admin/risk-events"
            ]
        }
    }

# Test registration endpoint
@app.post("/test/register")
async def test_register(user_data: UserRegister):
    """Test endpoint for user registration"""
    with auth.db_manager.session_scope() as db:
        # Check if user exists
        existing = db.query(User).filter(User.email == user_data.email).first()
        if existing:
            raise HTTPException(status_code=400, detail="User with this email already exists")
        
        # Validate password length (bcrypt limitation: max 72 bytes)
        if len(user_data.password.encode('utf-8')) > 72:
            raise HTTPException(status_code=400, detail="Password cannot be longer than 72 bytes")
        
        # Create new user
        user = User(
            email=user_data.email,
            password_hash=hash_password(user_data.password),
            full_name=getattr(user_data, 'full_name', ''),
            is_active=True,
            is_verified=False
        )
        
        db.add(user)
        db.commit()
        db.refresh(user)
        
        return {
            "message": "User registered successfully",
            "user_id": user.id,
            "email": user.email
        }

# Test login endpoint
@app.post("/test/login")
async def test_login(login_data: UserLogin):
    """Test endpoint for user login"""
    with auth.db_manager.session_scope() as db:
        user = db.query(User).filter(User.email == login_data.email).first()
        
        if not user or not verify_password(login_data.password, user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        if not user.is_active:
            raise HTTPException(status_code=401, detail="User account is deactivated")
        
        # Create access token
        from adaptiveauth.core.security import create_access_token
        access_token = create_access_token(data={"sub": user.email})
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user_id": user.id,
            "email": user.email
        }

# Test user creation (programmatic)
@app.post("/test/create-user")
async def create_test_user(
    email: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(None),
    role: str = Form("user")
):
    """Create a test user programmatically"""
    # Validate password length (bcrypt limitation: max 72 bytes)
    if len(password.encode('utf-8')) > 72:
        raise HTTPException(status_code=400, detail="Password cannot be longer than 72 bytes")
    
    try:
        user = auth.create_user(email=email, password=password, full_name=full_name, role=role)
        return {
            "message": "User created successfully",
            "user_id": user.id,
            "email": user.email,
            "role": user.role
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

if __name__ == "__main__":
    print("🚀 Starting AdaptiveAuth Framework Live Test Application...")
    print("📋 Available endpoints:")
    print("   - GET / (Home page with instructions)")
    print("   - POST /auth/register (Register new user)")
    print("   - POST /auth/login (Login to get token)")
    print("   - GET /protected (Access with Authorization header)")
    print("   - GET /auth/docs (API documentation)")
    print("   - GET /demo/features (Show all features)")
    print("\n📝 To test the framework:")
    print("   1. Register a user at /auth/register")
    print("   2. Login at /auth/login to get your JWT token")
    print("   3. Use the token to access protected endpoints")
    print("   4. Try different authentication methods")
    print("   5. Test 2FA, risk assessment, and admin features")
    print("\n🌐 Visit http://localhost:8000/docs for full API documentation")
    
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")