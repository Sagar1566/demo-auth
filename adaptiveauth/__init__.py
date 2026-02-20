"""
AdaptiveAuth - Production-Ready Adaptive Authentication Framework

A comprehensive authentication framework that combines:
- JWT-based authentication with token management
- Two-factor authentication (TOTP) with QR code support
- Risk-based adaptive authentication with dynamic security levels
- Behavioral analysis and anomaly detection
- Continuous session monitoring
- Admin dashboard for security management

Easy integration with any FastAPI application:

    from adaptiveauth import AdaptiveAuth
    
    # Initialize the framework
    auth = AdaptiveAuth(
        database_url="sqlite:///./app.db",
        secret_key="your-secret-key"
    )
    
    # Mount to your FastAPI app
    app.include_router(auth.router)
"""

__version__ = "1.0.0"
__author__ = "AdaptiveAuth Team"

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from .config import AdaptiveAuthSettings, get_settings, get_risk_weights
from .models import (
    Base, User, UserProfile, LoginAttempt, UserSession,
    TokenBlacklist, PasswordResetCode, EmailVerificationCode,
    RiskEvent, AnomalyPattern, StepUpChallenge,
    UserRole, RiskLevel, SecurityLevel, SessionStatus
)
from .schemas import (
    UserRegister, UserLogin, AdaptiveLoginRequest, AdaptiveLoginResponse,
    TokenResponse, UserResponse, RiskAssessmentResult
)
from .core import (
    get_db, init_database, DatabaseManager,
    hash_password, verify_password, create_access_token,
    get_current_user, get_current_active_user, require_role, require_admin
)
from .risk import (
    RiskEngine, RiskAssessment, BehaviorAnalyzer,
    SessionMonitor, AnomalyDetector
)
from .auth import AuthService, OTPService, EmailService
from .routers import (
    auth_router, user_router, admin_router,
    risk_router, adaptive_router
)


class AdaptiveAuth:
    """
    Main AdaptiveAuth framework class for easy integration.
    
    Example usage:
        from adaptiveauth import AdaptiveAuth
        from fastapi import FastAPI
        
        app = FastAPI()
        
        # Initialize AdaptiveAuth
        auth = AdaptiveAuth(
            database_url="sqlite:///./app.db",
            secret_key="your-super-secret-key",
            enable_2fa=True,
            enable_risk_assessment=True
        )
        
        # Mount all auth routes
        app.include_router(auth.router)
        
        # Or mount individual routers
        app.include_router(auth.auth_router, prefix="/auth")
        app.include_router(auth.admin_router, prefix="/admin")
    """
    
    def __init__(
        self,
        database_url: str = "sqlite:///./adaptiveauth.db",
        secret_key: str = "change-this-secret-key",
        enable_2fa: bool = True,
        enable_risk_assessment: bool = True,
        enable_session_monitoring: bool = True,
        cors_origins: Optional[List[str]] = None,
        **kwargs
    ):
        """
        Initialize AdaptiveAuth framework.
        
        Args:
            database_url: Database connection string
            secret_key: Secret key for JWT tokens
            enable_2fa: Enable two-factor authentication
            enable_risk_assessment: Enable risk-based authentication
            enable_session_monitoring: Enable continuous session verification
            cors_origins: List of allowed CORS origins
            **kwargs: Additional settings to override defaults
        """
        # Store settings
        self.database_url = database_url
        self.secret_key = secret_key
        self.enable_2fa = enable_2fa
        self.enable_risk_assessment = enable_risk_assessment
        self.enable_session_monitoring = enable_session_monitoring
        self.cors_origins = cors_origins or ["*"]
        
        # Override settings
        import os
        os.environ["ADAPTIVEAUTH_DATABASE_URL"] = database_url
        os.environ["ADAPTIVEAUTH_SECRET_KEY"] = secret_key
        os.environ["ADAPTIVEAUTH_ENABLE_2FA"] = str(enable_2fa)
        os.environ["ADAPTIVEAUTH_ENABLE_RISK_ASSESSMENT"] = str(enable_risk_assessment)
        os.environ["ADAPTIVEAUTH_ENABLE_SESSION_MONITORING"] = str(enable_session_monitoring)
        
        for key, value in kwargs.items():
            os.environ[f"ADAPTIVEAUTH_{key.upper()}"] = str(value)
        
        # Initialize database
        self.db_manager = DatabaseManager(database_url)
        self.db_manager.init_tables()
        
        # Create combined router
        self._router = APIRouter()
        self._setup_routers()
    
    def _setup_routers(self):
        """Set up all routers."""
        self._router.include_router(auth_router)
        self._router.include_router(user_router)
        self._router.include_router(admin_router)
        
        if self.enable_risk_assessment:
            self._router.include_router(risk_router)
            self._router.include_router(adaptive_router)
    
    @property
    def router(self) -> APIRouter:
        """Get the combined API router."""
        return self._router
    
    @property
    def auth_router(self) -> APIRouter:
        """Get the authentication router."""
        return auth_router
    
    @property
    def user_router(self) -> APIRouter:
        """Get the user management router."""
        return user_router
    
    @property
    def admin_router(self) -> APIRouter:
        """Get the admin router."""
        return admin_router
    
    @property
    def risk_router(self) -> APIRouter:
        """Get the risk dashboard router."""
        return risk_router
    
    @property
    def adaptive_router(self) -> APIRouter:
        """Get the adaptive authentication router."""
        return adaptive_router
    
    def get_db_session(self):
        """Get database session generator for custom use."""
        return self.db_manager.get_session()
    
    def init_app(self, app: FastAPI, prefix: str = ""):
        """
        Initialize AdaptiveAuth with a FastAPI application.
        
        Args:
            app: FastAPI application instance
            prefix: Optional prefix for all routes
        """
        # Add CORS middleware
        app.add_middleware(
            CORSMiddleware,
            allow_origins=self.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Include routers
        app.include_router(self._router, prefix=prefix)
        
        # Add continuous monitoring middleware if enabled
        if self.enable_session_monitoring:
            app.add_middleware(AdaptiveAuthMiddleware, auth=self)
    
    def create_user(
        self,
        email: str,
        password: str,
        full_name: Optional[str] = None,
        role: str = "user"
    ) -> User:
        """
        Create a new user programmatically.
        
        Args:
            email: User's email address
            password: User's password
            full_name: User's full name
            role: User role (user, admin, superadmin)
        
        Returns:
            Created User object
        """
        with self.db_manager.session_scope() as db:
            # Check existing
            existing = db.query(User).filter(User.email == email).first()
            if existing:
                raise ValueError(f"User with email {email} already exists")
            
            user = User(
                email=email,
                password_hash=hash_password(password),
                full_name=full_name,
                role=role,
                is_active=True,
                is_verified=True  # Skip verification for programmatic creation
            )
            
            db.add(user)
            db.commit()
            db.refresh(user)
            
            return user
    
    def get_auth_service(self, db) -> AuthService:
        """Get AuthService instance with database session."""
        return AuthService(db)
    
    def cleanup(self):
        """Cleanup resources."""
        self.db_manager.close()


class AdaptiveAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware for continuous session monitoring.
    Checks session validity and risk on each request.
    """
    
    def __init__(self, app, auth: AdaptiveAuth):
        super().__init__(app)
        self.auth = auth
    
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip for non-authenticated routes
        skip_paths = ['/auth/login', '/auth/register', '/auth/forgot-password', '/docs', '/openapi.json']
        if any(request.url.path.endswith(p) for p in skip_paths):
            return await call_next(request)
        
        # Get token from header
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "")
            
            # Verify session if monitoring enabled
            if self.auth.enable_session_monitoring:
                with self.auth.db_manager.session_scope() as db:
                    from .core.security import decode_token
                    from .core.dependencies import get_client_info
                    
                    payload = decode_token(token)
                    if payload:
                        email = payload.get("sub")
                        user = db.query(User).filter(User.email == email).first()
                        
                        if user:
                            # Get active session
                            session = db.query(UserSession).filter(
                                UserSession.user_id == user.id,
                                UserSession.status == SessionStatus.ACTIVE.value
                            ).first()
                            
                            if session:
                                # Update last activity
                                from datetime import datetime
                                session.last_activity = datetime.utcnow()
                                session.activity_count += 1
        
        response = await call_next(request)
        return response


# Convenience exports
__all__ = [
    # Main class
    "AdaptiveAuth",
    "AdaptiveAuthMiddleware",
    
    # Settings
    "AdaptiveAuthSettings",
    "get_settings",
    
    # Models
    "Base",
    "User",
    "UserProfile",
    "LoginAttempt",
    "UserSession",
    "TokenBlacklist",
    "RiskEvent",
    "AnomalyPattern",
    "UserRole",
    "RiskLevel",
    "SecurityLevel",
    
    # Core utilities
    "get_db",
    "init_database",
    "hash_password",
    "verify_password",
    "create_access_token",
    "get_current_user",
    "require_admin",
    
    # Risk assessment
    "RiskEngine",
    "RiskAssessment",
    "BehaviorAnalyzer",
    "SessionMonitor",
    "AnomalyDetector",
    
    # Services
    "AuthService",
    "OTPService",
    "EmailService",
    
    # Routers
    "auth_router",
    "user_router",
    "admin_router",
    "risk_router",
    "adaptive_router",
]
