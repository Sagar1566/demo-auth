"""
AdaptiveAuth Routers Module
"""
from .auth import router as auth_router
from .user import router as user_router
from .admin import router as admin_router
from .risk import router as risk_router
from .adaptive import router as adaptive_router

__all__ = [
    "auth_router",
    "user_router",
    "admin_router",
    "risk_router",
    "adaptive_router",
]
