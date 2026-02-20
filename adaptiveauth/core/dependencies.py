"""
AdaptiveAuth Core - Dependencies Module
FastAPI dependencies for authentication and authorization.
"""
from typing import Optional, List
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from .database import get_db
from .security import decode_token, verify_token
from ..models import User, UserSession, TokenBlacklist, UserRole
from ..config import get_settings

# OAuth2 scheme for token extraction
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=False)


async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """Get current authenticated user from JWT token."""
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if not token:
        raise credentials_exception
    
    # Check if token is blacklisted
    blacklisted = db.query(TokenBlacklist).filter(
        TokenBlacklist.token == token
    ).first()
    
    if blacklisted:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Decode and verify token
    payload = decode_token(token)
    if payload is None:
        raise credentials_exception
    
    if payload.get("type") != "access":
        raise credentials_exception
    
    email: str = payload.get("sub")
    if email is None:
        raise credentials_exception
    
    # Get user from database
    user = db.query(User).filter(User.email == email).first()
    
    if user is None:
        raise credentials_exception
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    
    if user.is_locked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is locked"
        )
    
    return user


async def get_current_user_optional(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Get current user if authenticated, None otherwise."""
    
    if not token:
        return None
    
    try:
        payload = decode_token(token)
        if payload is None or payload.get("type") != "access":
            return None
        
        email = payload.get("sub")
        if not email:
            return None
        
        # Check blacklist
        blacklisted = db.query(TokenBlacklist).filter(
            TokenBlacklist.token == token
        ).first()
        if blacklisted:
            return None
        
        user = db.query(User).filter(User.email == email).first()
        if user and user.is_active and not user.is_locked:
            return user
        
    except Exception:
        pass
    
    return None


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Ensure user is active."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user


def require_role(allowed_roles: List[str]):
    """Dependency factory for role-based access control."""
    
    async def role_checker(
        current_user: User = Depends(get_current_user)
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        return current_user
    
    return role_checker


def require_admin():
    """Require admin or superadmin role."""
    return require_role([UserRole.ADMIN.value, UserRole.SUPERADMIN.value])


def require_superadmin():
    """Require superadmin role."""
    return require_role([UserRole.SUPERADMIN.value])


async def get_current_session(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> Optional[UserSession]:
    """Get current session from request."""
    
    if not token:
        return None
    
    payload = decode_token(token)
    if not payload:
        return None
    
    session_id = payload.get("session_id")
    if not session_id:
        return None
    
    session = db.query(UserSession).filter(
        UserSession.id == session_id,
        UserSession.status == "active"
    ).first()
    
    return session


class RateLimiter:
    """Simple rate limiter for API endpoints."""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests = {}  # ip -> [(timestamp, count)]
    
    async def __call__(self, request: Request):
        from datetime import datetime, timedelta
        
        client_ip = request.client.host if request.client else "unknown"
        current_time = datetime.utcnow()
        window_start = current_time - timedelta(seconds=self.window_seconds)
        
        # Clean old entries
        if client_ip in self._requests:
            self._requests[client_ip] = [
                (ts, count) for ts, count in self._requests[client_ip]
                if ts > window_start
            ]
        
        # Count requests in window
        request_count = sum(
            count for _, count in self._requests.get(client_ip, [])
        )
        
        if request_count >= self.max_requests:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded"
            )
        
        # Add current request
        if client_ip not in self._requests:
            self._requests[client_ip] = []
        self._requests[client_ip].append((current_time, 1))
        
        return True


def get_client_info(request: Request) -> dict:
    """Extract client information from request."""
    return {
        "ip_address": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", ""),
        "device_fingerprint": request.headers.get("x-device-fingerprint"),
        "accept_language": request.headers.get("accept-language", ""),
        "origin": request.headers.get("origin", ""),
    }
