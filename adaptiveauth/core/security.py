"""
AdaptiveAuth Core - Security Module
Password hashing, JWT management, and cryptographic utilities.
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Union
from jose import JWTError, jwt
import bcrypt
import secrets
import hashlib

from ..config import get_settings


# ======================== PASSWORD HASHING ========================

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    # Bcrypt has a 72 byte limit, truncate if necessary
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password_bytes, salt).decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    try:
        # Bcrypt has a 72 byte limit, truncate if necessary
        password_bytes = plain_password.encode('utf-8')
        if len(password_bytes) > 72:
            password_bytes = password_bytes[:72]
        return bcrypt.checkpw(password_bytes, hashed_password.encode('utf-8'))
    except Exception:
        return False


def validate_password_strength(password: str) -> Dict[str, Any]:
    """Validate password meets security requirements."""
    settings = get_settings()
    errors = []
    
    if len(password) < settings.MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {settings.MIN_PASSWORD_LENGTH} characters")
    
    if settings.REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    
    if settings.REQUIRE_LOWERCASE and not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    
    if settings.REQUIRE_DIGIT and not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit")
    
    if settings.REQUIRE_SPECIAL and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        errors.append("Password must contain at least one special character")
    
    return {
        "valid": len(errors) == 0,
        "errors": errors
    }


# ======================== JWT MANAGEMENT ========================

def create_access_token(
    subject: Union[str, int],
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[Dict[str, Any]] = None
) -> str:
    """Create JWT access token."""
    settings = get_settings()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {
        "sub": str(subject),
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    }
    
    if extra_claims:
        to_encode.update(extra_claims)
    
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def create_refresh_token(
    subject: Union[str, int],
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create JWT refresh token."""
    settings = get_settings()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode = {
        "sub": str(subject),
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh",
        "jti": generate_token(32)  # Unique token ID
    }
    
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate JWT token."""
    settings = get_settings()
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        return None


def verify_token(token: str, token_type: str = "access") -> Optional[str]:
    """Verify token and return subject if valid."""
    payload = decode_token(token)
    
    if payload is None:
        return None
    
    if payload.get("type") != token_type:
        return None
    
    return payload.get("sub")


def get_token_expiry(token: str) -> Optional[datetime]:
    """Get token expiration time."""
    payload = decode_token(token)
    
    if payload is None:
        return None
    
    exp = payload.get("exp")
    if exp:
        return datetime.fromtimestamp(exp)
    
    return None


# ======================== TOKEN GENERATION ========================

def generate_token(length: int = 32) -> str:
    """Generate a secure random token."""
    return secrets.token_urlsafe(length)


def generate_session_token() -> str:
    """Generate a unique session token."""
    return secrets.token_urlsafe(48)


def generate_reset_code() -> str:
    """Generate password reset code."""
    return secrets.token_urlsafe(32)


def generate_verification_code(length: int = 6) -> str:
    """Generate numeric verification code."""
    return ''.join([str(secrets.randbelow(10)) for _ in range(length)])


# ======================== DEVICE FINGERPRINTING ========================

def generate_device_fingerprint(
    user_agent: str,
    ip_address: str,
    extra_data: Optional[Dict[str, str]] = None
) -> str:
    """Generate a device fingerprint from request data."""
    data_parts = [user_agent, ip_address]
    
    if extra_data:
        for key in sorted(extra_data.keys()):
            data_parts.append(f"{key}:{extra_data[key]}")
    
    fingerprint_data = "|".join(data_parts)
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]


def generate_browser_hash(user_agent: str) -> str:
    """Generate a hash for browser identification."""
    return hashlib.md5(user_agent.encode()).hexdigest()[:16]


# ======================== ENCRYPTION UTILITIES ========================

def hash_token(token: str) -> str:
    """Hash a token for storage (e.g., refresh tokens)."""
    return hashlib.sha256(token.encode()).hexdigest()


def constant_time_compare(val1: str, val2: str) -> bool:
    """Compare two strings in constant time to prevent timing attacks."""
    return secrets.compare_digest(val1, val2)
