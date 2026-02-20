"""
AdaptiveAuth Pydantic Schemas
Request/Response models for API validation.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, Field, field_validator
import re


# ======================== AUTH SCHEMAS ========================

class UserRegister(BaseModel):
    """User registration request."""
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        return v


class UserLogin(BaseModel):
    """Standard login request."""
    email: EmailStr
    password: str


class AdaptiveLoginRequest(BaseModel):
    """Adaptive login request with context."""
    email: EmailStr
    password: str
    device_fingerprint: Optional[str] = None
    remember_device: bool = False


class AdaptiveLoginResponse(BaseModel):
    """Adaptive login response."""
    status: str  # success, challenge_required, blocked
    risk_level: str
    security_level: int
    access_token: Optional[str] = None
    token_type: Optional[str] = "bearer"
    challenge_type: Optional[str] = None  # otp, email, sms
    challenge_id: Optional[str] = None
    message: Optional[str] = None
    user_info: Optional[Dict[str, Any]] = None


class StepUpRequest(BaseModel):
    """Step-up authentication request."""
    challenge_id: str
    verification_code: str


class StepUpResponse(BaseModel):
    """Step-up authentication response."""
    status: str
    access_token: Optional[str] = None
    token_type: Optional[str] = "bearer"
    message: Optional[str] = None


class LoginOTP(BaseModel):
    """Login with TOTP code."""
    email: EmailStr
    otp: str = Field(..., min_length=6, max_length=6)


class TokenResponse(BaseModel):
    """JWT token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_info: Optional[Dict[str, Any]] = None


class RefreshTokenRequest(BaseModel):
    """Refresh token request."""
    refresh_token: str


# ======================== PASSWORD SCHEMAS ========================

class PasswordResetRequest(BaseModel):
    """Request password reset."""
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Confirm password reset."""
    reset_token: str
    new_password: str = Field(..., min_length=8)
    confirm_password: str
    
    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, v, info):
        if 'new_password' in info.data and v != info.data['new_password']:
            raise ValueError('Passwords do not match')
        return v


class PasswordChange(BaseModel):
    """Change password (authenticated)."""
    current_password: str
    new_password: str = Field(..., min_length=8)
    confirm_password: str


# ======================== USER SCHEMAS ========================

class UserResponse(BaseModel):
    """User information response."""
    id: int
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    is_verified: bool
    tfa_enabled: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class UserUpdate(BaseModel):
    """Update user information."""
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None


class UserSecuritySettings(BaseModel):
    """User security settings response."""
    tfa_enabled: bool
    last_password_change: Optional[datetime]
    active_sessions: int
    known_devices: int
    recent_login_attempts: int


class Enable2FAResponse(BaseModel):
    """Enable 2FA response with QR code."""
    secret: str
    qr_code: str  # Base64 encoded QR code image
    backup_codes: List[str]


class Verify2FARequest(BaseModel):
    """Verify 2FA setup."""
    otp: str = Field(..., min_length=6, max_length=6)


# ======================== DEVICE SCHEMAS ========================

class DeviceInfo(BaseModel):
    """Known device information."""
    id: str
    name: str
    browser: Optional[str]
    os: Optional[str]
    first_seen: datetime
    last_seen: datetime
    is_current: bool = False


class DeviceListResponse(BaseModel):
    """List of known devices."""
    devices: List[DeviceInfo]
    total: int


# ======================== RISK ASSESSMENT SCHEMAS ========================

class RiskContext(BaseModel):
    """Context for risk assessment."""
    ip_address: str
    user_agent: str
    device_fingerprint: Optional[str] = None
    timestamp: Optional[datetime] = None


class RiskAssessmentResult(BaseModel):
    """Risk assessment result."""
    risk_score: float = Field(..., ge=0, le=100)
    risk_level: str
    security_level: int = Field(..., ge=0, le=4)
    risk_factors: Dict[str, float]
    required_action: Optional[str] = None
    message: Optional[str] = None


class RiskEventResponse(BaseModel):
    """Risk event information."""
    id: int
    event_type: str
    risk_score: float
    risk_level: str
    ip_address: Optional[str]
    risk_factors: Dict[str, Any]
    action_taken: Optional[str]
    created_at: datetime
    resolved: bool
    
    class Config:
        from_attributes = True


class RiskEventList(BaseModel):
    """List of risk events."""
    events: List[RiskEventResponse]
    total: int
    page: int
    page_size: int


# ======================== SESSION SCHEMAS ========================

class SessionInfo(BaseModel):
    """Active session information."""
    id: int
    ip_address: str
    user_agent: str
    country: Optional[str]
    city: Optional[str]
    risk_level: str
    status: str
    last_activity: datetime
    created_at: datetime
    is_current: bool = False
    
    class Config:
        from_attributes = True


class SessionListResponse(BaseModel):
    """List of user sessions."""
    sessions: List[SessionInfo]
    total: int


class SessionRevokeRequest(BaseModel):
    """Request to revoke session(s)."""
    session_ids: List[int]
    revoke_all: bool = False


# ======================== ADMIN SCHEMAS ========================

class AdminUserList(BaseModel):
    """Admin user list response."""
    users: List[UserResponse]
    total: int
    page: int
    page_size: int


class AdminBlockUser(BaseModel):
    """Block user request."""
    user_id: int
    reason: str
    duration_hours: Optional[int] = None  # None = permanent


class AdminUnblockUser(BaseModel):
    """Unblock user request."""
    user_id: int


class AdminStatistics(BaseModel):
    """Admin dashboard statistics."""
    total_users: int
    active_users: int
    blocked_users: int
    active_sessions: int
    high_risk_events_today: int
    failed_logins_today: int
    new_users_today: int


# ======================== ANOMALY SCHEMAS ========================

class AnomalyPatternResponse(BaseModel):
    """Detected anomaly pattern."""
    id: int
    pattern_type: str
    severity: str
    confidence: float
    is_active: bool
    first_detected: datetime
    last_detected: datetime
    pattern_data: Dict[str, Any]
    
    class Config:
        from_attributes = True


class AnomalyListResponse(BaseModel):
    """List of anomaly patterns."""
    anomalies: List[AnomalyPatternResponse]
    total: int


# ======================== CHALLENGE SCHEMAS ========================

class ChallengeRequest(BaseModel):
    """Request a new challenge."""
    challenge_type: str = Field(..., pattern="^(otp|email|sms)$")
    session_id: Optional[int] = None


class ChallengeResponse(BaseModel):
    """Challenge created response."""
    challenge_id: str
    challenge_type: str
    expires_at: datetime
    message: str


class VerifyChallengeRequest(BaseModel):
    """Verify challenge code."""
    challenge_id: str
    code: str


# ======================== DASHBOARD SCHEMAS ========================

class RiskDashboardOverview(BaseModel):
    """Risk dashboard overview."""
    total_risk_events: int
    high_risk_events: int
    active_anomalies: int
    blocked_users: int
    average_risk_score: float
    risk_trend: str  # increasing, decreasing, stable


class RiskStatistics(BaseModel):
    """Risk statistics."""
    period: str
    total_logins: int
    successful_logins: int
    failed_logins: int
    blocked_attempts: int
    average_risk_score: float
    risk_distribution: Dict[str, int]  # {low: X, medium: X, high: X, critical: X}
