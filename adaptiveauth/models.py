"""
AdaptiveAuth Database Models
All SQLAlchemy models for the authentication framework.
"""
import enum
from datetime import datetime
from sqlalchemy import (
    Boolean, Column, Integer, String, DateTime, Float, 
    ForeignKey, Text, JSON, Enum, Index
)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


class UserRole(str, enum.Enum):
    """User role enumeration."""
    USER = "user"
    ADMIN = "admin"
    SUPERADMIN = "superadmin"


class RiskLevel(str, enum.Enum):
    """Risk level enumeration for security assessment."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityLevel(int, enum.Enum):
    """Security level (0-4) based on risk assessment."""
    LEVEL_0 = 0  # Known device + IP + browser - minimal auth
    LEVEL_1 = 1  # Unknown browser - password only
    LEVEL_2 = 2  # Unknown IP - password + email verification
    LEVEL_3 = 3  # Unknown device - password + 2FA
    LEVEL_4 = 4  # Suspicious pattern - blocked/full verification


class SessionStatus(str, enum.Enum):
    """Session status enumeration."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUSPICIOUS = "suspicious"


# ======================== USER MODELS ========================

class User(Base):
    """Main user model with authentication data."""
    __tablename__ = "adaptiveauth_users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default=UserRole.USER.value)
    
    # Account Status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    is_locked = Column(Boolean, default=False)
    locked_until = Column(DateTime, nullable=True)
    
    # 2FA Settings
    tfa_enabled = Column(Boolean, default=False)
    tfa_secret = Column(String(255), nullable=True)
    
    # Security Tracking
    failed_login_attempts = Column(Integer, default=0)
    last_failed_login = Column(DateTime, nullable=True)
    last_successful_login = Column(DateTime, nullable=True)
    password_changed_at = Column(DateTime, default=datetime.utcnow)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    profile = relationship("UserProfile", back_populates="user", uselist=False, cascade="all, delete-orphan")
    login_attempts = relationship("LoginAttempt", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    risk_events = relationship("RiskEvent", back_populates="user", cascade="all, delete-orphan")
    framework_usages = relationship("FrameworkUsage", back_populates="user", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index("ix_user_email_active", "email", "is_active"),
    )


class UserProfile(Base):
    """User behavioral profile for risk assessment."""
    __tablename__ = "adaptiveauth_user_profiles"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("adaptiveauth_users.id", ondelete="CASCADE"), unique=True)
    
    # Known Devices & Browsers (JSON arrays)
    known_devices = Column(JSON, default=list)  # [{fingerprint, name, first_seen, last_seen}]
    known_browsers = Column(JSON, default=list)  # [{user_agent, first_seen, last_seen}]
    known_ips = Column(JSON, default=list)  # [{ip, location, first_seen, last_seen}]
    
    # Login Patterns
    typical_login_hours = Column(JSON, default=list)  # [8, 9, 10, ...] typical hours
    typical_login_days = Column(JSON, default=list)  # [0, 1, 2, ...] typical weekdays
    average_session_duration = Column(Float, default=0.0)
    
    # Risk History
    risk_score_history = Column(JSON, default=list)  # [{timestamp, score, factors}]
    total_logins = Column(Integer, default=0)
    successful_logins = Column(Integer, default=0)
    failed_logins = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="profile")


# ======================== AUTHENTICATION MODELS ========================

class LoginAttempt(Base):
    """Login attempt history for analysis."""
    __tablename__ = "adaptiveauth_login_attempts"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("adaptiveauth_users.id", ondelete="CASCADE"), nullable=True)
    email = Column(String(255), index=True)  # Store email even if user doesn't exist
    
    # Request Context
    ip_address = Column(String(45))
    user_agent = Column(Text)
    device_fingerprint = Column(String(255), nullable=True)
    
    # Geolocation (if available)
    country = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    
    # Risk Assessment
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default=RiskLevel.LOW.value)
    security_level = Column(Integer, default=0)
    risk_factors = Column(JSON, default=dict)
    
    # Result
    success = Column(Boolean, default=False)
    failure_reason = Column(String(255), nullable=True)
    required_action = Column(String(100), nullable=True)  # e.g., "2fa", "email_verify", "blocked"
    
    # Timestamps
    attempted_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    user = relationship("User", back_populates="login_attempts")
    
    __table_args__ = (
        Index("ix_login_attempt_user_time", "user_id", "attempted_at"),
        Index("ix_login_attempt_ip", "ip_address"),
    )


class UserSession(Base):
    """Active user sessions with risk monitoring."""
    __tablename__ = "adaptiveauth_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("adaptiveauth_users.id", ondelete="CASCADE"))
    session_token = Column(String(255), unique=True, index=True)
    
    # Session Context
    ip_address = Column(String(45))
    user_agent = Column(Text)
    device_fingerprint = Column(String(255), nullable=True)
    
    # Location
    country = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)
    
    # Risk Status
    current_risk_score = Column(Float, default=0.0)
    current_risk_level = Column(String(20), default=RiskLevel.LOW.value)
    status = Column(String(20), default=SessionStatus.ACTIVE.value)
    step_up_completed = Column(Boolean, default=False)
    
    # Activity Tracking
    last_activity = Column(DateTime, default=datetime.utcnow)
    activity_count = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    __table_args__ = (
        Index("ix_session_user_status", "user_id", "status"),
        Index("ix_session_token", "session_token"),
    )


class TokenBlacklist(Base):
    """Blacklisted/revoked JWT tokens."""
    __tablename__ = "adaptiveauth_token_blacklist"
    
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(500), unique=True, index=True)
    user_id = Column(Integer, ForeignKey("adaptiveauth_users.id", ondelete="SET NULL"), nullable=True)
    reason = Column(String(255), nullable=True)
    blacklisted_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)


class PasswordResetCode(Base):
    """Password reset tokens."""
    __tablename__ = "adaptiveauth_password_resets"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("adaptiveauth_users.id", ondelete="CASCADE"))
    email = Column(String(255), index=True)
    reset_code = Column(String(255), unique=True, index=True)
    is_used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)


class FrameworkUsage(Base):
    """Framework usage tracking for monitoring who uses the framework."""
    __tablename__ = "adaptiveauth_framework_usages"
    
    id = Column(Integer, primary_key=True, index=True)
    client_ip = Column(String(45), nullable=False)
    user_agent = Column(Text)
    endpoint_accessed = Column(String(255))
    method = Column(String(10))
    timestamp = Column(DateTime, default=datetime.utcnow)
    risk_score = Column(Float, default=0.0)
    is_anomalous = Column(Boolean, default=False)
    anomaly_description = Column(Text)
    
    # Relationship to user if authenticated
    user_id = Column(Integer, ForeignKey("adaptiveauth_users.id"), nullable=True)
    user = relationship("User", back_populates="framework_usages")


class EmailVerificationCode(Base):
    """Email verification codes."""
    __tablename__ = "adaptiveauth_email_verifications"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("adaptiveauth_users.id", ondelete="CASCADE"))
    email = Column(String(255), index=True)  # Can be None for SMS
    phone = Column(String(20), index=True)  # Can be None for email
    verification_type = Column(String(20), default="email")  # email or sms
    verification_code = Column(String(255), unique=True, index=True)
    is_used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)


# ======================== RISK ASSESSMENT MODELS ========================

class RiskEvent(Base):
    """Risk events for logging and analysis."""
    __tablename__ = "adaptiveauth_risk_events"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("adaptiveauth_users.id", ondelete="CASCADE"), nullable=True)
    
    # Event Details
    event_type = Column(String(100), nullable=False)  # login, session_activity, suspicious_pattern
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default=RiskLevel.LOW.value)
    security_level = Column(Integer, default=0)
    
    # Context
    ip_address = Column(String(45))
    user_agent = Column(Text, nullable=True)
    device_fingerprint = Column(String(255), nullable=True)
    
    # Risk Details
    risk_factors = Column(JSON, default=dict)  # {factor: score}
    triggered_rules = Column(JSON, default=list)  # [rule_name, ...]
    
    # Action Taken
    action_required = Column(String(100), nullable=True)
    action_taken = Column(String(100), nullable=True)
    resolved = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    resolved_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="risk_events")
    
    __table_args__ = (
        Index("ix_risk_event_user_time", "user_id", "created_at"),
        Index("ix_risk_event_type", "event_type"),
    )


class AnomalyPattern(Base):
    """Detected anomaly patterns for suspicious activity."""
    __tablename__ = "adaptiveauth_anomaly_patterns"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Pattern Details
    pattern_type = Column(String(100), nullable=False)  # brute_force, impossible_travel, credential_stuffing
    pattern_data = Column(JSON, default=dict)
    
    # Scope
    user_id = Column(Integer, ForeignKey("adaptiveauth_users.id", ondelete="CASCADE"), nullable=True)
    ip_address = Column(String(45), nullable=True)
    
    # Severity
    severity = Column(String(20), default=RiskLevel.MEDIUM.value)
    confidence = Column(Float, default=0.0)  # 0.0 to 1.0
    
    # Status
    is_active = Column(Boolean, default=True)
    false_positive = Column(Boolean, default=False)
    
    # Timestamps
    first_detected = Column(DateTime, default=datetime.utcnow)
    last_detected = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)


class StepUpChallenge(Base):
    """Step-up authentication challenges."""
    __tablename__ = "adaptiveauth_stepup_challenges"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("adaptiveauth_users.id", ondelete="CASCADE"))
    session_id = Column(Integer, ForeignKey("adaptiveauth_sessions.id", ondelete="CASCADE"), nullable=True)
    
    # Challenge Details
    challenge_type = Column(String(50), nullable=False)  # otp, email, sms, security_question
    challenge_code = Column(String(255), nullable=True)
    
    # Status
    is_completed = Column(Boolean, default=False)
    attempts = Column(Integer, default=0)
    max_attempts = Column(Integer, default=3)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime, nullable=True)
