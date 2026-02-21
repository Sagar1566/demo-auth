"""
AdaptiveAuth Configuration Module
Environment-based configuration management for the framework.
"""
from typing import Optional, List
from pydantic_settings import BaseSettings
from pydantic import Field
from functools import lru_cache

# Load .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


class AdaptiveAuthSettings(BaseSettings):
    """Main configuration settings for AdaptiveAuth framework."""
    
    # Database Configuration
    DATABASE_URL: str = Field(default="sqlite:///./adaptiveauth.db", description="Database connection URL")
    DATABASE_ECHO: bool = Field(default=False, description="Enable SQL query logging")
    
    # JWT Configuration
    SECRET_KEY: str = Field(default="your-super-secret-key-change-in-production", description="JWT secret key")
    ALGORITHM: str = Field(default="HS256", description="JWT signing algorithm")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, description="Access token expiration in minutes")
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, description="Refresh token expiration in days")
    
    # 2FA Configuration
    ENABLE_2FA: bool = Field(default=True, description="Enable two-factor authentication")
    OTP_ISSUER: str = Field(default="AdaptiveAuth", description="TOTP issuer name")
    OTP_LENGTH: int = Field(default=6, description="TOTP code length")
    
    # Email Configuration
    MAIL_USERNAME: Optional[str] = Field(default=None, description="SMTP username")
    MAIL_PASSWORD: Optional[str] = Field(default=None, description="SMTP password")
    MAIL_FROM: Optional[str] = Field(default=None, description="Sender email address")
    MAIL_PORT: int = Field(default=587, description="SMTP port")
    MAIL_SERVER: Optional[str] = Field(default=None, description="SMTP server")
    MAIL_STARTTLS: bool = Field(default=True, description="Use STARTTLS")
    MAIL_SSL_TLS: bool = Field(default=False, description="Use SSL/TLS")
    
    # SMS Configuration (Twilio)
    TWILIO_ACCOUNT_SID: Optional[str] = Field(default=None, description="Twilio Account SID")
    TWILIO_AUTH_TOKEN: Optional[str] = Field(default=None, description="Twilio Auth Token")
    TWILIO_PHONE_NUMBER: Optional[str] = Field(default=None, description="Twilio Phone Number")
    
    # Risk Assessment Configuration
    ENABLE_RISK_ASSESSMENT: bool = Field(default=True, description="Enable risk-based authentication")
    MAX_SECURITY_LEVEL: int = Field(default=4, description="Maximum security level (0-4)")
    RISK_LOW_THRESHOLD: float = Field(default=25.0, description="Low risk threshold score")
    RISK_MEDIUM_THRESHOLD: float = Field(default=50.0, description="Medium risk threshold score")
    RISK_HIGH_THRESHOLD: float = Field(default=75.0, description="High risk threshold score")
    
    # Session Monitoring
    ENABLE_SESSION_MONITORING: bool = Field(default=True, description="Enable continuous session verification")
    SESSION_CHECK_INTERVAL: int = Field(default=300, description="Session check interval in seconds")
    MAX_CONCURRENT_SESSIONS: int = Field(default=5, description="Max concurrent sessions per user")
    
    # Rate Limiting
    MAX_LOGIN_ATTEMPTS: int = Field(default=5, description="Max failed login attempts before lockout")
    LOCKOUT_DURATION_MINUTES: int = Field(default=15, description="Account lockout duration")
    REQUEST_RATE_LIMIT: int = Field(default=100, description="Max requests per minute")
    
    # Security Alerts
    ENABLE_SECURITY_ALERTS: bool = Field(default=True, description="Send security alert emails")
    ALERT_ON_NEW_DEVICE: bool = Field(default=True, description="Alert on new device login")
    ALERT_ON_NEW_LOCATION: bool = Field(default=True, description="Alert on new location login")
    ALERT_ON_SUSPICIOUS_ACTIVITY: bool = Field(default=True, description="Alert on suspicious activity")
    
    # Password Policy
    MIN_PASSWORD_LENGTH: int = Field(default=8, description="Minimum password length")
    REQUIRE_UPPERCASE: bool = Field(default=True, description="Require uppercase in password")
    REQUIRE_LOWERCASE: bool = Field(default=True, description="Require lowercase in password")
    REQUIRE_DIGIT: bool = Field(default=True, description="Require digit in password")
    REQUIRE_SPECIAL: bool = Field(default=False, description="Require special character in password")
    
    # CORS Configuration
    CORS_ORIGINS: List[str] = Field(default=["*"], description="Allowed CORS origins")
    CORS_ALLOW_CREDENTIALS: bool = Field(default=True, description="Allow credentials in CORS")
    
    class Config:
        env_prefix = "ADAPTIVEAUTH_"
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


class RiskFactorWeights(BaseSettings):
    """Configuration for risk factor weights in risk assessment."""
    
    DEVICE_WEIGHT: float = Field(default=25.0, description="Weight for device factor")
    LOCATION_WEIGHT: float = Field(default=25.0, description="Weight for location factor")
    TIME_WEIGHT: float = Field(default=15.0, description="Weight for time factor")
    VELOCITY_WEIGHT: float = Field(default=20.0, description="Weight for velocity factor")
    BEHAVIOR_WEIGHT: float = Field(default=15.0, description="Weight for behavior factor")
    
    class Config:
        env_prefix = "ADAPTIVEAUTH_RISK_"
        env_file = ".env"
        extra = "ignore"  # Ignore extra fields that don't belong to this config


@lru_cache()
def get_settings() -> AdaptiveAuthSettings:
    """Get cached settings instance."""
    return AdaptiveAuthSettings()


@lru_cache()
def get_risk_weights() -> RiskFactorWeights:
    """Get cached risk factor weights."""
    return RiskFactorWeights()
