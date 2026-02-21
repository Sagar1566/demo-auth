"""
AdaptiveAuth Authentication Service
Main authentication logic combining JWT, 2FA, and risk assessment.
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session
import uuid

from ..config import get_settings
from ..models import (
    User, UserProfile, LoginAttempt, TokenBlacklist,
    PasswordResetCode, EmailVerificationCode, StepUpChallenge,
    RiskLevel
)
from ..core.security import (
    hash_password, verify_password, create_access_token,
    generate_session_token, generate_reset_code, generate_verification_code
)
from ..risk.engine import RiskEngine, RiskAssessment
from ..risk.analyzer import BehaviorAnalyzer
from ..risk.monitor import SessionMonitor, AnomalyDetector
from .otp import get_otp_service
from .email import get_email_service


class AuthService:
    """
    Main authentication service combining all auth features.
    Implements adaptive authentication based on risk assessment.
    """
    
    def __init__(self, db: Session):
        self.db = db
        self.settings = get_settings()
        self.risk_engine = RiskEngine(db)
        self.behavior_analyzer = BehaviorAnalyzer(db)
        self.session_monitor = SessionMonitor(db)
        self.anomaly_detector = AnomalyDetector(db)
        self.otp_service = get_otp_service()
        self.email_service = get_email_service()
    
    async def register_user(
        self,
        email: str,
        password: str,
        full_name: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> Tuple[User, Optional[str]]:
        """
        Register a new user.
        Returns (user, verification_code).
        """
        # Check if user exists
        existing = self.db.query(User).filter(User.email == email).first()
        if existing:
            raise ValueError("User with this email already exists")
        
        # Create user
        user = User(
            email=email,
            password_hash=hash_password(password),
            full_name=full_name,
            is_active=True,
            is_verified=False,
            created_at=datetime.utcnow()
        )
        
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        
        # Create profile
        self.behavior_analyzer.get_or_create_profile(user)
        
        # Generate verification code
        verification_code = generate_verification_code()
        verification = EmailVerificationCode(
            user_id=user.id,
            email=email,
            verification_type="email",
            verification_code=verification_code,
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        self.db.add(verification)
        self.db.commit()
        
        # Send verification email
        await self.email_service.send_verification_code(email, verification_code)
        
        return user, verification_code
    
    async def adaptive_login(
        self,
        email: str,
        password: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Adaptive login with risk-based authentication.
        
        Returns:
            {
                'status': 'success' | 'challenge_required' | 'blocked',
                'risk_level': str,
                'security_level': int,
                'access_token': str (if success),
                'challenge_type': str (if challenge_required),
                'challenge_id': str (if challenge_required),
                'message': str
            }
        """
        # Check for anomalies from this IP
        self.anomaly_detector.detect_brute_force(context.get('ip_address', ''))
        self.anomaly_detector.detect_credential_stuffing(context.get('ip_address', ''))
        
        # Find user
        user = self.db.query(User).filter(User.email == email).first()
        
        if not user:
            # Log failed attempt for unknown user
            self._log_login_attempt(
                None, email, context, False, "user_not_found"
            )
            return {
                'status': 'blocked',
                'risk_level': RiskLevel.HIGH.value,
                'security_level': 4,
                'message': 'Invalid credentials'
            }
        
        # Check if user is locked
        if user.is_locked:
            if user.locked_until and user.locked_until > datetime.utcnow():
                return {
                    'status': 'blocked',
                    'risk_level': RiskLevel.CRITICAL.value,
                    'security_level': 4,
                    'message': 'Account is temporarily locked'
                }
            else:
                # Unlock if lockout expired
                user.is_locked = False
                user.locked_until = None
                self.db.commit()
        
        # Verify password
        if not verify_password(password, user.password_hash):
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.utcnow()
            
            # Lock account after too many failures
            if user.failed_login_attempts >= self.settings.MAX_LOGIN_ATTEMPTS:
                user.is_locked = True
                user.locked_until = datetime.utcnow() + timedelta(
                    minutes=self.settings.LOCKOUT_DURATION_MINUTES
                )
            
            self.db.commit()
            
            self._log_login_attempt(user, email, context, False, "invalid_password")
            
            return {
                'status': 'blocked',
                'risk_level': RiskLevel.HIGH.value,
                'security_level': 4,
                'message': 'Invalid credentials'
            }
        
        # Password correct - perform risk assessment
        profile = self.behavior_analyzer.get_or_create_profile(user)
        assessment = self.risk_engine.evaluate_risk(user, context, profile)
        
        # Log the attempt
        self._log_login_attempt(
            user, email, context, True, None,
            assessment.risk_score, assessment.risk_level.value,
            assessment.security_level, assessment.risk_factors
        )
        
        # Log risk event
        self.risk_engine.log_risk_event(user, 'login', assessment, context)
        
        # Handle based on security level
        if assessment.security_level >= 4 or assessment.required_action == 'blocked':
            return {
                'status': 'blocked',
                'risk_level': assessment.risk_level.value,
                'security_level': assessment.security_level,
                'message': assessment.message or 'Access denied due to security concerns'
            }
        
        if assessment.security_level >= 2:
            # Require step-up authentication
            challenge = await self._create_challenge(
                user, assessment.required_action or '2fa', context
            )
            
            return {
                'status': 'challenge_required',
                'risk_level': assessment.risk_level.value,
                'security_level': assessment.security_level,
                'challenge_type': challenge['type'],
                'challenge_id': challenge['id'],
                'message': assessment.message or 'Additional verification required'
            }
        
        # Low risk - grant access
        return await self._complete_login(user, context, assessment, profile)
    
    async def verify_step_up(
        self,
        challenge_id: str,
        code: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Verify step-up authentication challenge."""
        
        challenge = self.db.query(StepUpChallenge).filter(
            StepUpChallenge.id == int(challenge_id)
        ).first()
        
        if not challenge:
            return {
                'status': 'error',
                'message': 'Invalid challenge'
            }
        
        if challenge.is_completed:
            return {
                'status': 'error',
                'message': 'Challenge already completed'
            }
        
        if challenge.expires_at < datetime.utcnow():
            return {
                'status': 'error',
                'message': 'Challenge expired'
            }
        
        if challenge.attempts >= challenge.max_attempts:
            return {
                'status': 'error',
                'message': 'Too many attempts'
            }
        
        # Verify based on challenge type
        user = self.db.query(User).filter(User.id == challenge.user_id).first()
        verified = False
        
        if challenge.challenge_type == 'otp':
            verified = self.otp_service.verify_otp(user.tfa_secret, code)
        elif challenge.challenge_type == 'email':
            verified = challenge.challenge_code == code
        
        challenge.attempts += 1
        
        if not verified:
            self.db.commit()
            return {
                'status': 'error',
                'message': 'Invalid verification code',
                'attempts_remaining': challenge.max_attempts - challenge.attempts
            }
        
        # Challenge completed
        challenge.is_completed = True
        challenge.completed_at = datetime.utcnow()
        self.db.commit()
        
        # Complete login
        profile = self.behavior_analyzer.get_or_create_profile(user)
        assessment = self.risk_engine.evaluate_risk(user, context, profile)
        assessment.security_level = 0  # Step-up completed
        
        return await self._complete_login(user, context, assessment, profile)
    
    async def _complete_login(
        self,
        user: User,
        context: Dict[str, Any],
        assessment: RiskAssessment,
        profile: UserProfile
    ) -> Dict[str, Any]:
        """Complete login and return tokens."""
        
        # Reset failed attempts
        user.failed_login_attempts = 0
        user.last_successful_login = datetime.utcnow()
        user.is_active = True
        self.db.commit()
        
        # Update behavior profile
        self.behavior_analyzer.update_profile_on_login(user, context, True)
        self.behavior_analyzer.add_risk_score_to_history(
            profile, assessment.risk_score, assessment.risk_factors
        )
        
        # Create tokens
        expires_delta = timedelta(minutes=self.settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            subject=user.email,
            expires_delta=expires_delta,
            extra_claims={'user_id': user.id, 'role': user.role}
        )
        
        # Create session
        session = self.session_monitor.create_session(
            user=user,
            context=context,
            risk_assessment=assessment,
            token=generate_session_token(),
            expires_at=datetime.utcnow() + expires_delta
        )
        
        return {
            'status': 'success',
            'risk_level': assessment.risk_level.value,
            'security_level': assessment.security_level,
            'access_token': access_token,
            'token_type': 'bearer',
            'expires_in': self.settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            'user_info': {
                'id': user.id,
                'email': user.email,
                'full_name': user.full_name,
                'role': user.role
            }
        }
    
    async def _create_challenge(
        self,
        user: User,
        challenge_type: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a step-up authentication challenge."""
        
        # Determine best challenge type
        if challenge_type == '2fa' and user.tfa_enabled:
            actual_type = 'otp'
            code = None  # OTP is generated by authenticator app
        else:
            actual_type = 'email'
            code = generate_verification_code()
        
        # Create challenge
        challenge = StepUpChallenge(
            user_id=user.id,
            challenge_type=actual_type,
            challenge_code=code,
            expires_at=datetime.utcnow() + timedelta(minutes=15)
        )
        
        self.db.add(challenge)
        self.db.commit()
        self.db.refresh(challenge)
        
        # Send code if email challenge
        if actual_type == 'email':
            await self.email_service.send_verification_code(user.email, code)
        
        return {
            'id': str(challenge.id),
            'type': actual_type
        }
    
    def _log_login_attempt(
        self,
        user: Optional[User],
        email: str,
        context: Dict[str, Any],
        success: bool,
        failure_reason: Optional[str] = None,
        risk_score: float = 0.0,
        risk_level: str = RiskLevel.LOW.value,
        security_level: int = 0,
        risk_factors: Optional[Dict[str, float]] = None
    ):
        """Log a login attempt."""
        attempt = LoginAttempt(
            user_id=user.id if user else None,
            email=email,
            ip_address=context.get('ip_address', ''),
            user_agent=context.get('user_agent', ''),
            device_fingerprint=context.get('device_fingerprint'),
            country=context.get('country'),
            city=context.get('city'),
            risk_score=risk_score,
            risk_level=risk_level,
            security_level=security_level,
            risk_factors=risk_factors or {},
            success=success,
            failure_reason=failure_reason,
            attempted_at=datetime.utcnow()
        )
        
        self.db.add(attempt)
        self.db.commit()
    
    async def request_password_reset(self, email: str) -> bool:
        """Request password reset."""
        user = self.db.query(User).filter(User.email == email).first()
        
        if not user:
            # Don't reveal if user exists
            return True
        
        # Create reset code
        reset_code = generate_reset_code()
        reset = PasswordResetCode(
            user_id=user.id,
            email=email,
            reset_code=reset_code,
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        
        self.db.add(reset)
        self.db.commit()
        
        # Send email
        await self.email_service.send_password_reset(
            email, reset_code, "http://localhost:8000/reset-password"
        )
        
        return True
    
    async def reset_password(
        self,
        reset_token: str,
        new_password: str
    ) -> bool:
        """Reset password with token."""
        reset = self.db.query(PasswordResetCode).filter(
            PasswordResetCode.reset_code == reset_token,
            PasswordResetCode.is_used == False,
            PasswordResetCode.expires_at > datetime.utcnow()
        ).first()
        
        if not reset:
            raise ValueError("Invalid or expired reset token")
        
        user = self.db.query(User).filter(User.id == reset.user_id).first()
        if not user:
            raise ValueError("User not found")
        
        # Update password
        user.password_hash = hash_password(new_password)
        user.password_changed_at = datetime.utcnow()
        
        # Mark reset code as used
        reset.is_used = True
        
        # Revoke all sessions
        self.session_monitor.revoke_all_sessions(user)
        
        self.db.commit()
        
        return True
    
    def logout(self, token: str, user: User):
        """Logout user and blacklist token."""
        # Blacklist token
        blacklist = TokenBlacklist(
            token=token,
            user_id=user.id,
            reason="logout",
            blacklisted_at=datetime.utcnow()
        )
        
        self.db.add(blacklist)
        self.db.commit()
    
    def enable_2fa(self, user: User) -> Dict[str, Any]:
        """Enable 2FA for user."""
        secret = self.otp_service.generate_secret()
        qr_code = self.otp_service.generate_qr_code(user.email, secret)
        backup_codes, hashed_codes = self.otp_service.generate_backup_codes()
        
        # Store secret temporarily (user must verify before permanent)
        user.tfa_secret = secret
        self.db.commit()
        
        return {
            'secret': secret,
            'qr_code': qr_code,
            'backup_codes': backup_codes
        }
    
    def verify_and_activate_2fa(self, user: User, otp: str) -> bool:
        """Verify OTP and activate 2FA."""
        if not user.tfa_secret:
            raise ValueError("2FA not initialized")
        
        if not self.otp_service.verify_otp(user.tfa_secret, otp):
            return False
        
        user.tfa_enabled = True
        self.db.commit()
        
        return True
    
    def disable_2fa(self, user: User, password: str) -> bool:
        """Disable 2FA for user."""
        if not verify_password(password, user.password_hash):
            return False
        
        user.tfa_enabled = False
        user.tfa_secret = None
        self.db.commit()
        
        return True
