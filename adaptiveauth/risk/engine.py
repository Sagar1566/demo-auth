"""
AdaptiveAuth Risk Engine
Core risk assessment engine for adaptive authentication.
Based on Risk-Based-Authentication-master, enhanced with modern features.
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
from sqlalchemy.orm import Session

from ..config import get_settings, get_risk_weights
from ..models import (
    User, UserProfile, LoginAttempt, RiskEvent, UserSession,
    RiskLevel, SecurityLevel, AnomalyPattern
)


@dataclass
class RiskAssessment:
    """Result of risk assessment."""
    risk_score: float  # 0-100
    risk_level: RiskLevel
    security_level: int  # 0-4
    risk_factors: Dict[str, float]
    required_action: Optional[str]  # None, 'password', 'email_verify', '2fa', 'blocked'
    triggered_rules: List[str]
    message: Optional[str] = None


class RiskEngine:
    """
    Core risk assessment engine.
    
    Security Levels (from Risk-Based-Authentication-master):
    - Level 0: Known device + IP + browser → Minimal auth (remember me)
    - Level 1: Unknown browser → Password only
    - Level 2: Unknown IP → Password + email verification
    - Level 3: Unknown device → Password + 2FA required
    - Level 4: Suspicious pattern → Blocked or full verification
    """
    
    MAX_SECURITY_LEVEL = 4
    
    def __init__(self, db: Session):
        self.db = db
        self.settings = get_settings()
        self.weights = get_risk_weights()
    
    def evaluate_risk(
        self,
        user: User,
        context: Dict[str, Any],
        profile: Optional[UserProfile] = None
    ) -> RiskAssessment:
        """
        Evaluate risk for a login attempt.
        
        Args:
            user: The user attempting to login
            context: Request context (ip_address, user_agent, device_fingerprint, etc.)
            profile: User's behavioral profile
        
        Returns:
            RiskAssessment with score, level, and required action
        """
        from .factors import (
            DeviceFactor, LocationFactor, TimeFactor,
            VelocityFactor, BehaviorFactor
        )
        
        # Get or create profile
        if profile is None:
            profile = self.db.query(UserProfile).filter(
                UserProfile.user_id == user.id
            ).first()
        
        # Initialize factors
        risk_factors = {}
        triggered_rules = []
        
        # Calculate each risk factor
        device_factor = DeviceFactor(self.db, self.weights)
        location_factor = LocationFactor(self.db, self.weights)
        time_factor = TimeFactor(self.db, self.weights)
        velocity_factor = VelocityFactor(self.db, self.weights)
        behavior_factor = BehaviorFactor(self.db, self.weights)
        
        # Device Risk
        device_score, device_rules = device_factor.calculate(user, context, profile)
        risk_factors['device'] = device_score
        triggered_rules.extend(device_rules)
        
        # Location Risk
        location_score, location_rules = location_factor.calculate(user, context, profile)
        risk_factors['location'] = location_score
        triggered_rules.extend(location_rules)
        
        # Time Pattern Risk
        time_score, time_rules = time_factor.calculate(user, context, profile)
        risk_factors['time'] = time_score
        triggered_rules.extend(time_rules)
        
        # Velocity Risk (rapid attempts)
        velocity_score, velocity_rules = velocity_factor.calculate(user, context, profile)
        risk_factors['velocity'] = velocity_score
        triggered_rules.extend(velocity_rules)
        
        # Behavior Anomaly Risk
        behavior_score, behavior_rules = behavior_factor.calculate(user, context, profile)
        risk_factors['behavior'] = behavior_score
        triggered_rules.extend(behavior_rules)
        
        # Calculate weighted total score
        total_score = (
            risk_factors['device'] * (self.weights.DEVICE_WEIGHT / 100) +
            risk_factors['location'] * (self.weights.LOCATION_WEIGHT / 100) +
            risk_factors['time'] * (self.weights.TIME_WEIGHT / 100) +
            risk_factors['velocity'] * (self.weights.VELOCITY_WEIGHT / 100) +
            risk_factors['behavior'] * (self.weights.BEHAVIOR_WEIGHT / 100)
        )
        
        # Normalize to 0-100
        total_score = min(100, max(0, total_score))
        
        # Determine risk level
        risk_level = self._determine_risk_level(total_score)
        
        # Determine security level (0-4 system)
        security_level = self._determine_security_level(
            risk_factors, profile, triggered_rules
        )
        
        # Determine required action
        required_action, message = self._determine_action(
            risk_level, security_level, user, triggered_rules
        )
        
        return RiskAssessment(
            risk_score=round(total_score, 2),
            risk_level=risk_level,
            security_level=security_level,
            risk_factors=risk_factors,
            required_action=required_action,
            triggered_rules=triggered_rules,
            message=message
        )
    
    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level from score."""
        if score >= self.settings.RISK_HIGH_THRESHOLD:
            return RiskLevel.CRITICAL
        elif score >= self.settings.RISK_MEDIUM_THRESHOLD:
            return RiskLevel.HIGH
        elif score >= self.settings.RISK_LOW_THRESHOLD:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _determine_security_level(
        self,
        risk_factors: Dict[str, float],
        profile: Optional[UserProfile],
        triggered_rules: List[str]
    ) -> int:
        """
        Determine security level (0-4) based on risk factors.
        
        Level 0: All known (device + IP + browser)
        Level 1: Unknown browser only
        Level 2: Unknown IP
        Level 3: Unknown device
        Level 4: Suspicious pattern or critical risk
        """
        # Check for critical rules
        critical_rules = ['brute_force', 'impossible_travel', 'credential_stuffing', 'blocked_ip']
        if any(rule in triggered_rules for rule in critical_rules):
            return SecurityLevel.LEVEL_4.value
        
        # No profile = new user = high security
        if profile is None:
            return SecurityLevel.LEVEL_3.value
        
        security_level = 0
        
        # Check each factor
        if risk_factors.get('device', 0) > 50:
            security_level = max(security_level, SecurityLevel.LEVEL_3.value)
        
        if risk_factors.get('location', 0) > 50:
            security_level = max(security_level, SecurityLevel.LEVEL_2.value)
        
        if risk_factors.get('behavior', 0) > 50:
            security_level = max(security_level, SecurityLevel.LEVEL_1.value)
        
        # Velocity issues are serious
        if risk_factors.get('velocity', 0) > 70:
            security_level = max(security_level, SecurityLevel.LEVEL_4.value)
        
        return security_level
    
    def _determine_action(
        self,
        risk_level: RiskLevel,
        security_level: int,
        user: User,
        triggered_rules: List[str]
    ) -> Tuple[Optional[str], Optional[str]]:
        """Determine required authentication action."""
        
        # Critical rules = block
        if 'brute_force' in triggered_rules:
            return 'blocked', 'Too many failed attempts. Please try again later.'
        
        if 'credential_stuffing' in triggered_rules:
            return 'blocked', 'Suspicious activity detected. Access temporarily blocked.'
        
        if 'impossible_travel' in triggered_rules:
            return '2fa', 'Unusual location detected. Please verify your identity.'
        
        # Based on security level
        if security_level == SecurityLevel.LEVEL_4.value:
            return 'blocked', 'Access denied due to security concerns.'
        
        if security_level == SecurityLevel.LEVEL_3.value:
            if user.tfa_enabled:
                return '2fa', 'Additional verification required.'
            return 'email_verify', 'Please verify your email to continue.'
        
        if security_level == SecurityLevel.LEVEL_2.value:
            return 'email_verify', 'New location detected. Please verify your email.'
        
        if security_level == SecurityLevel.LEVEL_1.value:
            return 'password', None  # Just password, normal flow
        
        # Level 0 - trusted environment
        return None, None
    
    def log_risk_event(
        self,
        user: Optional[User],
        event_type: str,
        assessment: RiskAssessment,
        context: Dict[str, Any],
        action_taken: Optional[str] = None
    ) -> RiskEvent:
        """Log a risk event to the database."""
        
        event = RiskEvent(
            user_id=user.id if user else None,
            event_type=event_type,
            risk_score=assessment.risk_score,
            risk_level=assessment.risk_level.value,
            security_level=assessment.security_level,
            ip_address=context.get('ip_address'),
            user_agent=context.get('user_agent'),
            device_fingerprint=context.get('device_fingerprint'),
            risk_factors=assessment.risk_factors,
            triggered_rules=assessment.triggered_rules,
            action_required=assessment.required_action,
            action_taken=action_taken,
            created_at=datetime.utcnow()
        )
        
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        
        return event
    
    def evaluate_new_user_risk(self, context: Dict[str, Any]) -> RiskAssessment:
        """Evaluate risk for a new/unknown user (registration or unknown login)."""
        from .factors import VelocityFactor
        
        risk_factors = {
            'device': 50.0,  # Unknown device
            'location': 50.0,  # Unknown location
            'time': 0.0,  # No pattern to compare
            'velocity': 0.0,
            'behavior': 50.0  # Unknown behavior
        }
        
        triggered_rules = ['new_user']
        
        # Check velocity for IP
        velocity_factor = VelocityFactor(self.db, self.weights)
        velocity_score, velocity_rules = velocity_factor.calculate_for_ip(
            context.get('ip_address')
        )
        risk_factors['velocity'] = velocity_score
        triggered_rules.extend(velocity_rules)
        
        # Calculate score
        total_score = sum(risk_factors.values()) / len(risk_factors)
        
        # New users start at security level 3 (require 2FA or email verify)
        return RiskAssessment(
            risk_score=round(total_score, 2),
            risk_level=RiskLevel.MEDIUM,
            security_level=SecurityLevel.LEVEL_3.value,
            risk_factors=risk_factors,
            required_action='email_verify',
            triggered_rules=triggered_rules,
            message='Please verify your email to complete registration.'
        )
