"""
AdaptiveAuth Risk Factors
Individual risk factor calculators for adaptive authentication.
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func

from ..config import RiskFactorWeights
from ..models import User, UserProfile, LoginAttempt, AnomalyPattern


class BaseFactor:
    """Base class for risk factors."""
    
    def __init__(self, db: Session, weights: RiskFactorWeights):
        self.db = db
        self.weights = weights
    
    def calculate(
        self,
        user: User,
        context: Dict[str, Any],
        profile: Optional[UserProfile]
    ) -> Tuple[float, List[str]]:
        """Calculate risk score (0-100) and triggered rules."""
        raise NotImplementedError


class DeviceFactor(BaseFactor):
    """
    Device fingerprint risk assessment.
    Checks if the device/browser is known to the user.
    """
    
    def calculate(
        self,
        user: User,
        context: Dict[str, Any],
        profile: Optional[UserProfile]
    ) -> Tuple[float, List[str]]:
        score = 0.0
        rules = []
        
        device_fingerprint = context.get('device_fingerprint')
        user_agent = context.get('user_agent', '')
        
        if profile is None:
            return 75.0, ['new_user_device']
        
        known_devices = profile.known_devices or []
        known_browsers = profile.known_browsers or []
        
        # Check device fingerprint
        device_known = False
        if device_fingerprint:
            device_known = any(
                d.get('fingerprint') == device_fingerprint
                for d in known_devices
            )
        
        # Check browser/user agent
        browser_known = any(
            b.get('user_agent') == user_agent
            for b in known_browsers
        )
        
        if not device_known and device_fingerprint:
            score += 50.0
            rules.append('unknown_device')
        
        if not browser_known and user_agent:
            score += 30.0
            rules.append('unknown_browser')
        
        # Check for suspicious user agent patterns
        suspicious_agents = ['curl', 'wget', 'python-requests', 'scrapy', 'bot']
        if any(agent in user_agent.lower() for agent in suspicious_agents):
            score += 20.0
            rules.append('suspicious_user_agent')
        
        return min(100, score), rules


class LocationFactor(BaseFactor):
    """
    IP address and location risk assessment.
    Checks for new IPs, impossible travel, etc.
    """
    
    def calculate(
        self,
        user: User,
        context: Dict[str, Any],
        profile: Optional[UserProfile]
    ) -> Tuple[float, List[str]]:
        score = 0.0
        rules = []
        
        ip_address = context.get('ip_address', '')
        
        if profile is None:
            return 50.0, ['new_user_location']
        
        known_ips = profile.known_ips or []
        
        # Check if IP is known
        ip_known = any(
            ip.get('ip') == ip_address
            for ip in known_ips
        )
        
        if not ip_known:
            score += 40.0
            rules.append('unknown_ip')
            
            # Check for impossible travel
            if self._check_impossible_travel(user, ip_address, profile):
                score += 40.0
                rules.append('impossible_travel')
        
        # Check for suspicious IP patterns
        if self._is_vpn_or_proxy(ip_address):
            score += 20.0
            rules.append('vpn_proxy_detected')
        
        # Check for TOR exit nodes (simplified)
        if self._is_tor_exit_node(ip_address):
            score += 30.0
            rules.append('tor_detected')
        
        return min(100, score), rules
    
    def _check_impossible_travel(
        self,
        user: User,
        current_ip: str,
        profile: UserProfile
    ) -> bool:
        """Check if login from this IP would require impossible travel speed."""
        # Get last successful login
        last_login = self.db.query(LoginAttempt).filter(
            LoginAttempt.user_id == user.id,
            LoginAttempt.success == True,
            LoginAttempt.attempted_at >= datetime.utcnow() - timedelta(hours=1)
        ).order_by(LoginAttempt.attempted_at.desc()).first()
        
        if not last_login or not last_login.latitude:
            return False
        
        # Simplified check - in production, calculate actual distance
        # If same IP, no travel
        if last_login.ip_address == current_ip:
            return False
        
        # If login was within last 10 minutes and different IP, could be suspicious
        if last_login.attempted_at >= datetime.utcnow() - timedelta(minutes=10):
            return True
        
        return False
    
    def _is_vpn_or_proxy(self, ip_address: str) -> bool:
        """Check if IP is a known VPN/proxy. Simplified implementation."""
        # In production, use IP reputation services
        return False
    
    def _is_tor_exit_node(self, ip_address: str) -> bool:
        """Check if IP is a TOR exit node. Simplified implementation."""
        # In production, use TOR exit node lists
        return False


class TimeFactor(BaseFactor):
    """
    Time-based risk assessment.
    Checks if login time matches user's typical patterns.
    """
    
    def calculate(
        self,
        user: User,
        context: Dict[str, Any],
        profile: Optional[UserProfile]
    ) -> Tuple[float, List[str]]:
        score = 0.0
        rules = []
        
        current_hour = datetime.utcnow().hour
        current_day = datetime.utcnow().weekday()
        
        if profile is None:
            return 0.0, []  # No pattern to compare
        
        typical_hours = profile.typical_login_hours or []
        typical_days = profile.typical_login_days or []
        
        # Check if current time is within typical hours
        if typical_hours and current_hour not in typical_hours:
            score += 30.0
            rules.append('unusual_hour')
        
        # Check if current day is typical
        if typical_days and current_day not in typical_days:
            score += 20.0
            rules.append('unusual_day')
        
        # Late night logins (2-5 AM) are more suspicious
        if 2 <= current_hour <= 5:
            score += 20.0
            rules.append('late_night_login')
        
        return min(100, score), rules


class VelocityFactor(BaseFactor):
    """
    Velocity-based risk assessment.
    Checks for rapid login attempts, brute force, etc.
    """
    
    def calculate(
        self,
        user: User,
        context: Dict[str, Any],
        profile: Optional[UserProfile]
    ) -> Tuple[float, List[str]]:
        score = 0.0
        rules = []
        
        ip_address = context.get('ip_address', '')
        
        # Check failed attempts for this user
        recent_failures = self.db.query(LoginAttempt).filter(
            LoginAttempt.user_id == user.id,
            LoginAttempt.success == False,
            LoginAttempt.attempted_at >= datetime.utcnow() - timedelta(minutes=15)
        ).count()
        
        if recent_failures >= 10:
            score += 80.0
            rules.append('brute_force')
        elif recent_failures >= 5:
            score += 50.0
            rules.append('multiple_failures')
        elif recent_failures >= 3:
            score += 25.0
            rules.append('some_failures')
        
        # Check attempts from this IP across all users
        ip_attempts = self.db.query(LoginAttempt).filter(
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.attempted_at >= datetime.utcnow() - timedelta(minutes=15)
        ).count()
        
        if ip_attempts >= 20:
            score += 40.0
            rules.append('credential_stuffing')
        elif ip_attempts >= 10:
            score += 20.0
            rules.append('high_ip_volume')
        
        return min(100, score), rules
    
    def calculate_for_ip(self, ip_address: str) -> Tuple[float, List[str]]:
        """Calculate velocity risk for an IP (for new users)."""
        score = 0.0
        rules = []
        
        if not ip_address:
            return 0.0, []
        
        # Check attempts from this IP
        recent_attempts = self.db.query(LoginAttempt).filter(
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.attempted_at >= datetime.utcnow() - timedelta(minutes=15)
        ).count()
        
        recent_failures = self.db.query(LoginAttempt).filter(
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.success == False,
            LoginAttempt.attempted_at >= datetime.utcnow() - timedelta(minutes=15)
        ).count()
        
        if recent_failures >= 10:
            score += 60.0
            rules.append('ip_brute_force')
        
        if recent_attempts >= 20:
            score += 40.0
            rules.append('credential_stuffing')
        
        return min(100, score), rules


class BehaviorFactor(BaseFactor):
    """
    Behavioral anomaly detection.
    Compares current behavior to historical patterns.
    """
    
    def calculate(
        self,
        user: User,
        context: Dict[str, Any],
        profile: Optional[UserProfile]
    ) -> Tuple[float, List[str]]:
        score = 0.0
        rules = []
        
        if profile is None:
            return 30.0, ['no_profile']
        
        # Check for existing anomaly patterns for this user
        active_anomalies = self.db.query(AnomalyPattern).filter(
            AnomalyPattern.user_id == user.id,
            AnomalyPattern.is_active == True,
            AnomalyPattern.false_positive == False
        ).all()
        
        for anomaly in active_anomalies:
            if anomaly.severity == 'critical':
                score += 50.0
                rules.append(f'anomaly_{anomaly.pattern_type}')
            elif anomaly.severity == 'high':
                score += 30.0
                rules.append(f'anomaly_{anomaly.pattern_type}')
            elif anomaly.severity == 'medium':
                score += 15.0
                rules.append(f'anomaly_{anomaly.pattern_type}')
        
        # Check login frequency
        last_week_logins = self.db.query(LoginAttempt).filter(
            LoginAttempt.user_id == user.id,
            LoginAttempt.success == True,
            LoginAttempt.attempted_at >= datetime.utcnow() - timedelta(days=7)
        ).count()
        
        # If user normally logs in rarely but suddenly has many logins
        if profile.total_logins > 0:
            avg_weekly_logins = profile.total_logins / max(1, (datetime.utcnow() - profile.created_at).days / 7)
            if last_week_logins > avg_weekly_logins * 3 and last_week_logins > 5:
                score += 20.0
                rules.append('unusual_login_frequency')
        
        # Check for pattern changes
        if self._detect_session_anomaly(user, profile):
            score += 15.0
            rules.append('session_anomaly')
        
        return min(100, score), rules
    
    def _detect_session_anomaly(self, user: User, profile: UserProfile) -> bool:
        """Detect anomalies in session behavior."""
        if not profile.average_session_duration:
            return False
        
        # Get recent session durations
        recent_sessions = self.db.query(LoginAttempt).filter(
            LoginAttempt.user_id == user.id,
            LoginAttempt.success == True,
            LoginAttempt.attempted_at >= datetime.utcnow() - timedelta(days=1)
        ).all()
        
        # Simplified check - in production, use statistical analysis
        return len(recent_sessions) > 10  # Too many sessions in 24h
