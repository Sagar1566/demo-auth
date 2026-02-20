"""
AdaptiveAuth Behavioral Analyzer
Analyzes and updates user behavior profiles.
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from collections import Counter

from ..models import User, UserProfile, LoginAttempt


class BehaviorAnalyzer:
    """
    Analyzes user behavior and maintains behavioral profiles.
    Based on Risk-Based-Authentication-master user tracking.
    """
    
    def __init__(self, db: Session):
        self.db = db
    
    def get_or_create_profile(self, user: User) -> UserProfile:
        """Get existing profile or create new one for user."""
        profile = self.db.query(UserProfile).filter(
            UserProfile.user_id == user.id
        ).first()
        
        if not profile:
            profile = UserProfile(
                user_id=user.id,
                known_devices=[],
                known_browsers=[],
                known_ips=[],
                typical_login_hours=[],
                typical_login_days=[],
                risk_score_history=[],
                total_logins=0,
                successful_logins=0,
                failed_logins=0
            )
            self.db.add(profile)
            self.db.commit()
            self.db.refresh(profile)
        
        return profile
    
    def update_profile_on_login(
        self,
        user: User,
        context: Dict[str, Any],
        success: bool
    ) -> UserProfile:
        """Update user profile after a login attempt."""
        profile = self.get_or_create_profile(user)
        
        now = datetime.utcnow()
        ip_address = context.get('ip_address', '')
        user_agent = context.get('user_agent', '')
        device_fingerprint = context.get('device_fingerprint')
        
        # Update login counts
        profile.total_logins += 1
        if success:
            profile.successful_logins += 1
        else:
            profile.failed_logins += 1
        
        if success:
            # Update known IPs
            self._update_known_ips(profile, ip_address, context)
            
            # Update known browsers
            self._update_known_browsers(profile, user_agent)
            
            # Update known devices
            if device_fingerprint:
                self._update_known_devices(profile, device_fingerprint, context)
            
            # Update login patterns
            self._update_login_patterns(profile, now)
        
        profile.updated_at = now
        self.db.commit()
        self.db.refresh(profile)
        
        return profile
    
    def _update_known_ips(
        self,
        profile: UserProfile,
        ip_address: str,
        context: Dict[str, Any]
    ):
        """Update known IP addresses list."""
        if not ip_address:
            return
        
        known_ips = profile.known_ips or []
        now = datetime.utcnow().isoformat()
        
        # Check if IP already known
        ip_found = False
        for ip in known_ips:
            if ip.get('ip') == ip_address:
                ip['last_seen'] = now
                ip['count'] = ip.get('count', 0) + 1
                ip_found = True
                break
        
        if not ip_found:
            known_ips.append({
                'ip': ip_address,
                'country': context.get('country'),
                'city': context.get('city'),
                'first_seen': now,
                'last_seen': now,
                'count': 1
            })
        
        # Keep only last 20 IPs
        if len(known_ips) > 20:
            known_ips = sorted(
                known_ips,
                key=lambda x: x.get('last_seen', ''),
                reverse=True
            )[:20]
        
        profile.known_ips = known_ips
    
    def _update_known_browsers(self, profile: UserProfile, user_agent: str):
        """Update known browsers list."""
        if not user_agent:
            return
        
        known_browsers = profile.known_browsers or []
        now = datetime.utcnow().isoformat()
        
        # Check if browser already known
        browser_found = False
        for browser in known_browsers:
            if browser.get('user_agent') == user_agent:
                browser['last_seen'] = now
                browser['count'] = browser.get('count', 0) + 1
                browser_found = True
                break
        
        if not browser_found:
            # Parse user agent for display
            browser_name = self._parse_browser_name(user_agent)
            known_browsers.append({
                'user_agent': user_agent,
                'browser_name': browser_name,
                'first_seen': now,
                'last_seen': now,
                'count': 1
            })
        
        # Keep only last 10 browsers
        if len(known_browsers) > 10:
            known_browsers = sorted(
                known_browsers,
                key=lambda x: x.get('last_seen', ''),
                reverse=True
            )[:10]
        
        profile.known_browsers = known_browsers
    
    def _update_known_devices(
        self,
        profile: UserProfile,
        fingerprint: str,
        context: Dict[str, Any]
    ):
        """Update known devices list."""
        known_devices = profile.known_devices or []
        now = datetime.utcnow().isoformat()
        
        # Check if device already known
        device_found = False
        for device in known_devices:
            if device.get('fingerprint') == fingerprint:
                device['last_seen'] = now
                device['count'] = device.get('count', 0) + 1
                device_found = True
                break
        
        if not device_found:
            device_name = self._generate_device_name(context.get('user_agent', ''))
            known_devices.append({
                'fingerprint': fingerprint,
                'name': device_name,
                'first_seen': now,
                'last_seen': now,
                'count': 1
            })
        
        # Keep only last 10 devices
        if len(known_devices) > 10:
            known_devices = sorted(
                known_devices,
                key=lambda x: x.get('last_seen', ''),
                reverse=True
            )[:10]
        
        profile.known_devices = known_devices
    
    def _update_login_patterns(self, profile: UserProfile, login_time: datetime):
        """Update typical login time patterns."""
        hour = login_time.hour
        day = login_time.weekday()
        
        # Update typical hours
        typical_hours = profile.typical_login_hours or []
        if hour not in typical_hours:
            typical_hours.append(hour)
        
        # Keep most common hours (based on history)
        recent_logins = self.db.query(LoginAttempt).filter(
            LoginAttempt.user_id == profile.user_id,
            LoginAttempt.success == True,
            LoginAttempt.attempted_at >= datetime.utcnow() - timedelta(days=30)
        ).all()
        
        if len(recent_logins) >= 10:
            hours = [login.attempted_at.hour for login in recent_logins]
            hour_counts = Counter(hours)
            # Keep hours that appear in at least 10% of logins
            threshold = len(recent_logins) * 0.1
            typical_hours = [h for h, c in hour_counts.items() if c >= threshold]
        
        profile.typical_login_hours = typical_hours
        
        # Update typical days
        typical_days = profile.typical_login_days or []
        if day not in typical_days:
            typical_days.append(day)
        
        if len(recent_logins) >= 10:
            days = [login.attempted_at.weekday() for login in recent_logins]
            day_counts = Counter(days)
            threshold = len(recent_logins) * 0.1
            typical_days = [d for d, c in day_counts.items() if c >= threshold]
        
        profile.typical_login_days = typical_days
    
    def _parse_browser_name(self, user_agent: str) -> str:
        """Parse browser name from user agent string."""
        ua_lower = user_agent.lower()
        
        if 'chrome' in ua_lower and 'edge' not in ua_lower:
            return 'Chrome'
        elif 'firefox' in ua_lower:
            return 'Firefox'
        elif 'safari' in ua_lower and 'chrome' not in ua_lower:
            return 'Safari'
        elif 'edge' in ua_lower:
            return 'Edge'
        elif 'opera' in ua_lower or 'opr' in ua_lower:
            return 'Opera'
        else:
            return 'Unknown Browser'
    
    def _generate_device_name(self, user_agent: str) -> str:
        """Generate a friendly device name from user agent."""
        ua_lower = user_agent.lower()
        
        # Detect OS
        if 'windows' in ua_lower:
            os_name = 'Windows'
        elif 'mac' in ua_lower:
            os_name = 'Mac'
        elif 'linux' in ua_lower:
            os_name = 'Linux'
        elif 'android' in ua_lower:
            os_name = 'Android'
        elif 'iphone' in ua_lower or 'ipad' in ua_lower:
            os_name = 'iOS'
        else:
            os_name = 'Unknown'
        
        browser = self._parse_browser_name(user_agent)
        return f"{os_name} - {browser}"
    
    def add_risk_score_to_history(
        self,
        profile: UserProfile,
        risk_score: float,
        risk_factors: Dict[str, float]
    ):
        """Add risk assessment to profile history."""
        history = profile.risk_score_history or []
        
        history.append({
            'timestamp': datetime.utcnow().isoformat(),
            'score': risk_score,
            'factors': risk_factors
        })
        
        # Keep only last 100 entries
        if len(history) > 100:
            history = history[-100:]
        
        profile.risk_score_history = history
        self.db.commit()
    
    def get_risk_trend(self, profile: UserProfile) -> str:
        """Analyze risk score trend over recent history."""
        history = profile.risk_score_history or []
        
        if len(history) < 5:
            return 'stable'
        
        # Get last 10 scores
        recent_scores = [h['score'] for h in history[-10:]]
        
        # Calculate average of first half vs second half
        mid = len(recent_scores) // 2
        first_half_avg = sum(recent_scores[:mid]) / mid
        second_half_avg = sum(recent_scores[mid:]) / (len(recent_scores) - mid)
        
        diff = second_half_avg - first_half_avg
        
        if diff > 10:
            return 'increasing'
        elif diff < -10:
            return 'decreasing'
        else:
            return 'stable'
