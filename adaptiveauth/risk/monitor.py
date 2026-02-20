"""
AdaptiveAuth Session Monitor
Continuous session verification and monitoring.
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import and_

from ..models import (
    User, UserSession, RiskEvent, AnomalyPattern, LoginAttempt,
    SessionStatus, RiskLevel
)
from ..config import get_settings
from .engine import RiskEngine, RiskAssessment


class SessionMonitor:
    """
    Continuous session monitoring for adaptive authentication.
    Tracks session activity and triggers step-up auth when needed.
    """
    
    def __init__(self, db: Session):
        self.db = db
        self.settings = get_settings()
    
    def create_session(
        self,
        user: User,
        context: Dict[str, Any],
        risk_assessment: RiskAssessment,
        token: str,
        expires_at: datetime
    ) -> UserSession:
        """Create a new user session after successful login."""
        
        # Check and enforce max concurrent sessions
        self._enforce_session_limit(user)
        
        session = UserSession(
            user_id=user.id,
            session_token=token,
            ip_address=context.get('ip_address', ''),
            user_agent=context.get('user_agent', ''),
            device_fingerprint=context.get('device_fingerprint'),
            country=context.get('country'),
            city=context.get('city'),
            current_risk_score=risk_assessment.risk_score,
            current_risk_level=risk_assessment.risk_level.value,
            status=SessionStatus.ACTIVE.value,
            step_up_completed=risk_assessment.security_level <= 1,
            last_activity=datetime.utcnow(),
            created_at=datetime.utcnow(),
            expires_at=expires_at
        )
        
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        
        return session
    
    def _enforce_session_limit(self, user: User):
        """Revoke oldest sessions if limit exceeded."""
        active_sessions = self.db.query(UserSession).filter(
            UserSession.user_id == user.id,
            UserSession.status == SessionStatus.ACTIVE.value
        ).order_by(UserSession.created_at.asc()).all()
        
        max_sessions = self.settings.MAX_CONCURRENT_SESSIONS
        
        if len(active_sessions) >= max_sessions:
            # Revoke oldest sessions
            sessions_to_revoke = active_sessions[:len(active_sessions) - max_sessions + 1]
            for session in sessions_to_revoke:
                session.status = SessionStatus.REVOKED.value
        
        self.db.commit()
    
    def verify_session(
        self,
        session: UserSession,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Verify ongoing session and check for anomalies.
        Called periodically during active sessions.
        """
        result = {
            'valid': True,
            'step_up_required': False,
            'reason': None
        }
        
        # Check if session is still active
        if session.status != SessionStatus.ACTIVE.value:
            result['valid'] = False
            result['reason'] = 'Session is no longer active'
            return result
        
        # Check expiration
        if session.expires_at < datetime.utcnow():
            session.status = SessionStatus.EXPIRED.value
            self.db.commit()
            result['valid'] = False
            result['reason'] = 'Session has expired'
            return result
        
        # Check for context changes (IP, device)
        context_changed = self._check_context_change(session, context)
        
        if context_changed:
            # Re-evaluate risk
            user = self.db.query(User).filter(User.id == session.user_id).first()
            if user:
                risk_engine = RiskEngine(self.db)
                assessment = risk_engine.evaluate_risk(user, context)
                
                # Update session risk
                session.current_risk_score = assessment.risk_score
                session.current_risk_level = assessment.risk_level.value
                
                if assessment.security_level >= 3:
                    session.status = SessionStatus.SUSPICIOUS.value
                    result['step_up_required'] = True
                    result['reason'] = 'Session context changed significantly'
                
                self.db.commit()
        
        # Update last activity
        session.last_activity = datetime.utcnow()
        session.activity_count += 1
        self.db.commit()
        
        return result
    
    def _check_context_change(
        self,
        session: UserSession,
        context: Dict[str, Any]
    ) -> bool:
        """Check if session context has changed significantly."""
        
        # IP address change
        if context.get('ip_address') != session.ip_address:
            return True
        
        # Device fingerprint change
        if (session.device_fingerprint and 
            context.get('device_fingerprint') and
            context.get('device_fingerprint') != session.device_fingerprint):
            return True
        
        return False
    
    def get_user_sessions(
        self,
        user: User,
        include_expired: bool = False
    ) -> List[UserSession]:
        """Get all sessions for a user."""
        query = self.db.query(UserSession).filter(
            UserSession.user_id == user.id
        )
        
        if not include_expired:
            query = query.filter(
                UserSession.status == SessionStatus.ACTIVE.value
            )
        
        return query.order_by(UserSession.created_at.desc()).all()
    
    def revoke_session(self, session_id: int, reason: str = "User requested"):
        """Revoke a specific session."""
        session = self.db.query(UserSession).filter(
            UserSession.id == session_id
        ).first()
        
        if session:
            session.status = SessionStatus.REVOKED.value
            self.db.commit()
    
    def revoke_all_sessions(self, user: User, except_session_id: Optional[int] = None):
        """Revoke all sessions for a user."""
        query = self.db.query(UserSession).filter(
            UserSession.user_id == user.id,
            UserSession.status == SessionStatus.ACTIVE.value
        )
        
        if except_session_id:
            query = query.filter(UserSession.id != except_session_id)
        
        for session in query.all():
            session.status = SessionStatus.REVOKED.value
        
        self.db.commit()
    
    def mark_session_suspicious(self, session: UserSession, reason: str):
        """Mark a session as suspicious."""
        session.status = SessionStatus.SUSPICIOUS.value
        
        # Log risk event
        event = RiskEvent(
            user_id=session.user_id,
            event_type='session_suspicious',
            risk_score=session.current_risk_score,
            risk_level=session.current_risk_level,
            ip_address=session.ip_address,
            user_agent=session.user_agent,
            risk_factors={'reason': reason},
            action_required='step_up',
            created_at=datetime.utcnow()
        )
        
        self.db.add(event)
        self.db.commit()
    
    def complete_step_up(self, session: UserSession):
        """Mark step-up authentication as completed for session."""
        session.step_up_completed = True
        session.status = SessionStatus.ACTIVE.value
        session.current_risk_level = RiskLevel.LOW.value
        self.db.commit()
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions. Should be run periodically."""
        expired = self.db.query(UserSession).filter(
            UserSession.status == SessionStatus.ACTIVE.value,
            UserSession.expires_at < datetime.utcnow()
        ).all()
        
        for session in expired:
            session.status = SessionStatus.EXPIRED.value
        
        self.db.commit()
        return len(expired)
    
    def get_session_statistics(self, user: Optional[User] = None) -> Dict[str, Any]:
        """Get session statistics."""
        query = self.db.query(UserSession)
        
        if user:
            query = query.filter(UserSession.user_id == user.id)
        
        active = query.filter(
            UserSession.status == SessionStatus.ACTIVE.value
        ).count()
        
        suspicious = query.filter(
            UserSession.status == SessionStatus.SUSPICIOUS.value
        ).count()
        
        total = query.count()
        
        return {
            'total': total,
            'active': active,
            'suspicious': suspicious,
            'expired': query.filter(
                UserSession.status == SessionStatus.EXPIRED.value
            ).count(),
            'revoked': query.filter(
                UserSession.status == SessionStatus.REVOKED.value
            ).count()
        }


class AnomalyDetector:
    """
    Detects suspicious patterns and anomalies.
    """
    
    def __init__(self, db: Session):
        self.db = db
    
    def detect_brute_force(
        self,
        ip_address: str,
        window_minutes: int = 15,
        threshold: int = 10
    ) -> Optional[AnomalyPattern]:
        """Detect brute force attack pattern."""
        
        failed_count = self.db.query(LoginAttempt).filter(
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.success == False,
            LoginAttempt.attempted_at >= datetime.utcnow() - timedelta(minutes=window_minutes)
        ).count()
        
        if failed_count >= threshold:
            # Check if pattern already exists
            existing = self.db.query(AnomalyPattern).filter(
                AnomalyPattern.ip_address == ip_address,
                AnomalyPattern.pattern_type == 'brute_force',
                AnomalyPattern.is_active == True
            ).first()
            
            if existing:
                existing.last_detected = datetime.utcnow()
                existing.pattern_data['count'] = failed_count
                self.db.commit()
                return existing
            
            pattern = AnomalyPattern(
                pattern_type='brute_force',
                ip_address=ip_address,
                severity=RiskLevel.CRITICAL.value,
                confidence=min(1.0, failed_count / (threshold * 2)),
                pattern_data={
                    'failed_attempts': failed_count,
                    'window_minutes': window_minutes
                },
                is_active=True,
                first_detected=datetime.utcnow(),
                last_detected=datetime.utcnow()
            )
            
            self.db.add(pattern)
            self.db.commit()
            return pattern
        
        return None
    
    def detect_credential_stuffing(
        self,
        ip_address: str,
        window_minutes: int = 15,
        unique_users_threshold: int = 5
    ) -> Optional[AnomalyPattern]:
        """Detect credential stuffing attack pattern."""
        from sqlalchemy import distinct
        
        # Count unique users attempted from this IP
        unique_users = self.db.query(
            distinct(LoginAttempt.email)
        ).filter(
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.attempted_at >= datetime.utcnow() - timedelta(minutes=window_minutes)
        ).count()
        
        if unique_users >= unique_users_threshold:
            existing = self.db.query(AnomalyPattern).filter(
                AnomalyPattern.ip_address == ip_address,
                AnomalyPattern.pattern_type == 'credential_stuffing',
                AnomalyPattern.is_active == True
            ).first()
            
            if existing:
                existing.last_detected = datetime.utcnow()
                existing.pattern_data['unique_users'] = unique_users
                self.db.commit()
                return existing
            
            pattern = AnomalyPattern(
                pattern_type='credential_stuffing',
                ip_address=ip_address,
                severity=RiskLevel.CRITICAL.value,
                confidence=min(1.0, unique_users / (unique_users_threshold * 2)),
                pattern_data={
                    'unique_users': unique_users,
                    'window_minutes': window_minutes
                },
                is_active=True,
                first_detected=datetime.utcnow(),
                last_detected=datetime.utcnow()
            )
            
            self.db.add(pattern)
            self.db.commit()
            return pattern
        
        return None
    
    def get_active_anomalies(
        self,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None
    ) -> List[AnomalyPattern]:
        """Get active anomaly patterns."""
        query = self.db.query(AnomalyPattern).filter(
            AnomalyPattern.is_active == True
        )
        
        if user_id:
            query = query.filter(AnomalyPattern.user_id == user_id)
        
        if ip_address:
            query = query.filter(AnomalyPattern.ip_address == ip_address)
        
        return query.order_by(AnomalyPattern.last_detected.desc()).all()
    
    def resolve_anomaly(self, anomaly_id: int, false_positive: bool = False):
        """Resolve an anomaly pattern."""
        anomaly = self.db.query(AnomalyPattern).filter(
            AnomalyPattern.id == anomaly_id
        ).first()
        
        if anomaly:
            anomaly.is_active = False
            anomaly.false_positive = false_positive
            anomaly.resolved_at = datetime.utcnow()
            self.db.commit()
