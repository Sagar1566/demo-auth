"""
AdaptiveAuth Risk Dashboard Router
Risk monitoring and dashboard endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta
from typing import Optional

from ..core.database import get_db
from ..core.dependencies import require_admin, get_current_user, get_client_info
from ..models import (
    User, UserSession, LoginAttempt, RiskEvent, AnomalyPattern,
    UserProfile, SessionStatus, RiskLevel
)
from ..risk.engine import RiskEngine
from ..risk.analyzer import BehaviorAnalyzer
from ..risk.monitor import SessionMonitor, AnomalyDetector
from .. import schemas

router = APIRouter(prefix="/risk", tags=["Risk Dashboard"])


@router.get("/overview", response_model=schemas.RiskDashboardOverview)
async def get_risk_overview(
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Get risk dashboard overview."""
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Total risk events
    total_events = db.query(RiskEvent).filter(
        RiskEvent.created_at >= today - timedelta(days=7)
    ).count()
    
    # High risk events
    high_risk = db.query(RiskEvent).filter(
        RiskEvent.created_at >= today - timedelta(days=7),
        RiskEvent.risk_level.in_([RiskLevel.HIGH.value, RiskLevel.CRITICAL.value])
    ).count()
    
    # Active anomalies
    active_anomalies = db.query(AnomalyPattern).filter(
        AnomalyPattern.is_active == True
    ).count()
    
    # Blocked users
    blocked_users = db.query(User).filter(User.is_locked == True).count()
    
    # Average risk score (last 7 days)
    avg_score = db.query(func.avg(LoginAttempt.risk_score)).filter(
        LoginAttempt.attempted_at >= today - timedelta(days=7)
    ).scalar() or 0.0
    
    # Risk trend (compare last 7 days to previous 7 days)
    recent_avg = db.query(func.avg(LoginAttempt.risk_score)).filter(
        LoginAttempt.attempted_at >= today - timedelta(days=7),
        LoginAttempt.attempted_at < today
    ).scalar() or 0.0
    
    previous_avg = db.query(func.avg(LoginAttempt.risk_score)).filter(
        LoginAttempt.attempted_at >= today - timedelta(days=14),
        LoginAttempt.attempted_at < today - timedelta(days=7)
    ).scalar() or 0.0
    
    if recent_avg > previous_avg + 5:
        trend = "increasing"
    elif recent_avg < previous_avg - 5:
        trend = "decreasing"
    else:
        trend = "stable"
    
    return schemas.RiskDashboardOverview(
        total_risk_events=total_events,
        high_risk_events=high_risk,
        active_anomalies=active_anomalies,
        blocked_users=blocked_users,
        average_risk_score=round(float(avg_score), 2),
        risk_trend=trend
    )


@router.post("/assess")
async def assess_risk(
    request: Request,
    user_id: Optional[int] = None,
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Manually assess risk for a context or user."""
    context = get_client_info(request)
    risk_engine = RiskEngine(db)
    
    if user_id:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        analyzer = BehaviorAnalyzer(db)
        profile = analyzer.get_or_create_profile(user)
        assessment = risk_engine.evaluate_risk(user, context, profile)
    else:
        assessment = risk_engine.evaluate_new_user_risk(context)
    
    return schemas.RiskAssessmentResult(
        risk_score=assessment.risk_score,
        risk_level=assessment.risk_level.value,
        security_level=assessment.security_level,
        risk_factors=assessment.risk_factors,
        required_action=assessment.required_action,
        message=assessment.message
    )


@router.get("/profile/{user_id}")
async def get_user_risk_profile(
    user_id: int,
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Get detailed risk profile for a user."""
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    profile = db.query(UserProfile).filter(
        UserProfile.user_id == user_id
    ).first()
    
    if not profile:
        return {
            "user_id": user_id,
            "has_profile": False,
            "message": "No behavioral profile available"
        }
    
    # Get recent risk events
    recent_events = db.query(RiskEvent).filter(
        RiskEvent.user_id == user_id
    ).order_by(RiskEvent.created_at.desc()).limit(10).all()
    
    # Get login history summary
    last_30_days = datetime.utcnow() - timedelta(days=30)
    login_stats = db.query(
        LoginAttempt.success,
        func.count(LoginAttempt.id)
    ).filter(
        LoginAttempt.user_id == user_id,
        LoginAttempt.attempted_at >= last_30_days
    ).group_by(LoginAttempt.success).all()
    
    analyzer = BehaviorAnalyzer(db)
    risk_trend = analyzer.get_risk_trend(profile)
    
    return {
        "user_id": user_id,
        "email": user.email,
        "has_profile": True,
        "total_logins": profile.total_logins,
        "successful_logins": profile.successful_logins,
        "failed_logins": profile.failed_logins,
        "known_devices": len(profile.known_devices or []),
        "known_ips": len(profile.known_ips or []),
        "known_browsers": len(profile.known_browsers or []),
        "typical_login_hours": profile.typical_login_hours,
        "typical_login_days": profile.typical_login_days,
        "risk_trend": risk_trend,
        "recent_risk_scores": [
            h['score'] for h in (profile.risk_score_history or [])[-10:]
        ],
        "recent_events": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "risk_level": e.risk_level,
                "created_at": e.created_at.isoformat()
            } for e in recent_events
        ],
        "login_stats_30d": {
            "successful": next((c for s, c in login_stats if s), 0),
            "failed": next((c for s, c in login_stats if not s), 0)
        }
    }


@router.get("/active-sessions")
async def get_high_risk_sessions(
    min_risk_level: str = Query("medium", pattern="^(low|medium|high|critical)$"),
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Get sessions with elevated risk levels."""
    risk_levels = {
        "low": [RiskLevel.LOW.value, RiskLevel.MEDIUM.value, RiskLevel.HIGH.value, RiskLevel.CRITICAL.value],
        "medium": [RiskLevel.MEDIUM.value, RiskLevel.HIGH.value, RiskLevel.CRITICAL.value],
        "high": [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value],
        "critical": [RiskLevel.CRITICAL.value]
    }
    
    sessions = db.query(UserSession).filter(
        UserSession.status == SessionStatus.ACTIVE.value,
        UserSession.current_risk_level.in_(risk_levels[min_risk_level])
    ).order_by(UserSession.current_risk_score.desc()).limit(50).all()
    
    return {
        "sessions": [
            {
                "id": s.id,
                "user_id": s.user_id,
                "ip_address": s.ip_address,
                "risk_score": s.current_risk_score,
                "risk_level": s.current_risk_level,
                "country": s.country,
                "city": s.city,
                "last_activity": s.last_activity.isoformat(),
                "step_up_completed": s.step_up_completed
            } for s in sessions
        ],
        "total": len(sessions)
    }


@router.get("/login-patterns")
async def get_login_patterns(
    hours: int = Query(24, ge=1, le=168),
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Get login patterns analysis."""
    since = datetime.utcnow() - timedelta(hours=hours)
    
    # Group by hour
    hourly_stats = db.query(
        func.extract('hour', LoginAttempt.attempted_at).label('hour'),
        func.count(LoginAttempt.id).label('total'),
        func.sum(func.cast(LoginAttempt.success, db.bind.dialect.type_descriptor(db.bind.dialect.name))).label('successful')
    ).filter(
        LoginAttempt.attempted_at >= since
    ).group_by('hour').all()
    
    # Group by risk level
    risk_stats = db.query(
        LoginAttempt.risk_level,
        func.count(LoginAttempt.id)
    ).filter(
        LoginAttempt.attempted_at >= since
    ).group_by(LoginAttempt.risk_level).all()
    
    # Top IPs by volume
    top_ips = db.query(
        LoginAttempt.ip_address,
        func.count(LoginAttempt.id).label('count')
    ).filter(
        LoginAttempt.attempted_at >= since
    ).group_by(LoginAttempt.ip_address).order_by(
        func.count(LoginAttempt.id).desc()
    ).limit(10).all()
    
    return {
        "period_hours": hours,
        "hourly_distribution": [
            {"hour": int(h), "total": t, "successful": s or 0}
            for h, t, s in hourly_stats
        ],
        "risk_distribution": {
            level: count for level, count in risk_stats
        },
        "top_ips": [
            {"ip": ip, "count": count} for ip, count in top_ips
        ]
    }


@router.get("/suspicious-ips")
async def get_suspicious_ips(
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Get IPs with suspicious activity."""
    since = datetime.utcnow() - timedelta(hours=24)
    
    # IPs with high failure rate
    ip_stats = db.query(
        LoginAttempt.ip_address,
        func.count(LoginAttempt.id).label('total'),
        func.sum(
            func.cast(~LoginAttempt.success, db.bind.dialect.type_descriptor(db.bind.dialect.name))
        ).label('failed')
    ).filter(
        LoginAttempt.attempted_at >= since
    ).group_by(LoginAttempt.ip_address).having(
        func.count(LoginAttempt.id) >= 5
    ).all()
    
    suspicious = []
    for ip, total, failed in ip_stats:
        failure_rate = (failed or 0) / total if total > 0 else 0
        if failure_rate > 0.5:  # More than 50% failure rate
            suspicious.append({
                "ip": ip,
                "total_attempts": total,
                "failed_attempts": failed or 0,
                "failure_rate": round(failure_rate * 100, 2)
            })
    
    # Sort by failure rate
    suspicious.sort(key=lambda x: x['failure_rate'], reverse=True)
    
    return {
        "suspicious_ips": suspicious[:20],
        "total": len(suspicious)
    }


@router.post("/block-ip")
async def block_ip(
    ip_address: str,
    reason: str = "Suspicious activity",
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Block an IP address (creates anomaly pattern)."""
    anomaly = AnomalyPattern(
        pattern_type='blocked_ip',
        ip_address=ip_address,
        severity=RiskLevel.CRITICAL.value,
        confidence=1.0,
        pattern_data={'reason': reason, 'blocked_by': current_user.email},
        is_active=True,
        first_detected=datetime.utcnow(),
        last_detected=datetime.utcnow()
    )
    
    db.add(anomaly)
    db.commit()
    
    return {"message": f"IP {ip_address} has been blocked"}
