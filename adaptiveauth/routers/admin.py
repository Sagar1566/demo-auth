"""
AdaptiveAuth Admin Router
Administrative endpoints for user and security management.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta
from typing import Optional
import csv
import io
from fastapi.responses import StreamingResponse

from ..core.database import get_db
from ..core.dependencies import require_admin, get_current_user
from ..models import (
    User, UserSession, LoginAttempt, RiskEvent, AnomalyPattern,
    UserRole, SessionStatus, RiskLevel, FrameworkUsage
)
from ..risk.monitor import SessionMonitor, AnomalyDetector
from .. import schemas

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get("/users", response_model=schemas.AdminUserList)
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """List all users (admin only)."""
    query = db.query(User)
    
    if role:
        query = query.filter(User.role == role)
    
    if is_active is not None:
        query = query.filter(User.is_active == is_active)
    
    total = query.count()
    users = query.offset((page - 1) * page_size).limit(page_size).all()
    
    return schemas.AdminUserList(
        users=[schemas.UserResponse.model_validate(u) for u in users],
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/users/{user_id}", response_model=schemas.UserResponse)
async def get_user(
    user_id: int,
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Get user details (admin only)."""
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return user


@router.post("/users/{user_id}/block")
async def block_user(
    user_id: int,
    reason: str = "Administrative action",
    duration_hours: Optional[int] = None,
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Block a user (admin only)."""
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user.is_locked = True
    if duration_hours:
        user.locked_until = datetime.utcnow() + timedelta(hours=duration_hours)
    else:
        user.locked_until = None  # Permanent
    
    # Revoke all sessions
    session_monitor = SessionMonitor(db)
    session_monitor.revoke_all_sessions(user)
    
    db.commit()
    
    return {"message": f"User {user.email} has been blocked"}


@router.post("/users/{user_id}/unblock")
async def unblock_user(
    user_id: int,
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Unblock a user (admin only)."""
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user.is_locked = False
    user.locked_until = None
    user.failed_login_attempts = 0
    
    db.commit()
    
    return {"message": f"User {user.email} has been unblocked"}


@router.get("/sessions", response_model=schemas.SessionListResponse)
async def list_sessions(
    status_filter: Optional[str] = None,
    risk_level: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """List all active sessions (admin only)."""
    query = db.query(UserSession)
    
    if status_filter:
        query = query.filter(UserSession.status == status_filter)
    else:
        query = query.filter(UserSession.status == SessionStatus.ACTIVE.value)
    
    if risk_level:
        query = query.filter(UserSession.current_risk_level == risk_level)
    
    total = query.count()
    sessions = query.order_by(
        UserSession.last_activity.desc()
    ).offset((page - 1) * page_size).limit(page_size).all()
    
    session_list = [
        schemas.SessionInfo(
            id=s.id,
            ip_address=s.ip_address,
            user_agent=s.user_agent or "",
            country=s.country,
            city=s.city,
            risk_level=s.current_risk_level,
            status=s.status,
            last_activity=s.last_activity,
            created_at=s.created_at
        ) for s in sessions
    ]
    
    return schemas.SessionListResponse(sessions=session_list, total=total)


@router.post("/sessions/{session_id}/revoke")
async def revoke_session(
    session_id: int,
    reason: str = "Administrative action",
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Revoke a specific session (admin only)."""
    session_monitor = SessionMonitor(db)
    session_monitor.revoke_session(session_id, reason)
    
    return {"message": "Session revoked"}


@router.get("/risk-events", response_model=schemas.RiskEventList)
async def list_risk_events(
    risk_level: Optional[str] = None,
    event_type: Optional[str] = None,
    user_id: Optional[int] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """List risk events (admin only)."""
    query = db.query(RiskEvent)
    
    if risk_level:
        query = query.filter(RiskEvent.risk_level == risk_level)
    
    if event_type:
        query = query.filter(RiskEvent.event_type == event_type)
    
    if user_id:
        query = query.filter(RiskEvent.user_id == user_id)
    
    total = query.count()
    events = query.order_by(
        RiskEvent.created_at.desc()
    ).offset((page - 1) * page_size).limit(page_size).all()
    
    event_list = [
        schemas.RiskEventResponse(
            id=e.id,
            event_type=e.event_type,
            risk_score=e.risk_score,
            risk_level=e.risk_level,
            ip_address=e.ip_address,
            risk_factors=e.risk_factors or {},
            action_taken=e.action_taken,
            created_at=e.created_at,
            resolved=e.resolved
        ) for e in events
    ]
    
    return schemas.RiskEventList(
        events=event_list,
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/anomalies", response_model=schemas.AnomalyListResponse)
async def list_anomalies(
    active_only: bool = True,
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """List detected anomaly patterns (admin only)."""
    anomaly_detector = AnomalyDetector(db)
    
    if active_only:
        anomalies = anomaly_detector.get_active_anomalies()
    else:
        anomalies = db.query(AnomalyPattern).order_by(
            AnomalyPattern.last_detected.desc()
        ).limit(100).all()
    
    anomaly_list = [
        schemas.AnomalyPatternResponse(
            id=a.id,
            pattern_type=a.pattern_type,
            severity=a.severity,
            confidence=a.confidence,
            is_active=a.is_active,
            first_detected=a.first_detected,
            last_detected=a.last_detected,
            pattern_data=a.pattern_data or {}
        ) for a in anomalies
    ]
    
    return schemas.AnomalyListResponse(anomalies=anomaly_list, total=len(anomaly_list))


@router.post("/anomalies/{anomaly_id}/resolve")
async def resolve_anomaly(
    anomaly_id: int,
    false_positive: bool = False,
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Resolve an anomaly pattern (admin only)."""
    anomaly_detector = AnomalyDetector(db)
    anomaly_detector.resolve_anomaly(anomaly_id, false_positive)
    
    return {"message": "Anomaly resolved"}


@router.get("/statistics", response_model=schemas.AdminStatistics)
async def get_statistics(
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Get admin dashboard statistics."""
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    
    total_users = db.query(User).count()
    active_users = db.query(User).filter(User.is_active == True).count()
    blocked_users = db.query(User).filter(User.is_locked == True).count()
    
    active_sessions = db.query(UserSession).filter(
        UserSession.status == SessionStatus.ACTIVE.value
    ).count()
    
    high_risk_events = db.query(RiskEvent).filter(
        RiskEvent.created_at >= today,
        RiskEvent.risk_level.in_([RiskLevel.HIGH.value, RiskLevel.CRITICAL.value])
    ).count()
    
    failed_logins = db.query(LoginAttempt).filter(
        LoginAttempt.attempted_at >= today,
        LoginAttempt.success == False
    ).count()
    
    new_users = db.query(User).filter(
        User.created_at >= today
    ).count()
    
    return schemas.AdminStatistics(
        total_users=total_users,
        active_users=active_users,
        blocked_users=blocked_users,
        active_sessions=active_sessions,
        high_risk_events_today=high_risk_events,
        failed_logins_today=failed_logins,
        new_users_today=new_users
    )


@router.get("/risk-statistics", response_model=schemas.RiskStatistics)
async def get_risk_statistics(
    period: str = Query("day", pattern="^(day|week|month)$"),
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Get risk statistics for a period."""
    if period == "day":
        since = datetime.utcnow() - timedelta(days=1)
    elif period == "week":
        since = datetime.utcnow() - timedelta(weeks=1)
    else:
        since = datetime.utcnow() - timedelta(days=30)
    
    # Login statistics
    total_logins = db.query(LoginAttempt).filter(
        LoginAttempt.attempted_at >= since
    ).count()
    
    successful_logins = db.query(LoginAttempt).filter(
        LoginAttempt.attempted_at >= since,
        LoginAttempt.success == True
    ).count()
    
    failed_logins = db.query(LoginAttempt).filter(
        LoginAttempt.attempted_at >= since,
        LoginAttempt.success == False
    ).count()
    
    # Risk distribution
    risk_distribution = {}
    for level in RiskLevel:
        count = db.query(LoginAttempt).filter(
            LoginAttempt.attempted_at >= since,
            LoginAttempt.risk_level == level.value
        ).count()
        risk_distribution[level.value] = count
    
    # Average risk score
    avg_score_result = db.query(func.avg(LoginAttempt.risk_score)).filter(
        LoginAttempt.attempted_at >= since
    ).scalar()
    avg_score = float(avg_score_result) if avg_score_result else 0.0
    
    # Blocked attempts
    blocked = db.query(LoginAttempt).filter(
        LoginAttempt.attempted_at >= since,
        LoginAttempt.security_level >= 4
    ).count()
    
    return schemas.RiskStatistics(
        period=period,
        total_logins=total_logins,
        successful_logins=successful_logins,
        failed_logins=failed_logins,
        blocked_attempts=blocked,
        average_risk_score=round(avg_score, 2),
        risk_distribution=risk_distribution
    )


@router.get("/export/users")
async def export_users(
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Export all users to CSV (admin only)."""
    users = db.query(User).all()
    
    # Prepare CSV data
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        "ID", "Email", "Full Name", "Role", "Active", "Verified", "Locked",
        "Failed Attempts", "Created At", "Last Login"
    ])
    
    # Write data rows
    for user in users:
        writer.writerow([
            user.id,
            user.email,
            user.full_name or "",
            user.role,
            user.is_active,
            user.is_verified,
            user.is_locked,
            user.failed_login_attempts,
            user.created_at.isoformat() if user.created_at else "",
            user.last_successful_login.isoformat() if user.last_successful_login else ""
        ])
    
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=users_export.csv"}
    )


@router.get("/export/sessions")
async def export_sessions(
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Export all sessions to CSV (admin only)."""
    sessions = db.query(UserSession).all()
    
    # Prepare CSV data
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        "ID", "User ID", "IP Address", "User Agent", "Country", "City",
        "Risk Level", "Status", "Created At", "Last Activity", "Expires At"
    ])
    
    # Write data rows
    for session in sessions:
        writer.writerow([
            session.id,
            session.user_id,
            session.ip_address,
            session.user_agent or "",
            session.country or "",
            session.city or "",
            session.current_risk_level,
            session.status,
            session.created_at.isoformat() if session.created_at else "",
            session.last_activity.isoformat() if session.last_activity else "",
            session.expires_at.isoformat() if session.expires_at else ""
        ])
    
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sessions_export.csv"}
    )


@router.get("/export/risk-events")
async def export_risk_events(
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Export all risk events to CSV (admin only)."""
    events = db.query(RiskEvent).all()
    
    # Prepare CSV data
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        "ID", "User ID", "Event Type", "Risk Score", "Risk Level", "IP Address",
        "Risk Factors", "Action Taken", "Resolved", "Created At"
    ])
    
    # Write data rows
    for event in events:
        writer.writerow([
            event.id,
            event.user_id,
            event.event_type,
            event.risk_score,
            event.risk_level,
            event.ip_address,
            str(event.risk_factors) if event.risk_factors else "",
            event.action_taken or "",
            event.resolved,
            event.created_at.isoformat() if event.created_at else ""
        ])
    
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=risk_events_export.csv"}
    )


@router.get("/export/anomalies")
async def export_anomalies(
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Export all anomalies to CSV (admin only)."""
    anomalies = db.query(AnomalyPattern).all()
    
    # Prepare CSV data
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        "ID", "Pattern Type", "Severity", "Confidence", "Active", "First Detected",
        "Last Detected", "Pattern Data"
    ])
    
    # Write data rows
    for anomaly in anomalies:
        writer.writerow([
            anomaly.id,
            anomaly.pattern_type,
            anomaly.severity,
            anomaly.confidence,
            anomaly.is_active,
            anomaly.first_detected.isoformat() if anomaly.first_detected else "",
            anomaly.last_detected.isoformat() if anomaly.last_detected else "",
            str(anomaly.pattern_data) if anomaly.pattern_data else ""
        ])
    
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=anomalies_export.csv"}
    )


# Framework Usage Tracking Endpoints

@router.get("/framework-usages", response_model=schemas.FrameworkUsageList)
async def list_framework_usages(
    is_anomalous: Optional[bool] = None,
    client_ip: Optional[str] = None,
    endpoint: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """List framework usage records (admin only)."""
    query = db.query(FrameworkUsage)
    
    if is_anomalous is not None:
        query = query.filter(FrameworkUsage.is_anomalous == is_anomalous)
    
    if client_ip:
        query = query.filter(FrameworkUsage.client_ip.like(f"%{client_ip}%"))
    
    if endpoint:
        query = query.filter(FrameworkUsage.endpoint_accessed.like(f"%{endpoint}%"))
    
    total = query.count()
    usages = query.order_by(
        FrameworkUsage.timestamp.desc()
    ).offset((page - 1) * page_size).limit(page_size).all()
    
    usage_list = [
        schemas.FrameworkUsageResponse(
            id=u.id,
            client_ip=u.client_ip,
            user_agent=u.user_agent or "",
            endpoint_accessed=u.endpoint_accessed,
            method=u.method,
            timestamp=u.timestamp,
            risk_score=u.risk_score,
            is_anomalous=u.is_anomalous,
            anomaly_description=u.anomaly_description
        ) for u in usages
    ]
    
    return schemas.FrameworkUsageList(
        usages=usage_list,
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/framework-usages/anomalies", response_model=schemas.FrameworkUsageList)
async def list_framework_anomalies(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """List only anomalous framework usage records (admin only)."""
    query = db.query(FrameworkUsage).filter(FrameworkUsage.is_anomalous == True)
    
    total = query.count()
    usages = query.order_by(
        FrameworkUsage.timestamp.desc()
    ).offset((page - 1) * page_size).limit(page_size).all()
    
    usage_list = [
        schemas.FrameworkUsageResponse(
            id=u.id,
            client_ip=u.client_ip,
            user_agent=u.user_agent or "",
            endpoint_accessed=u.endpoint_accessed,
            method=u.method,
            timestamp=u.timestamp,
            risk_score=u.risk_score,
            is_anomalous=u.is_anomalous,
            anomaly_description=u.anomaly_description
        ) for u in usages
    ]
    
    return schemas.FrameworkUsageList(
        usages=usage_list,
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/framework-statistics")
async def get_framework_statistics(
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Get framework usage statistics (admin only)."""
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    
    total_usage = db.query(FrameworkUsage).count()
    total_anomalies = db.query(FrameworkUsage).filter(FrameworkUsage.is_anomalous == True).count()
    
    # Get unique IPs
    unique_ips = db.query(FrameworkUsage.client_ip).distinct().count()
    
    # Get unique endpoints accessed
    unique_endpoints = db.query(FrameworkUsage.endpoint_accessed).distinct().count()
    
    # Usage today
    usage_today = db.query(FrameworkUsage).filter(
        FrameworkUsage.timestamp >= today
    ).count()
    
    # Anomalies today
    anomalies_today = db.query(FrameworkUsage).filter(
        FrameworkUsage.timestamp >= today,
        FrameworkUsage.is_anomalous == True
    ).count()
    
    # Top endpoints accessed
    from sqlalchemy import func
    top_endpoints = db.query(
        FrameworkUsage.endpoint_accessed,
        func.count(FrameworkUsage.id).label('count')
    ).group_by(FrameworkUsage.endpoint_accessed).order_by(
        func.count(FrameworkUsage.id).desc()
    ).limit(10).all()
    
    # Top IP addresses
    top_ips = db.query(
        FrameworkUsage.client_ip,
        func.count(FrameworkUsage.id).label('count')
    ).group_by(FrameworkUsage.client_ip).order_by(
        func.count(FrameworkUsage.id).desc()
    ).limit(10).all()
    
    return {
        "total_usage": total_usage,
        "total_anomalies": total_anomalies,
        "unique_ips": unique_ips,
        "unique_endpoints": unique_endpoints,
        "usage_today": usage_today,
        "anomalies_today": anomalies_today,
        "top_endpoints": [{"endpoint": ep[0], "count": ep[1]} for ep in top_endpoints],
        "top_ips": [{"ip": ip[0], "count": ip[1]} for ip in top_ips]
    }


@router.get("/export/framework-usages")
async def export_framework_usages(
    current_user: User = Depends(require_admin()),
    db: Session = Depends(get_db)
):
    """Export framework usage records to CSV (admin only)."""
    usages = db.query(FrameworkUsage).all()
    
    # Prepare CSV data
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        "ID", "Client IP", "User Agent", "Endpoint Accessed", "Method",
        "Timestamp", "Risk Score", "Is Anomalous", "Anomaly Description"
    ])
    
    # Write data rows
    for usage in usages:
        writer.writerow([
            usage.id,
            usage.client_ip,
            usage.user_agent or "",
            usage.endpoint_accessed,
            usage.method,
            usage.timestamp.isoformat() if usage.timestamp else "",
            usage.risk_score,
            usage.is_anomalous,
            usage.anomaly_description or ""
        ])
    
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=framework_usages_export.csv"}
    )