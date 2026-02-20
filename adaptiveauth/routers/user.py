"""
AdaptiveAuth User Router
User profile and security settings endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List

from ..core.database import get_db
from ..core.dependencies import get_current_user, get_client_info
from ..core.security import verify_password, hash_password
from ..auth.service import AuthService
from ..risk.monitor import SessionMonitor
from ..risk.analyzer import BehaviorAnalyzer
from ..models import User, UserProfile, UserSession, SessionStatus
from .. import schemas

router = APIRouter(prefix="/user", tags=["User"])


@router.get("/profile", response_model=schemas.UserResponse)
async def get_profile(
    current_user: User = Depends(get_current_user)
):
    """Get current user's profile."""
    return current_user


@router.put("/profile", response_model=schemas.UserResponse)
async def update_profile(
    request: schemas.UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update current user's profile."""
    if request.full_name is not None:
        current_user.full_name = request.full_name
    
    if request.email is not None and request.email != current_user.email:
        # Check if email is already taken
        existing = db.query(User).filter(User.email == request.email).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use"
            )
        current_user.email = request.email
        current_user.is_verified = False  # Re-verify new email
    
    db.commit()
    db.refresh(current_user)
    
    return current_user


@router.get("/security", response_model=schemas.UserSecuritySettings)
async def get_security_settings(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's security settings."""
    # Count active sessions
    active_sessions = db.query(UserSession).filter(
        UserSession.user_id == current_user.id,
        UserSession.status == SessionStatus.ACTIVE.value
    ).count()
    
    # Get profile for known devices
    profile = db.query(UserProfile).filter(
        UserProfile.user_id == current_user.id
    ).first()
    
    known_devices = len(profile.known_devices) if profile and profile.known_devices else 0
    
    # Count recent login attempts
    from datetime import datetime, timedelta
    from ..models import LoginAttempt
    
    recent_attempts = db.query(LoginAttempt).filter(
        LoginAttempt.user_id == current_user.id,
        LoginAttempt.attempted_at >= datetime.utcnow() - timedelta(days=7)
    ).count()
    
    return schemas.UserSecuritySettings(
        tfa_enabled=current_user.tfa_enabled,
        last_password_change=current_user.password_changed_at,
        active_sessions=active_sessions,
        known_devices=known_devices,
        recent_login_attempts=recent_attempts
    )


@router.post("/change-password")
async def change_password(
    request: schemas.PasswordChange,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Change user's password."""
    # Verify current password
    if not verify_password(request.current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    if request.new_password != request.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New passwords do not match"
        )
    
    # Update password
    from datetime import datetime
    current_user.password_hash = hash_password(request.new_password)
    current_user.password_changed_at = datetime.utcnow()
    db.commit()
    
    # Optionally revoke other sessions
    session_monitor = SessionMonitor(db)
    session_monitor.revoke_all_sessions(current_user)
    
    return {"message": "Password changed successfully"}


@router.get("/devices", response_model=schemas.DeviceListResponse)
async def get_devices(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's known devices."""
    profile = db.query(UserProfile).filter(
        UserProfile.user_id == current_user.id
    ).first()
    
    if not profile or not profile.known_devices:
        return schemas.DeviceListResponse(devices=[], total=0)
    
    from datetime import datetime
    
    devices = []
    for i, device in enumerate(profile.known_devices):
        devices.append(schemas.DeviceInfo(
            id=str(i),
            name=device.get('name', 'Unknown Device'),
            browser=device.get('browser'),
            os=device.get('os'),
            first_seen=datetime.fromisoformat(device['first_seen']) if device.get('first_seen') else datetime.utcnow(),
            last_seen=datetime.fromisoformat(device['last_seen']) if device.get('last_seen') else datetime.utcnow(),
            is_current=False
        ))
    
    return schemas.DeviceListResponse(devices=devices, total=len(devices))


@router.delete("/devices/{device_id}")
async def remove_device(
    device_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Remove a known device."""
    profile = db.query(UserProfile).filter(
        UserProfile.user_id == current_user.id
    ).first()
    
    if not profile or not profile.known_devices:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    try:
        device_idx = int(device_id)
        if 0 <= device_idx < len(profile.known_devices):
            profile.known_devices.pop(device_idx)
            db.commit()
            return {"message": "Device removed"}
    except (ValueError, IndexError):
        pass
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Device not found"
    )


@router.get("/sessions", response_model=schemas.SessionListResponse)
async def get_sessions(
    req: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's active sessions."""
    session_monitor = SessionMonitor(db)
    sessions = session_monitor.get_user_sessions(current_user, include_expired=False)
    
    # Get current session token
    auth_header = req.headers.get("Authorization", "")
    current_token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else None
    
    session_list = []
    for session in sessions:
        session_list.append(schemas.SessionInfo(
            id=session.id,
            ip_address=session.ip_address,
            user_agent=session.user_agent or "",
            country=session.country,
            city=session.city,
            risk_level=session.current_risk_level,
            status=session.status,
            last_activity=session.last_activity,
            created_at=session.created_at,
            is_current=False  # Would need token matching
        ))
    
    return schemas.SessionListResponse(sessions=session_list, total=len(session_list))


@router.post("/sessions/revoke")
async def revoke_sessions(
    request: schemas.SessionRevokeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Revoke user sessions."""
    session_monitor = SessionMonitor(db)
    
    if request.revoke_all:
        session_monitor.revoke_all_sessions(current_user)
        return {"message": "All sessions revoked"}
    
    for session_id in request.session_ids:
        # Verify session belongs to user
        session = db.query(UserSession).filter(
            UserSession.id == session_id,
            UserSession.user_id == current_user.id
        ).first()
        
        if session:
            session_monitor.revoke_session(session_id)
    
    return {"message": f"Revoked {len(request.session_ids)} session(s)"}


@router.get("/risk-profile")
async def get_risk_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's risk profile summary."""
    analyzer = BehaviorAnalyzer(db)
    profile = analyzer.get_or_create_profile(current_user)
    
    return {
        "total_logins": profile.total_logins,
        "successful_logins": profile.successful_logins,
        "failed_logins": profile.failed_logins,
        "known_devices_count": len(profile.known_devices or []),
        "known_ips_count": len(profile.known_ips or []),
        "typical_login_hours": profile.typical_login_hours,
        "typical_login_days": profile.typical_login_days,
        "risk_trend": analyzer.get_risk_trend(profile)
    }
