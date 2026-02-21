"""
AdaptiveAuth Adaptive Authentication Router
Specialized endpoints for adaptive/risk-based authentication.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from ..core.database import get_db
from ..core.dependencies import get_current_user, get_current_session, get_client_info, require_admin
from ..core.security import generate_verification_code
from ..auth.service import AuthService
from ..risk.engine import RiskEngine
from ..risk.monitor import SessionMonitor
from ..models import User, UserSession, StepUpChallenge, RiskLevel
from .. import schemas

from ..risk.biometrics import get_biometrics

router = APIRouter(prefix="/adaptive", tags=["Adaptive Authentication"])


@router.post("/assess", response_model=schemas.RiskAssessmentResult)
async def assess_current_risk(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Assess current risk level for authenticated user."""
    context = get_client_info(request)
    auth_service = AuthService(db)
    
    profile = auth_service.behavior_analyzer.get_or_create_profile(current_user)
    assessment = auth_service.risk_engine.evaluate_risk(current_user, context, profile)
    
    return schemas.RiskAssessmentResult(
        risk_score=assessment.risk_score,
        risk_level=assessment.risk_level.value,
        security_level=assessment.security_level,
        risk_factors=assessment.risk_factors,
        required_action=assessment.required_action,
        message=assessment.message
    )


@router.post("/verify-session")
async def verify_session(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verify current session is still valid and not compromised.
    Use this periodically during sensitive operations.
    """
    context = get_client_info(request)
    session_monitor = SessionMonitor(db)
    
    # Get current session
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else None
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No token provided"
        )
    
    # Find session by user (simplified - in production match by token hash)
    session = db.query(UserSession).filter(
        UserSession.user_id == current_user.id,
        UserSession.status == "active"
    ).order_by(UserSession.created_at.desc()).first()
    
    if not session:
        return {
            "valid": False,
            "reason": "No active session found"
        }
    
    result = session_monitor.verify_session(session, context)
    
    return {
        "valid": result['valid'],
        "step_up_required": result.get('step_up_required', False),
        "reason": result.get('reason'),
        "risk_level": session.current_risk_level,
        "risk_score": session.current_risk_score
    }


@router.post("/challenge", response_model=schemas.ChallengeResponse)
async def request_challenge(
    request: schemas.ChallengeRequest,
    req: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Request a new authentication challenge for step-up auth."""
    auth_service = AuthService(db)
    
    # Determine challenge type
    if request.challenge_type == 'otp' and current_user.tfa_enabled:
        challenge_type = 'otp'
        code = None
    else:
        challenge_type = 'email'
        code = generate_verification_code()
    
    # Create challenge
    challenge = StepUpChallenge(
        user_id=current_user.id,
        session_id=request.session_id,
        challenge_type=challenge_type,
        challenge_code=code,
        expires_at=datetime.utcnow() + timedelta(minutes=15)
    )
    
    db.add(challenge)
    db.commit()
    db.refresh(challenge)
    
    # Send code if email
    if challenge_type == 'email':
        await auth_service.email_service.send_verification_code(
            current_user.email, code
        )
    
    return schemas.ChallengeResponse(
        challenge_id=str(challenge.id),
        challenge_type=challenge_type,
        expires_at=challenge.expires_at,
        message="Enter the code from your authenticator app" if challenge_type == 'otp' 
                else "A verification code has been sent to your email"
    )


@router.post("/verify")
async def verify_challenge(
    request: schemas.VerifyChallengeRequest,
    req: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Verify a step-up authentication challenge."""
    challenge = db.query(StepUpChallenge).filter(
        StepUpChallenge.id == int(request.challenge_id),
        StepUpChallenge.user_id == current_user.id
    ).first()
    
    if not challenge:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Challenge not found"
        )
    
    if challenge.is_completed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Challenge already completed"
        )
    
    if challenge.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Challenge expired"
        )
    
    if challenge.attempts >= challenge.max_attempts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum attempts exceeded"
        )
    
    # Verify code
    auth_service = AuthService(db)
    verified = False
    
    if challenge.challenge_type == 'otp':
        verified = auth_service.otp_service.verify_otp(
            current_user.tfa_secret, request.code
        )
    elif challenge.challenge_type == 'email':
        verified = challenge.challenge_code == request.code
    
    challenge.attempts += 1
    
    if not verified:
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid code. {challenge.max_attempts - challenge.attempts} attempts remaining."
        )
    
    # Mark as completed
    challenge.is_completed = True
    challenge.completed_at = datetime.utcnow()
    
    # Update session if linked
    if challenge.session_id:
        session_monitor = SessionMonitor(db)
        session = db.query(UserSession).filter(
            UserSession.id == challenge.session_id
        ).first()
        if session:
            session_monitor.complete_step_up(session)
    
    db.commit()
    
    return {
        "status": "verified",
        "message": "Step-up authentication completed successfully"
    }


@router.get("/security-status")
async def get_security_status(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current security status for the user."""
    context = get_client_info(request)
    auth_service = AuthService(db)
    
    profile = auth_service.behavior_analyzer.get_or_create_profile(current_user)
    assessment = auth_service.risk_engine.evaluate_risk(current_user, context, profile)
    
    # Get session info
    active_sessions = db.query(UserSession).filter(
        UserSession.user_id == current_user.id,
        UserSession.status == "active"
    ).count()
    
    # Check for active anomalies
    from ..models import AnomalyPattern
    active_anomalies = db.query(AnomalyPattern).filter(
        AnomalyPattern.user_id == current_user.id,
        AnomalyPattern.is_active == True
    ).count()
    
    return {
        "user_id": current_user.id,
        "email": current_user.email,
        "current_risk_score": assessment.risk_score,
        "current_risk_level": assessment.risk_level.value,
        "security_level": assessment.security_level,
        "tfa_enabled": current_user.tfa_enabled,
        "account_locked": current_user.is_locked,
        "email_verified": current_user.is_verified,
        "active_sessions": active_sessions,
        "active_anomalies": active_anomalies,
        "known_devices": len(profile.known_devices or []),
        "known_locations": len(profile.known_ips or []),
        "risk_factors": assessment.risk_factors
    }


@router.post("/trust-device")
async def trust_current_device(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Mark current device as trusted."""
    context = get_client_info(request)
    auth_service = AuthService(db)
    
    profile = auth_service.behavior_analyzer.get_or_create_profile(current_user)
    
    # Add device to known devices
    device_fingerprint = context.get('device_fingerprint')
    if not device_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device fingerprint required"
        )
    
    # Update profile
    auth_service.behavior_analyzer.update_profile_on_login(
        current_user, context, True
    )
    
    return {
        "status": "success",
        "message": "Device has been marked as trusted"
    }


@router.delete("/trust-device/{device_index}")
async def remove_trusted_device(
    device_index: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Remove a device from trusted devices."""
    from ..models import UserProfile
    
    profile = db.query(UserProfile).filter(
        UserProfile.user_id == current_user.id
    ).first()
    
    if not profile or not profile.known_devices:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No devices found"
        )
    
    if device_index < 0 or device_index >= len(profile.known_devices):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    removed = profile.known_devices.pop(device_index)
    db.commit()
    
    return {
        "status": "success",
        "message": f"Device '{removed.get('name', 'Unknown')}' has been removed"
    }


# ============ BEHAVIORAL BIOMETRICS ENDPOINTS ============

@router.post("/behavior/keystroke")
async def record_keystroke(
    request: Request,
    keystroke_data: dict,
    current_user: User = Depends(get_current_user)
):
    """Record a keystroke for behavioral analysis."""
    session_id = request.headers.get("X-Session-ID", str(current_user.id))
    
    biometrics = get_biometrics()
    result = biometrics.record_keystroke(
        session_id=session_id,
        key=keystroke_data.get('key'),
        timestamp=keystroke_data.get('timestamp'),
        field_id=keystroke_data.get('field_id')
    )
    
    return result


@router.post("/behavior/mouse")
async def record_mouse(
    request: Request,
    mouse_data: dict,
    current_user: User = Depends(get_current_user)
):
    """Record mouse movement for behavioral analysis."""
    session_id = request.headers.get("X-Session-ID", str(current_user.id))
    
    biometrics = get_biometrics()
    
    if mouse_data.get('type') == 'move':
        result = biometrics.record_mouse_movement(
            session_id=session_id,
            x=mouse_data.get('x'),
            y=mouse_data.get('y'),
            timestamp=mouse_data.get('timestamp')
        )
    elif mouse_data.get('type') == 'click':
        result = biometrics.record_click(
            session_id=session_id,
            x=mouse_data.get('x'),
            y=mouse_data.get('y'),
            button=mouse_data.get('button', 'left'),
            timestamp=mouse_data.get('timestamp')
        )
    else:
        result = biometrics.get_session_behavior(session_id)
    
    return result or {"message": "No behavior data yet"}


@router.get("/behavior/status")
async def get_behavior_status(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Get current behavioral analysis status."""
    session_id = request.headers.get("X-Session-ID", str(current_user.id))
    
    biometrics = get_biometrics()
    result = biometrics.get_session_behavior(session_id)
    
    if not result:
        return {
            "human_score": 50,
            "confidence": 0,
            "is_likely_human": True,
            "message": "Start typing or moving mouse to analyze behavior"
        }
    
    return result


@router.get("/behavior/all-sessions")
async def get_all_behaviors(
    current_user: User = Depends(require_admin())
):
    """Get behavioral analysis for all sessions (admin only)."""
    biometrics = get_biometrics()
    return biometrics.get_all_active_behaviors()


# ============ END BEHAVIORAL BIOMETRICS ============
