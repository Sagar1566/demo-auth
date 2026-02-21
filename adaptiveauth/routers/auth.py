"""
AdaptiveAuth Authentication Router
Core authentication endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timedelta

from ..core.database import get_db
from ..core.dependencies import get_current_user, get_client_info
from ..auth.service import AuthService
from ..models import User
from .. import schemas

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=schemas.UserResponse)
async def register(
    request: schemas.UserRegister,
    req: Request,
    db: Session = Depends(get_db)
):
    """Register a new user."""
    context = get_client_info(req)
    auth_service = AuthService(db)
    
    try:
        user, _ = await auth_service.register_user(
            email=request.email,
            password=request.password,
            full_name=request.full_name,
            context=context
        )
        return user
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/login", response_model=schemas.TokenResponse)
async def login(
    request: schemas.UserLogin,
    req: Request = None,
    db: Session = Depends(get_db)
):
    """
    JSON login endpoint.
    For risk-based login, use /auth/adaptive-login.
    """
    context = get_client_info(req)
    auth_service = AuthService(db)
    
    result = await auth_service.adaptive_login(
        email=request.email,
        password=request.password,
        context=context
    )
    
    if result['status'] == 'blocked':
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result.get('message', 'Authentication failed')
        )
    
    if result['status'] == 'challenge_required':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                'message': result.get('message'),
                'challenge_type': result.get('challenge_type'),
                'challenge_id': result.get('challenge_id')
            }
        )
    
    return schemas.TokenResponse(
        access_token=result['access_token'],
        token_type=result['token_type'],
        expires_in=result['expires_in'],
        user_info=result.get('user_info')
    )


@router.post("/adaptive-login", response_model=schemas.AdaptiveLoginResponse)
async def adaptive_login(
    request: schemas.AdaptiveLoginRequest,
    req: Request,
    db: Session = Depends(get_db)
):
    """
    Risk-based adaptive login.
    Returns detailed risk assessment and may require step-up authentication.
    """
    context = get_client_info(req)
    if request.device_fingerprint:
        context['device_fingerprint'] = request.device_fingerprint
    
    auth_service = AuthService(db)
    result = await auth_service.adaptive_login(
        email=request.email,
        password=request.password,
        context=context
    )
    
    return schemas.AdaptiveLoginResponse(**result)


@router.post("/step-up", response_model=schemas.StepUpResponse)
async def step_up_verification(
    request: schemas.StepUpRequest,
    req: Request,
    db: Session = Depends(get_db)
):
    """Complete step-up authentication challenge."""
    context = get_client_info(req)
    auth_service = AuthService(db)
    
    result = await auth_service.verify_step_up(
        challenge_id=request.challenge_id,
        code=request.verification_code,
        context=context
    )
    
    if result['status'] == 'error':
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get('message', 'Verification failed')
        )
    
    return schemas.StepUpResponse(
        status=result['status'],
        access_token=result.get('access_token'),
        token_type=result.get('token_type'),
        message=result.get('message')
    )


@router.post("/login-otp", response_model=schemas.TokenResponse)
async def login_with_otp(
    request: schemas.LoginOTP,
    req: Request,
    db: Session = Depends(get_db)
):
    """Login using TOTP code only (for 2FA-enabled users)."""
    context = get_client_info(req)
    auth_service = AuthService(db)
    
    # Find user
    user = db.query(User).filter(User.email == request.email).first()
    
    if not user or not user.tfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or 2FA not enabled"
        )
    
    # Verify OTP
    if not auth_service.otp_service.verify_otp(user.tfa_secret, request.otp):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid OTP code"
        )
    
    # Complete login
    profile = auth_service.behavior_analyzer.get_or_create_profile(user)
    assessment = auth_service.risk_engine.evaluate_risk(user, context, profile)
    
    result = await auth_service._complete_login(user, context, assessment, profile)
    
    return schemas.TokenResponse(
        access_token=result['access_token'],
        token_type=result['token_type'],
        expires_in=result['expires_in'],
        user_info=result.get('user_info')
    )


@router.post("/logout")
async def logout(
    req: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Logout current user."""
    # Get token from header
    auth_header = req.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else None
    
    if token:
        auth_service = AuthService(db)
        auth_service.logout(token, current_user)
    
    return {"message": "Successfully logged out"}


@router.post("/forgot-password")
async def forgot_password(
    request: schemas.PasswordResetRequest,
    db: Session = Depends(get_db)
):
    """Request password reset email."""
    auth_service = AuthService(db)
    await auth_service.request_password_reset(request.email)
    
    return {
        "message": "If an account exists with that email, a reset link has been sent."
    }


@router.post("/reset-password")
async def reset_password(
    request: schemas.PasswordResetConfirm,
    db: Session = Depends(get_db)
):
    """Reset password with token."""
    auth_service = AuthService(db)
    
    try:
        await auth_service.reset_password(
            reset_token=request.reset_token,
            new_password=request.new_password
        )
        return {"message": "Password has been reset successfully"}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/enable-2fa", response_model=schemas.Enable2FAResponse)
async def enable_2fa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Enable 2FA for current user."""
    auth_service = AuthService(db)
    result = auth_service.enable_2fa(current_user)
    
    return schemas.Enable2FAResponse(
        secret=result['secret'],
        qr_code=result['qr_code'],
        backup_codes=result['backup_codes']
    )


@router.post("/verify-2fa")
async def verify_2fa(
    request: schemas.Verify2FARequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Verify and activate 2FA."""
    auth_service = AuthService(db)
    
    if not auth_service.verify_and_activate_2fa(current_user, request.otp):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP code"
        )
    
    return {"message": "2FA has been enabled successfully"}


@router.post("/disable-2fa")
async def disable_2fa(
    password: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Disable 2FA for current user."""
    auth_service = AuthService(db)
    
    if not auth_service.disable_2fa(current_user, password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password"
        )
    
    return {"message": "2FA has been disabled"}


# ============ EMAIL & SMS VERIFICATION ENDPOINTS ============

@router.post("/request-email-verification")
async def request_email_verification(
    request: dict,
    db: Session = Depends(get_db)
):
    """Request email verification code."""
    from ..models import User, EmailVerificationCode
    from ..core.security import generate_verification_code
    
    email = request.get('email')
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email required"
        )
    
    user = db.query(User).filter(User.email == email).first()
    if not user:
        # Don't reveal if user exists
        return {"message": "If an account exists, verification email has been sent"}
    
    if user.is_verified:
        return {"message": "Email already verified"}
    
    # Generate code
    code = generate_verification_code()
    
    # Save verification code
    verification = EmailVerificationCode(
        user_id=user.id,
        email=email,
        verification_type="email",
        verification_code=code,
        expires_at=datetime.utcnow() + timedelta(hours=24)
    )
    db.add(verification)
    db.commit()
    
    # Send email
    from ..auth.email import EmailService
    email_service = EmailService()
    await email_service.send_verification_code(email, code)
    
    return {"message": "Verification email sent"}


@router.post("/verify-email")
async def verify_email(
    request: dict,
    db: Session = Depends(get_db)
):
    """Verify email with code."""
    from ..models import User, EmailVerificationCode
    
    email = request.get('email')
    code = request.get('code')
    
    if not email or not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email and code required"
        )
    
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Find valid verification code
    verification = db.query(EmailVerificationCode).filter(
        EmailVerificationCode.user_id == user.id,
        EmailVerificationCode.verification_code == code,
        EmailVerificationCode.verification_type == "email",
        EmailVerificationCode.is_used == False,
        EmailVerificationCode.expires_at > datetime.utcnow()
    ).first()
    
    if not verification:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired code"
        )
    
    # Mark as used
    verification.is_used = True
    user.is_verified = True
    db.commit()
    
    return {"message": "Email verified successfully"}


@router.post("/request-sms")
async def request_sms_verification(
    request: dict,
    db: Session = Depends(get_db)
):
    """Request SMS verification code."""
    from ..auth.sms import get_sms_service
    from ..core.security import generate_verification_code
    from ..models import User, EmailVerificationCode
    
    phone = request.get('phone')
    if not phone:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone number required"
        )
    
    # Generate code
    code = generate_verification_code()
    
    # Send SMS first to check if it succeeds
    sms_service = get_sms_service()
    success = await sms_service.send_verification_code(phone, code)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send SMS"
        )
    
    # Only save to database if SMS sending succeeds
    verification = EmailVerificationCode(
        phone=phone,
        verification_type="sms",
        verification_code=code,
        expires_at=datetime.utcnow() + timedelta(hours=1)  # Shorter expiry for SMS
    )
    db.add(verification)
    db.commit()
    
    return {
        "message": "SMS verification code sent",
        "note": "Check your phone for the verification code"
    }


@router.post("/verify-sms")
async def verify_sms(
    request: dict,
    db: Session = Depends(get_db)
):
    """Verify SMS code."""
    from ..models import EmailVerificationCode
    
    phone = request.get('phone')
    code = request.get('code')
    
    if not phone or not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone and code required"
        )
    
    # Find valid SMS verification code
    verification = db.query(EmailVerificationCode).filter(
        EmailVerificationCode.phone == phone,
        EmailVerificationCode.verification_code == code,
        EmailVerificationCode.verification_type == "sms",
        EmailVerificationCode.is_used == False,
        EmailVerificationCode.expires_at > datetime.utcnow()
    ).first()
    
    if not verification:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired code"
        )
    
    # Mark as used
    verification.is_used = True
    db.commit()
    
    return {
        "message": "SMS verified successfully",
        "phone": phone
    }


# ============ END EMAIL & SMS VERIFICATION ============
