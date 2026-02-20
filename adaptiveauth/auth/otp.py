"""
AdaptiveAuth OTP Service
TOTP (Time-based One-Time Password) for 2FA.
"""
import pyotp
import qrcode
import base64
from io import BytesIO
from typing import Tuple, List
import secrets

from ..config import get_settings


class OTPService:
    """TOTP-based two-factor authentication service."""
    
    def __init__(self):
        self.settings = get_settings()
    
    def generate_secret(self) -> str:
        """Generate a new TOTP secret."""
        return pyotp.random_base32()
    
    def generate_totp(self, secret: str) -> pyotp.TOTP:
        """Create TOTP instance for a secret."""
        return pyotp.TOTP(
            secret,
            digits=self.settings.OTP_LENGTH,
            issuer=self.settings.OTP_ISSUER
        )
    
    def generate_qr_code(self, email: str, secret: str) -> str:
        """
        Generate QR code for TOTP setup.
        Returns base64 encoded image.
        """
        totp = self.generate_totp(secret)
        provisioning_uri = totp.provisioning_uri(
            name=email,
            issuer_name=self.settings.OTP_ISSUER
        )
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        img_base64 = base64.b64encode(buffer.getvalue()).decode()
        return f"data:image/png;base64,{img_base64}"
    
    def verify_otp(self, secret: str, otp: str) -> bool:
        """Verify an OTP code against the secret."""
        if not secret or not otp:
            return False
        
        totp = self.generate_totp(secret)
        # Allow 1 interval window for clock drift
        return totp.verify(otp, valid_window=1)
    
    def get_current_otp(self, secret: str) -> str:
        """Get current OTP (for testing purposes)."""
        totp = self.generate_totp(secret)
        return totp.now()
    
    def generate_backup_codes(self, count: int = 10) -> Tuple[List[str], List[str]]:
        """
        Generate backup codes for account recovery.
        Returns (plain_codes, hashed_codes).
        """
        from ..core.security import hash_password
        
        plain_codes = []
        hashed_codes = []
        
        for _ in range(count):
            # Generate 8-character alphanumeric code
            code = secrets.token_hex(4).upper()
            plain_codes.append(code)
            hashed_codes.append(hash_password(code))
        
        return plain_codes, hashed_codes
    
    def verify_backup_code(self, code: str, hashed_codes: List[str]) -> Tuple[bool, int]:
        """
        Verify a backup code.
        Returns (valid, index) where index is the position of used code.
        """
        from ..core.security import verify_password
        
        for i, hashed in enumerate(hashed_codes):
            if verify_password(code, hashed):
                return True, i
        
        return False, -1


# Global instance
_otp_service = None


def get_otp_service() -> OTPService:
    """Get OTP service singleton."""
    global _otp_service
    if _otp_service is None:
        _otp_service = OTPService()
    return _otp_service
