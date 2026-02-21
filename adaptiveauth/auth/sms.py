"""
AdaptiveAuth SMS Service
SMS notifications using Twilio for verification codes.
"""
from typing import Optional
from ..config import get_settings


class SMSService:
    """SMS service for authentication via Twilio."""
    
    def __init__(self):
        settings = get_settings()
        self.account_sid = settings.TWILIO_ACCOUNT_SID
        self.auth_token = settings.TWILIO_AUTH_TOKEN
        self.phone_number = settings.TWILIO_PHONE_NUMBER
        self._client = None
    
    @property
    def is_configured(self) -> bool:
        """Check if SMS is properly configured."""
        return all([self.account_sid, self.auth_token, self.phone_number])
    
    def _get_client(self):
        """Get Twilio client."""
        if self._client is None:
            try:
                from twilio.rest import Client
                self._client = Client(self.account_sid, self.auth_token)
            except ImportError:
                print("Twilio not installed. Run: pip install twilio")
                return None
        return self._client
    
    async def send_sms(self, to_phone: str, message: str) -> bool:
        """Send SMS to phone number."""
        if not self.is_configured:
            print("=" * 60)
            print("📱 SMS NOT CONFIGURED - Printing to console instead")
            print("=" * 60)
            print(f"To: {to_phone}")
            print(f"Message: {message}")
            print("=" * 60)
            return True
        
        try:
            client = self._get_client()
            if not client:
                return False
            
            message = client.messages.create(
                body=message,
                from_=self.phone_number,
                to=to_phone
            )
            
            print(f"SMS sent successfully. SID: {message.sid}")
            return True
            
        except Exception as e:
            print(f"Failed to send SMS: {e}")
            # Log the error but return False to indicate failure
            return False
    
    async def send_verification_code(self, phone: str, code: str) -> bool:
        """Send verification code via SMS."""
        message = f"Your AdaptiveAuth verification code is: {code}. Valid for 15 minutes."
        return await self.send_sms(phone, message)
    
    async def send_password_reset(self, phone: str, code: str) -> bool:
        """Send password reset code via SMS."""
        message = f"Your AdaptiveAuth password reset code is: {code}. Valid for 15 minutes."
        return await self.send_sms(phone, message)
    
    async def send_security_alert(self, phone: str, alert_type: str, details: str) -> bool:
        """Send security alert via SMS."""
        message = f"AdaptiveAuth Security Alert: {alert_type}. {details}"
        return await self.send_sms(phone, message)


# Global instance
_sms_service = None


def get_sms_service() -> SMSService:
    """Get SMS service singleton."""
    global _sms_service
    if _sms_service is None:
        _sms_service = SMSService()
    return _sms_service
