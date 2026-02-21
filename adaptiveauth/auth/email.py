"""
AdaptiveAuth Email Service
Email notifications for authentication events.
"""
from typing import List, Optional
from fastapi_mail import FastMail, MessageSchema, MessageType, ConnectionConfig
from pydantic import EmailStr

from ..config import get_settings


class EmailService:
    """Email service for authentication-related notifications."""
    
    def __init__(self):
        self.settings = get_settings()
        self._mail = None
    
    @property
    def is_configured(self) -> bool:
        """Check if email is properly configured."""
        return all([
            self.settings.MAIL_USERNAME,
            self.settings.MAIL_PASSWORD,
            self.settings.MAIL_SERVER,
            self.settings.MAIL_FROM
        ])
    
    def _get_connection_config(self) -> ConnectionConfig:
        """Get email connection configuration."""
        return ConnectionConfig(
            MAIL_USERNAME=self.settings.MAIL_USERNAME or "",
            MAIL_PASSWORD=self.settings.MAIL_PASSWORD or "",
            MAIL_FROM=self.settings.MAIL_FROM or "",
            MAIL_PORT=self.settings.MAIL_PORT,
            MAIL_SERVER=self.settings.MAIL_SERVER or "",
            MAIL_STARTTLS=self.settings.MAIL_STARTTLS,
            MAIL_SSL_TLS=self.settings.MAIL_SSL_TLS,
            USE_CREDENTIALS=True,
            VALIDATE_CERTS=True
        )
    
    def _get_mail(self) -> FastMail:
        """Get FastMail instance."""
        if self._mail is None:
            config = self._get_connection_config()
            self._mail = FastMail(config)
        return self._mail
    
    async def send_email(
        self,
        to: List[EmailStr],
        subject: str,
        body: str,
        subtype: MessageType = MessageType.html
    ) -> bool:
        """Send an email."""
        if not self.is_configured:
            print("=" * 60)
            print("📧 EMAIL NOT CONFIGURED - Printing to console instead")
            print("=" * 60)
            print(f"To: {to}")
            print(f"Subject: {subject}")
            print("-" * 60)
            # Extract code from body if present
            import re
            code_match = re.search(r'class="code">(\d+)</div>', body)
            if code_match:
                print(f"🔑 VERIFICATION CODE: {code_match.group(1)}")
                print("-" * 60)
            print("Body preview (first 500 chars):")
            print(body[:500])
            print("=" * 60)
            return True
        
        try:
            message = MessageSchema(
                subject=subject,
                recipients=to,
                body=body,
                subtype=subtype
            )
            
            fm = self._get_mail()
            await fm.send_message(message)
            return True
        except Exception as e:
            print(f"Failed to send email: {e}")
            return False
    
    async def send_password_reset(self, email: str, reset_code: str, reset_url: str) -> bool:
        """Send password reset email."""
        subject = "Password Reset Request - AdaptiveAuth"
        
        body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #4A90D9; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; background: #f9f9f9; }}
                .button {{ display: inline-block; padding: 12px 24px; background: #4A90D9; color: white; 
                          text-decoration: none; border-radius: 4px; margin: 20px 0; }}
                .footer {{ padding: 20px; text-align: center; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Password Reset</h1>
                </div>
                <div class="content">
                    <p>Hello,</p>
                    <p>We received a request to reset your password. Click the button below to create a new password:</p>
                    <p style="text-align: center;">
                        <a href="{reset_url}?token={reset_code}" class="button">Reset Password</a>
                    </p>
                    <p>If you didn't request this, you can safely ignore this email.</p>
                    <p>This link will expire in 1 hour.</p>
                </div>
                <div class="footer">
                    <p>This is an automated message from AdaptiveAuth.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return await self.send_email([email], subject, body)
    
    async def send_verification_code(self, email: str, code: str) -> bool:
        """Send email verification code."""
        subject = "Verify Your Email - AdaptiveAuth"
        
        body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #4A90D9; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; background: #f9f9f9; }}
                .code {{ font-size: 32px; font-weight: bold; text-align: center; 
                        padding: 20px; background: #e9e9e9; letter-spacing: 5px; margin: 20px 0; }}
                .footer {{ padding: 20px; text-align: center; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Email Verification</h1>
                </div>
                <div class="content">
                    <p>Hello,</p>
                    <p>Please use the following code to verify your email address:</p>
                    <div class="code">{code}</div>
                    <p>This code will expire in 15 minutes.</p>
                    <p>If you didn't request this, please ignore this email.</p>
                </div>
                <div class="footer">
                    <p>This is an automated message from AdaptiveAuth.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return await self.send_email([email], subject, body)
    
    async def send_security_alert(
        self,
        email: str,
        alert_type: str,
        details: dict
    ) -> bool:
        """Send security alert notification."""
        subject = f"Security Alert - {alert_type} - AdaptiveAuth"
        
        details_html = "<br>".join([f"<strong>{k}:</strong> {v}" for k, v in details.items()])
        
        body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #E74C3C; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; background: #f9f9f9; }}
                .alert-box {{ background: #FDF2F2; border-left: 4px solid #E74C3C; padding: 15px; margin: 20px 0; }}
                .footer {{ padding: 20px; text-align: center; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Security Alert</h1>
                </div>
                <div class="content">
                    <p>Hello,</p>
                    <p>We detected unusual activity on your account:</p>
                    <div class="alert-box">
                        <strong>Alert Type:</strong> {alert_type}<br>
                        {details_html}
                    </div>
                    <p>If this was you, you can ignore this message.</p>
                    <p>If you don't recognize this activity, please secure your account immediately.</p>
                </div>
                <div class="footer">
                    <p>This is an automated security notification from AdaptiveAuth.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return await self.send_email([email], subject, body)
    
    async def send_new_device_alert(
        self,
        email: str,
        device_info: dict,
        ip_address: str,
        location: Optional[str] = None
    ) -> bool:
        """Send new device login alert."""
        details = {
            "Device": device_info.get('name', 'Unknown'),
            "Browser": device_info.get('browser', 'Unknown'),
            "IP Address": ip_address,
            "Location": location or "Unknown"
        }
        
        return await self.send_security_alert(email, "New Device Login", details)


# Global instance
_email_service = None


def get_email_service() -> EmailService:
    """Get email service singleton."""
    global _email_service
    if _email_service is None:
        _email_service = EmailService()
    return _email_service
