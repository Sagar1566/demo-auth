"""
Framework Usage Tracking Middleware
Middleware to track who is using the AdaptiveAuth framework and detect anomalous usage patterns.
"""

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from sqlalchemy.orm import Session
from ..models import FrameworkUsage
from ..core.database import get_db
from datetime import datetime
import re


class FrameworkUsageTrackingMiddleware(BaseHTTPMiddleware):
    """
    Middleware to track framework usage and detect anomalies.
    Records every API call to the framework with client details.
    """
    
    def __init__(self, app):
        super().__init__(app)
        self.anomaly_patterns = [
            # Pattern 1: High frequency requests from same IP
            r"/api/v1/auth/(login|register)",
            # Pattern 2: Multiple endpoints accessed rapidly
            r"/api/v1/(auth|user|risk)/.*",
            # Pattern 3: Unusual user agents (bots)
            r"(bot|crawler|scraper|spider)",  # Case insensitive check
        ]
    
    async def dispatch(self, request: Request, call_next):
        # Process the request
        response = await call_next(request)
        
        # Track usage after request processing
        self.track_usage(request, response)
        
        return response
    
    def track_usage(self, request: Request, response: Response):
        """
        Track framework usage and detect anomalies.
        """
        try:
            # Extract client information
            client_ip = self.get_client_ip(request)
            user_agent = request.headers.get('user-agent', '')
            endpoint = request.url.path
            method = request.method
            
            # Calculate risk score based on usage patterns
            risk_score, is_anomalous, anomaly_desc = self.detect_anomalies(
                client_ip, user_agent, endpoint, method
            )
            
            # Create database session and record usage
            db: Session = next(get_db())
            
            usage_record = FrameworkUsage(
                client_ip=client_ip,
                user_agent=user_agent,
                endpoint_accessed=endpoint,
                method=method,
                risk_score=risk_score,
                is_anomalous=is_anomalous,
                anomaly_description=anomaly_desc if is_anomalous else None
            )
            
            db.add(usage_record)
            db.commit()
            
            # Close session
            db.close()
            
        except Exception as e:
            # Log error but don't break the request
            print(f"Error tracking framework usage: {str(e)}")
    
    def get_client_ip(self, request: Request) -> str:
        """
        Get client IP address from request, considering proxies.
        """
        forwarded_for = request.headers.get('x-forwarded-for')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('x-real-ip')
        if real_ip:
            return real_ip
        
        return request.client.host
    
    def detect_anomalies(self, client_ip: str, user_agent: str, endpoint: str, method: str) -> tuple[float, bool, str]:
        """
        Detect anomalous usage patterns.
        Returns: (risk_score, is_anomalous, anomaly_description)
        """
        risk_score = 0.0
        anomalies = []
        
        # Check for bot-like user agents
        if user_agent.lower().find('bot') != -1 or user_agent.lower().find('crawler') != -1:
            risk_score += 30.0
            anomalies.append("Bot-like user agent detected")
        
        # Check for unusual endpoints (potential probing)
        suspicious_endpoints = [
            '/api/v1/admin',  # Admin endpoints
            '/api/v1/debug',  # Debug endpoints
            '/health',        # Health checks (if unusual pattern)
        ]
        
        for suspicious_endpoint in suspicious_endpoints:
            if suspicious_endpoint in endpoint:
                risk_score += 25.0
                anomalies.append(f"Suspicious endpoint accessed: {endpoint}")
        
        # Check for high-risk authentication patterns
        if method == 'POST' and '/api/v1/auth/' in endpoint:
            risk_score += 10.0
            if endpoint in ['/api/v1/auth/login', '/api/v1/auth/register']:
                anomalies.append("Authentication endpoint accessed")
        
        # Check for potential brute force patterns (would need rate limiting data)
        # For now, just flag rapid consecutive requests
        
        is_anomalous = risk_score >= 20.0  # Threshold for anomaly detection
        anomaly_description = "; ".join(anomalies) if anomalies else None
        
        return risk_score, is_anomalous, anomaly_description


def setup_framework_tracking(app):
    """
    Set up framework usage tracking middleware.
    """
    app.add_middleware(FrameworkUsageTrackingMiddleware)