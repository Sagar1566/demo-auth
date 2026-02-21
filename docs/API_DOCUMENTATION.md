# SAGAR AdaptiveAuth Framework - API Documentation

## Table of Contents
1. [Overview](#overview)
2. [Authentication](#authentication)
3. [API Endpoints](#api-endpoints)
4. [Request/Response Formats](#requestresponse-formats)
5. [Error Handling](#error-handling)
6. [Rate Limiting](#rate-limiting)
7. [SDK Examples](#sdk-examples)

## Overview

The SAGAR AdaptiveAuth Framework provides a comprehensive authentication API with risk-based adaptive security. The API follows REST principles and returns JSON responses.

### Base URL
```
http://your-domain.com/api/v1
```

### Authentication
Most endpoints require authentication using JWT Bearer tokens:
````
Authorization: Bearer <jwt_token>
```

## Authentication Endpoints

### Login
````
POST /auth/login
```

Authenticate a user and receive JWT tokens.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response:**
```json
{
  "access_token": "jwt_token_here",
  "token_type": "bearer",
  "expires_in": 1800,
  "refresh_token": "refresh_token_here",
  "user_info": {
    "id": 1,
    "email": "user@example.com",
    "full_name": "John Doe",
    "role": "user"
  }
}
```

### Register
````
POST /auth/register
```

Register a new user account.

**Request Body:**
```json
{
  "email": "newuser@example.com",
  "password": "SecurePassword123!",
  "full_name": "Jane Smith"
}
```

**Response:**
```json
{
  "message": "User registered successfully",
  "user_info": {
    "id": 2,
    "email": "newuser@example.com",
    "full_name": "Jane Smith"
  }
}
```

### Adaptive Login
````
POST /auth/adaptive-login
```

Login with dynamic security requirements based on risk assessment.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "device_fingerprint": "device-identifier-here",
  "remember_device": false
}
```

**Response - Success:**
```json
{
  "status": "success",
  "risk_level": "low",
  "security_level": 0,
  "access_token": "jwt_token_here",
  "token_type": "bearer",
  "message": "Login successful"
}
```

**Response - Challenge Required:**
```json
{
  "status": "challenge_required",
  "risk_level": "medium",
  "security_level": 2,
  "challenge_type": "email",
  "challenge_id": "challenge-id-here",
  "message": "Email verification required"
}
```

**Response - Blocked:**
```json
{
  "status": "blocked",
  "risk_level": "critical",
  "security_level": 4,
  "message": "Account temporarily locked due to suspicious activity"
}
```

### Refresh Token
````
POST /auth/refresh
```

Refresh access token using refresh token.

**Request Body:**
```json
{
  "refresh_token": "refresh_token_here"
}
```

**Response:**
```json
{
  "access_token": "new_jwt_token_here",
  "token_type": "bearer",
  "expires_in": 1800
}
```

### Logout
````
POST /auth/logout
```

Logout user and invalidate session.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "message": "Logged out successfully"
}
```

## 2FA Endpoints

### Setup 2FA
````
POST /auth/setup-2fa
```

Setup two-factor authentication for the user.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "secret": "2FA_SECRET_HERE",
  "qr_code": "base64_encoded_qr_code",
  "backup_codes": ["code1", "code2", "code3"]
}
```

### Verify 2FA
````
POST /auth/verify-2fa
```

Verify 2FA code during login or for sensitive operations.

**Request Body:**
```json
{
  "otp": "123456"
}
```

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "verified": true,
  "message": "2FA verified successfully"
}
```

### Disable 2FA
````
POST /auth/disable-2fa
```

Disable two-factor authentication for the user.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "message": "2FA disabled successfully"
}
```

## User Management Endpoints

### Get Profile
````
GET /user/profile
```

Get current user's profile information.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "id": 1,
  "email": "user@example.com",
  "full_name": "John Doe",
  "role": "user",
  "is_active": true,
  "is_verified": true,
  "tfa_enabled": false,
  "created_at": "2023-01-01T00:00:00Z"
}
```

### Update Profile
````
PUT /user/profile
```

Update user's profile information.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Request Body:**
```json
{
  "full_name": "New Name",
  "email": "newemail@example.com"
}
```

**Response:**
```json
{
  "message": "Profile updated successfully",
  "user_info": {
    "id": 1,
    "email": "newemail@example.com",
    "full_name": "New Name"
  }
}
```

### Change Password
````
PUT /user/change-password
```

Change user's password.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Request Body:**
```json
{
  "current_password": "old_password",
  "new_password": "new_secure_password"
}
```

**Response:**
```json
{
  "message": "Password changed successfully"
}
```

### Get Sessions
````
GET /user/sessions
```

Get user's active sessions.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "sessions": [
    {
      "id": 1,
      "ip_address": "192.168.1.1",
      "user_agent": "Mozilla/5.0...",
      "country": "US",
      "city": "New York",
      "risk_level": "low",
      "status": "active",
      "last_activity": "2023-01-01T00:00:00Z",
      "created_at": "2023-01-01T00:00:00Z",
      "is_current": true
    }
  ],
  "total": 1
}
```

### Revoke Session
````
DELETE /user/sessions/{session_id}
```

Revoke a specific session.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "message": "Session revoked successfully"
}
```

## Risk Assessment Endpoints

### Assess Risk
````
POST /risk/assess
```

Assess risk for given context.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Request Body:**
```json
{
  "ip_address": "192.168.1.1",
  "user_agent": "Mozilla/5.0...",
  "device_fingerprint": "device-fingerprint"
}
```

**Response:**
```json
{
  "risk_score": 25.5,
  "risk_level": "medium",
  "security_level": 2,
  "risk_factors": {
    "device": 10.0,
    "location": 15.0,
    "time": 0.0,
    "velocity": 0.0,
    "behavior": 0.5
  },
  "required_action": "email_verification",
  "message": "Medium risk detected, additional verification required"
}
```

### Get Behavior Profile
````
GET /risk/behavior-profile
```

Get user's behavioral profile.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "known_devices": [
    {
      "fingerprint": "device-123",
      "name": "Chrome on Windows",
      "first_seen": "2023-01-01T00:00:00Z",
      "last_seen": "2023-01-01T00:00:00Z"
    }
  ],
  "known_ips": [
    {
      "ip": "192.168.1.1",
      "location": "Home Office",
      "first_seen": "2023-01-01T00:00:00Z",
      "last_seen": "2023-01-01T00:00:00Z"
    }
  ],
  "typical_login_hours": [8, 9, 10, 13, 14, 15],
  "typical_login_days": [0, 1, 2, 3, 4],
  "average_session_duration": 1800.0,
  "total_logins": 150,
  "successful_logins": 148,
  "failed_logins": 2
}
```

## Admin Endpoints

### Get Statistics
````
GET /admin/statistics
```

Get system-wide statistics.

**Headers:**
```
Authorization: Bearer <admin_jwt_token>
```

**Response:**
```json
{
  "total_users": 150,
  "active_users": 120,
  "blocked_users": 5,
  "active_sessions": 45,
  "high_risk_events_today": 3,
  "failed_logins_today": 12,
  "new_users_today": 2
}
```

### List Users
````
GET /admin/users
```

List all users with pagination.

**Headers:**
```
Authorization: Bearer <admin_jwt_token>
```

**Query Parameters:**
- `page` (optional, default: 1) - Page number
- `page_size` (optional, default: 20) - Items per page
- `role` (optional) - Filter by role
- `is_active` (optional) - Filter by active status

**Response:**
```json
{
  "users": [
    {
      "id": 1,
      "email": "user@example.com",
      "full_name": "John Doe",
      "role": "user",
      "is_active": true,
      "is_verified": true,
      "tfa_enabled": false,
      "created_at": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 150,
  "page": 1,
  "page_size": 20
}
```

### Get User by ID
````
GET /admin/users/{user_id}
```

Get specific user details.

**Headers:**
```
Authorization: Bearer <admin_jwt_token>
```

### Block User
````
POST /admin/users/{user_id}/block
```

Block a user account.

**Headers:**
```
Authorization: Bearer <admin_jwt_token>
```

**Request Body:**
```json
{
  "reason": "Suspicious activity",
  "duration_hours": 24
}
```

**Response:**
```json
{
  "message": "User user@example.com has been blocked"
}
```

### Unblock User
````
POST /admin/users/{user_id}/unblock
```

Unblock a user account.

**Headers:**
```
Authorization: Bearer <admin_jwt_token>
```

**Response:**
```json
{
  "message": "User user@example.com has been unblocked"
}
```

### List Sessions
````
GET /admin/sessions
```

List all active sessions.

**Headers:**
```
Authorization: Bearer <admin_jwt_token>
```

**Query Parameters:**
- `status_filter` (optional) - Filter by status (active, expired, revoked, suspicious)
- `risk_level` (optional) - Filter by risk level
- `page` (optional, default: 1) - Page number
- `page_size` (optional, default: 20) - Items per page

**Response:**
```json
{
  "sessions": [
    {
      "id": 1,
      "ip_address": "192.168.1.1",
      "user_agent": "Mozilla/5.0...",
      "country": "US",
      "city": "New York",
      "risk_level": "low",
      "status": "active",
      "last_activity": "2023-01-01T00:00:00Z",
      "created_at": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 45
}
```

### Revoke Session
````
POST /admin/sessions/{session_id}/revoke
```

Revoke a specific session.

**Headers:**
```
Authorization: Bearer <admin_jwt_token>
```

**Request Body:**
```json
{
  "reason": "Administrative action"
}
```

**Response:**
```json
{
  "message": "Session revoked"
}
```

### List Risk Events
````
GET /admin/risk-events
```

List risk events.

**Headers:**
```
Authorization: Bearer <admin_jwt_token>
```

**Query Parameters:**
- `risk_level` (optional) - Filter by risk level
- `event_type` (optional) - Filter by event type
- `user_id` (optional) - Filter by user ID
- `page` (optional, default: 1) - Page number
- `page_size` (optional, default: 20) - Items per page

**Response:**
```json
{
  "events": [
    {
      "id": 1,
      "event_type": "login_attempt",
      "risk_score": 45.0,
      "risk_level": "high",
      "ip_address": "192.168.1.1",
      "risk_factors": {
        "device": 10.0,
        "location": 35.0
      },
      "action_taken": "email_verification",
      "created_at": "2023-01-01T00:00:00Z",
      "resolved": false
    }
  ],
  "total": 10,
  "page": 1,
  "page_size": 20
}
```

### List Anomalies
````
GET /admin/anomalies
```

List detected anomaly patterns.

**Headers:**
```
Authorization: Bearer <admin_jwt_token>
```

**Query Parameters:**
- `active_only` (optional, default: true) - Only active anomalies

**Response:**
```json
{
  "anomalies": [
    {
      "id": 1,
      "pattern_type": "brute_force",
      "severity": "high",
      "confidence": 0.95,
      "is_active": true,
      "first_detected": "2023-01-01T00:00:00Z",
      "last_detected": "2023-01-01T00:00:00Z",
      "pattern_data": {
        "attempts": 100,
        "ip_count": 10,
        "time_window": "1 hour"
      }
    }
  ],
  "total": 3
}
```

### Resolve Anomaly
````
POST /admin/anomalies/{anomaly_id}/resolve
```

Mark an anomaly as resolved.

**Headers:**
```
Authorization: Bearer <admin_jwt_token>
```

**Request Body:**
```json
{
  "false_positive": false
}
```

**Response:**
```json
{
  "message": "Anomaly resolved"
}
```

### Framework Usage Statistics
````
GET /admin/framework-statistics
```

Get framework usage statistics.

**Headers:**
```
Authorization: Bearer <admin_jwt_token>
```

**Response:**
```json
{
  "total_usage": 1250,
  "total_anomalies": 5,
  "unique_ips": 45,
  "unique_endpoints": 23,
  "usage_today": 15,
  "anomalies_today": 0,
  "top_endpoints": [
    {"endpoint": "/api/v1/auth/login", "count": 450},
    {"endpoint": "/api/v1/user/profile", "count": 200}
  ],
  "top_ips": [
    {"ip": "127.0.0.1", "count": 500},
    {"ip": "192.168.1.100", "count": 150}
  ]
}
```

### List Framework Usages
````
GET /admin/framework-usages
```

List framework usage records.

**Headers:**
```
Authorization: Bearer <admin_jwt_token>
```

**Query Parameters:**
- `is_anomalous` (optional) - Filter by anomaly status
- `client_ip` (optional) - Filter by client IP
- `endpoint` (optional) - Filter by endpoint
- `page` (optional, default: 1) - Page number
- `page_size` (optional, default: 20) - Items per page

**Response:**
```json
{
  "usages": [
    {
      "id": 1,
      "client_ip": "127.0.0.1",
      "user_agent": "Mozilla/5.0...",
      "endpoint_accessed": "/api/v1/auth/login",
      "method": "POST",
      "timestamp": "2023-01-01T00:00:00Z",
      "risk_score": 10.0,
      "is_anomalous": false,
      "anomaly_description": null
    }
  ],
  "total": 1250,
  "page": 1,
  "page_size": 20
}
```

### Export Data Endpoints

#### Export Users
````
GET /admin/export/users
```

Export all users to CSV.

**Headers:**
```
Authorization: Bearer <admin_jwt_token>
```

**Response:** CSV file download

#### Export Sessions
````
GET /admin/export/sessions
```

Export all sessions to CSV.

**Headers:**
```
Authorization: Bearer <admin_jwt_token>
```

**Response:** CSV file download

#### Export Risk Events
````
GET /admin/export/risk-events
```

Export all risk events to CSV.

**Headers:**
```
Authorization: Bearer <admin_jwt_token>
```

**Response:** CSV file download

#### Export Anomalies
````
GET /admin/export/anomalies
```

Export all anomalies to CSV.

**Headers:**
```
Authorization: Bearer <admin_jwt_token>
```

**Response:** CSV file download

#### Export Framework Usages
````
GET /admin/export/framework-usages
```

Export framework usage records to CSV.

**Headers:**
```
Authorization: Bearer <admin_jwt_token>
```

**Response:** CSV file download

## Request/Response Formats

### Common Response Structure
```json
{
  "message": "Success message",
  "data": {...},  // Optional data payload
  "timestamp": "2023-01-01T00:00:00Z"
}
```

### Error Response Structure
```json
{
  "detail": "Error message",
  "error_code": "ERROR_CODE",
  "timestamp": "2023-01-01T00:00:00Z"
}
```

## Error Handling

### HTTP Status Codes
- `200 OK` - Successful request
- `201 Created` - Resource created successfully
- `400 Bad Request` - Invalid request format
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `422 Unprocessable Entity` - Validation error
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error

### Common Error Responses

**Invalid Credentials:**
```json
{
  "detail": "Incorrect email or password"
}
```

**Unauthorized Access:**
```json
{
  "detail": "Not authenticated"
}
```

**Insufficient Permissions:**
```json
{
  "detail": "Insufficient permissions"
}
```

**Validation Error:**
```json
{
  "detail": [
    {
      "loc": ["body", "email"],
      "msg": "value is not a valid email address",
      "type": "value_error.email"
    }
  ]
}
```

## Rate Limiting

The API implements rate limiting to prevent abuse:

- **Login attempts**: 5 per minute per IP
- **Registration**: 2 per hour per IP
- **General requests**: 100 per minute per user
- **Admin endpoints**: 50 per minute per admin user

When rate limit is exceeded:
```json
{
  "detail": "Rate limit exceeded. Try again in 60 seconds."
}
```

## SDK Examples

### JavaScript/Node.js
```javascript
// Login example
async function login(email, password) {
  try {
    const response = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email, password })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.detail);
    }
    
    localStorage.setItem('authToken', data.access_token);
    return data;
  } catch (error) {
    console.error('Login failed:', error.message);
    throw error;
  }
}

// Make authenticated requests
async function apiCall(endpoint, options = {}) {
  const token = localStorage.getItem('authToken');
  
  const response = await fetch(`/api/v1${endpoint}`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...options.headers
    },
    ...options
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail);
  }
  
  return response.json();
}

// Example: Get user profile
async function getUserProfile() {
  return await apiCall('/user/profile');
}
```

### Python
```python
import requests
import json

class AdaptiveAuthClient:
    def __init__(self, base_url, token=None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.session = requests.Session()
        
    def _get_headers(self):
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        return headers
    
    def login(self, email, password):
        response = self.session.post(
            f'{self.base_url}/auth/login',
            json={'email': email, 'password': password},
            headers=self._get_headers()
        )
        response.raise_for_status()
        data = response.json()
        self.token = data['access_token']
        return data
    
    def get_profile(self):
        response = self.session.get(
            f'{self.base_url}/user/profile',
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()
    
    def make_request(self, method, endpoint, **kwargs):
        response = self.session.request(
            method,
            f'{self.base_url}{endpoint}',
            headers=self._get_headers(),
            **kwargs
        )
        response.raise_for_status()
        return response.json()

# Usage
client = AdaptiveAuthClient('http://localhost:8080/api/v1')
login_data = client.login('user@example.com', 'password')
profile = client.get_profile()
```

### cURL Examples
```bash
# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'

# Get profile (with token)
curl -X GET http://localhost:8080/api/v1/user/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"

# Register new user
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "newuser@example.com", "password": "securepassword", "full_name": "Jane Doe"}'
```

## Security Best Practices

1. **Always use HTTPS** in production environments
2. **Store JWT tokens securely** (preferably in httpOnly cookies)
3. **Implement proper error handling** to avoid information disclosure
4. **Validate all inputs** on both client and server side
5. **Use strong passwords** with proper validation
6. **Enable 2FA** for admin accounts
7. **Monitor authentication logs** for suspicious activity
8. **Implement rate limiting** to prevent brute force attacks
9. **Regularly rotate JWT secrets** in production
10. **Keep dependencies updated** for security patches

## Versioning

The API uses URL versioning:
- Base URL: `/api/v1/`
- Future versions will be released as `/api/v2/`, etc.

## Support

For API support and questions:
- **Documentation**: Available at `/docs` endpoint
- **Issues**: Report bugs on GitHub
- **Contact**: [your-email@example.com]

---

This documentation covers all major API endpoints and usage patterns for the SAGAR AdaptiveAuth Framework.