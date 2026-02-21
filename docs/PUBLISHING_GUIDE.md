# Publishing Guide: SAGAR AdaptiveAuth Framework

## Table of Contents
1. [Overview](#overview)
2. [Features](#features)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Deployment](#deployment)
7. [API Documentation](#api-documentation)
8. [Admin Dashboard](#admin-dashboard)
9. [Usage Examples](#usage-examples)
10. [Production Checklist](#production-checklist)

## Overview
SAGAR AdaptiveAuth is an advanced authentication framework that provides risk-based adaptive authentication with dynamic security requirements. The framework adjusts security levels based on contextual signals and continuously monitors user sessions for suspicious activity.

## Features
- **Risk-Based Authentication**: Adjusts security requirements dynamically (Security Levels 0-4)
- **Multi-Factor Authentication**: Supports 2FA, email, and SMS verification
- **Behavioral Biometrics**: Typing patterns and mouse movement analysis
- **Session Monitoring**: Real-time session verification
- **Admin Dashboard**: Comprehensive monitoring and management tools
- **Framework Usage Tracking**: Monitor who uses your framework
- **Anomaly Detection**: Automated suspicious activity detection
- **Analytics & Reporting**: Charts, PDF, and CSV export capabilities

## Prerequisites
- Python 3.8 or higher
- pip package manager
- Git (optional, for cloning)
- PostgreSQL or SQLite (default)

## Installation

### Quick Start
```bash
# Clone the repository
git clone https://github.com/yourusername/adaptiveauth.git
cd adaptiveauth

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the server
python main.py
```

### Manual Installation
```bash
# Create project directory
mkdir adaptiveauth && cd adaptiveauth

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install core dependencies
pip install fastapi uvicorn sqlalchemy python-multipart pydantic[email] qrcode[pil] python-jose[cryptography] passlib[bcrypt] python-dotenv requests twilio

# Copy the framework files to your project
# (Include all files from the repository)

# Install remaining dependencies
pip install -r requirements.txt

# Start the server
python main.py
```

## Configuration

### Environment Variables
Create a `.env` file in the root directory:

```env
# Database Configuration
DATABASE_URL=sqlite:///./adaptiveauth.db
# For PostgreSQL: postgresql://user:password@localhost/dbname

# Security Configuration
SECRET_KEY=your-super-secret-key-change-in-production
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# Email Configuration
EMAIL_SERVICE=gmail  # gmail, sendgrid, mailgun
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password

# SMS Configuration (Twilio)
TWILIO_ACCOUNT_SID=your-account-sid
TWILIO_AUTH_TOKEN=your-auth-token
TWILIO_PHONE_NUMBER=+1234567890

# Risk Assessment Weights
ADAPTIVEAUTH_RISK_DEVICE_WEIGHT=30.0
ADAPTIVEAUTH_RISK_LOCATION_WEIGHT=25.0
ADAPTIVEAUTH_RISK_TIME_WEIGHT=15.0
ADAPTIVEAUTH_RISK_VELOCITY_WEIGHT=15.0
ADAPTIVEAUTH_RISK_BEHAVIOR_WEIGHT=15.0
```

### Configuration Settings
The framework uses Pydantic Settings for configuration management:

```python
# adaptiveauth/config.py
from pydantic_settings import BaseSettings
from pydantic import Field

class Settings(BaseSettings):
    DATABASE_URL: str = Field(default="sqlite:///./adaptiveauth.db", description="Database connection string")
    SECRET_KEY: str = Field(default="your-super-secret-key-change-in-production", description="JWT secret key")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, description="Access token expiration in minutes")
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, description="Refresh token expiration in days")
    
    class Config:
        env_file = ".env"
        extra = "ignore"
```

## Deployment

### Production Deployment
For production deployments, use the following configuration:

#### 1. Using Docker (Recommended)
```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "4"]
```

#### 2. Direct Deployment
```bash
# Install in production environment
pip install -r requirements.txt

# Run with uvicorn (production)
uvicorn main:app --host 0.0.0.0 --port 8080 --workers 4 --timeout-keep-alive 30

# Or use a process manager like pm2 (with Node.js)
npm install -g pm2
pm2 start "uvicorn main:app --host 0.0.0.0 --port 8080 --workers 4" --name "adaptiveauth"
```

#### 3. Using systemd (Linux)
Create `/etc/systemd/system/adaptiveauth.service`:
```ini
[Unit]
Description=SAGAR AdaptiveAuth Service
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/adaptiveauth
EnvironmentFile=/path/to/adaptiveauth/.env
ExecStart=/path/to/adaptiveauth/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8080 --workers 4
Restart=always

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable adaptiveauth
sudo systemctl start adaptiveauth
```

## API Documentation

### Base URL
```
http://your-domain.com/api/v1
```

### Authentication Endpoints

#### Login
````
POST /auth/login
````
Authenticate a user and get JWT tokens.

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

#### Register
````
POST /auth/register
````
Register a new user.

**Request Body:**
```json
{
  "email": "newuser@example.com",
  "password": "SecurePassword123!",
  "full_name": "Jane Smith"
}
```

#### Adaptive Login
````
POST /auth/adaptive-login
````
Login with risk assessment and dynamic security requirements.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "device_fingerprint": "device-identifier",
  "remember_device": false
}
```

**Response:**
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

### User Management Endpoints

#### Get Profile
````
GET /user/profile
````
Get current user profile.

#### Update Profile
````
PUT /user/profile
````
Update user profile information.

**Request Body:**
```json
{
  "full_name": "New Name",
  "email": "newemail@example.com"
}
```

### Admin Endpoints

#### Get Statistics
````
GET /admin/statistics
````
Get admin dashboard statistics.

#### List Users
````
GET /admin/users
````
List all users with pagination.

#### Framework Usage Statistics
````
GET /admin/framework-statistics
````
Get statistics about framework usage.

#### Export Data
````
GET /admin/export/users
GET /admin/export/sessions
GET /admin/export/risk-events
GET /admin/export/anomalies
GET /admin/export/framework-usages
````
Export data in CSV format.

## Admin Dashboard

### Access
The admin dashboard is accessible via the HTML interface:
```
http://your-domain.com/static/index.html
```

### Admin Credentials
Default admin user is created automatically:
- **Email:** `admin@adaptiveauth.com`
- **Password:** `Admin@123`

### Dashboard Features
1. **User Management**: View, activate/deactivate users
2. **System Statistics**: Overall system health and metrics
3. **Risk Events**: Monitor security events and alerts
4. **Data Export**: Export all system data to CSV
5. **Framework Usage Analytics**: Track who uses your framework
6. **Anomaly Detection**: Identify suspicious usage patterns
7. **Analytics & Charts**: Visualize data with charts
8. **PDF/CSV Reports**: Generate comprehensive reports

## Usage Examples

### 1. Basic Authentication
```javascript
// Login
fetch('/api/v1/auth/login', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'SecurePassword123!'
  })
})
.then(response => response.json())
.then(data => {
  localStorage.setItem('authToken', data.access_token);
});

// Protected API call
fetch('/api/v1/user/profile', {
  headers: {
    'Authorization': `Bearer ${localStorage.getItem('authToken')}`
  }
});
```

### 2. Adaptive Authentication
```javascript
// Adaptive login with risk assessment
fetch('/api/v1/auth/adaptive-login', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'SecurePassword123!',
    device_fingerprint: getDeviceFingerprint(),
    remember_device: true
  })
})
.then(response => response.json())
.then(data => {
  if (data.status === 'challenge_required') {
    // Handle challenge (email/SMS verification)
    showVerificationPrompt(data.challenge_type);
  } else if (data.status === 'success') {
    // Login successful
    storeTokens(data);
  }
});
```

### 3. Framework Integration
As a developer integrating this framework into your project:

```python
# In your application
from adaptiveauth import AdaptiveAuth, get_current_user, require_admin
from fastapi import Depends, FastAPI

# Initialize the framework
auth = AdaptiveAuth(
    database_url="postgresql://user:pass@localhost/mydb",
    secret_key="your-secret-key",
    enable_2fa=True,
    enable_risk_assessment=True,
    enable_session_monitoring=True
)

app = FastAPI()
auth.init_app(app, prefix="/api/v1")

# Use the authentication in your routes
@app.get("/protected-endpoint")
async def protected_route(current_user = Depends(get_current_user)):
    return {"message": f"Hello {current_user.email}"}
```

## Production Checklist

### Before Going Live
- [ ] Change the default SECRET_KEY
- [ ] Configure production database (PostgreSQL recommended)
- [ ] Set up SSL/TLS certificates
- [ ] Configure proper email/SMS services
- [ ] Set up monitoring and logging
- [ ] Configure backup procedures
- [ ] Review security settings
- [ ] Test all endpoints
- [ ] Set up rate limiting
- [ ] Configure CDN for static assets

### Security Hardening
- [ ] Use HTTPS in production
- [ ] Validate all inputs
- [ ] Sanitize all outputs
- [ ] Implement proper error handling
- [ ] Regular security audits
- [ ] Keep dependencies updated
- [ ] Use strong password policies
- [ ] Implement account lockout mechanisms

### Performance Optimization
- [ ] Use connection pooling
- [ ] Implement caching
- [ ] Optimize database queries
- [ ] Use CDN for static assets
- [ ] Monitor performance metrics
- [ ] Set up load balancing if needed

## Support & Community

### Getting Help
- **Issues**: Report bugs and feature requests on GitHub
- **Documentation**: Full API documentation at `/docs` endpoint
- **Community**: Join our Discord/Slack community

### Contributing
We welcome contributions! Please read our CONTRIBUTING.md file for guidelines.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Versioning
We use Semantic Versioning (SemVer) for versioning. For the versions available, see the tags on this repository.

---

**SAGAR AdaptiveAuth Framework** - Making authentication smarter and more secure, one adaptive login at a time.