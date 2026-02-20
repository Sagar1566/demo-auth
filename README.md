# SAGAR AdaptiveAuth Framework

**SAGAR AdaptiveAuth** is a FREE, open-source authentication framework with JWT, 2FA, and adaptive risk-based authentication.

## Key Features

- 🔐 **JWT Authentication** with token management
- 🔐 **Two-Factor Authentication** (TOTP with QR codes)
- 🔐 **Risk-Based Adaptive Authentication** (Security levels 0-4)
- 🔐 **Behavioral Analysis** (device, IP, location tracking)
- 🔐 **Step-up Authentication** for high-risk scenarios
- 🔐 **Continuous Session Monitoring**
- 🔐 **Anomaly Detection** (brute force, credential stuffing)
- 🔐 **Admin Dashboard** with real-time risk monitoring
- 🔐 **Password Reset** with email verification

## Installation & Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/Sagar1566/HackWack.git
cd HackWack/AdaptiveAuth
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the application
```bash
python main.py
```
The server will start at `http://localhost:8000`

**Alternative:** Use the start script:
- On Windows: Double-click `start_server.bat`
- On Linux/Mac: Run `./start_server.sh`

## How to Use the Framework

### Option 1: Integrate with Your Existing FastAPI App

```python
from fastapi import FastAPI
from adaptiveauth import AdaptiveAuth

app = FastAPI()

# Initialize AdaptiveAuth
auth = AdaptiveAuth(
    database_url="sqlite:///./app.db",
    secret_key="your-super-secret-key"
)

# Mount all authentication routes
app.include_router(auth.router, prefix="/api/v1/auth")
```

### Option 2: Run Standalone Server

Use the main application file to run as a standalone authentication service.

## Available API Endpoints

After starting the server, visit `http://localhost:8000/docs` for interactive API documentation.

### Authentication
- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Standard login
- `POST /api/v1/auth/adaptive-login` - Risk-based adaptive login
- `POST /api/v1/auth/step-up` - Step-up verification
- `POST /api/v1/auth/logout` - Logout user

### User Management
- `GET /api/v1/user/profile` - Get user profile
- `PUT /api/v1/user/profile` - Update profile
- `GET /api/v1/user/security` - Security settings
- `GET /api/v1/user/sessions` - Active sessions
- `POST /api/v1/user/change-password` - Change password

### 2FA
- `POST /api/v1/auth/enable-2fa` - Enable 2FA
- `POST /api/v1/auth/verify-2fa` - Verify 2FA
- `POST /api/v1/auth/disable-2fa` - Disable 2FA

### Risk Assessment
- `POST /api/v1/adaptive/assess` - Assess current risk
- `GET /api/v1/adaptive/security-status` - Get security status
- `POST /api/v1/adaptive/verify-session` - Verify session
- `POST /api/v1/adaptive/challenge` - Request challenge
- `POST /api/v1/adaptive/verify` - Verify challenge

### Admin Dashboard
- `GET /api/v1/admin/users` - List users
- `GET /api/v1/admin/statistics` - Dashboard statistics
- `GET /api/v1/admin/risk-events` - Risk events
- `GET /api/v1/risk/overview` - Risk dashboard

## Security Levels

| Level | Risk | Authentication Required | Description |
|-------|------|------------------------|-------------|
| 0 | Low | Password | Known device + IP + browser |
| 1 | Medium | Password | Unknown browser |
| 2 | High | Password + Email | Unknown IP address |
| 3 | High | Password + 2FA | Unknown device |
| 4 | Critical | Blocked | Suspicious activity |

## Examples

Check out `run_example.py` for a complete integration example.

## Testing the Framework

To verify the framework works correctly, run:

```bash
python test_framework.py
```

For detailed testing instructions, see [HOW_TO_TEST.md](HOW_TO_TEST.md).

## License

**MIT License - Completely FREE and OPEN SOURCE**
- ✅ Use in personal projects
- ✅ Use in commercial projects  
- ✅ Modify and distribute
- ✅ No attribution required
- ✅ No licensing fees
