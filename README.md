# SAGAR AdaptiveAuth Framework

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104.0+-009688.svg)](https://fastapi.tiangolo.com/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)]

**Advanced Adaptive Authentication Framework with Risk-Based Security**

_Authentication that adapts to risk in real-time, protecting users while maintaining seamless experience_

</div>

## 🚀 Overview

SAGAR AdaptiveAuth is a cutting-edge authentication framework that implements risk-based adaptive authentication. The system dynamically adjusts security requirements based on contextual signals, behavioral biometrics, and real-time risk assessment to protect against modern threats while maintaining optimal user experience.

### Key Features:
- **Risk-Based Authentication** - 5-level security system (0-4) adjusting dynamically
- **Multi-Factor Authentication** - Support for 2FA, email, and SMS verification
- **Behavioral Biometrics** - Typing patterns and mouse movement analysis
- **Real-Time Session Monitoring** - Continuous verification during active sessions
- **Framework Usage Tracking** - Monitor who integrates your framework
- **Anomaly Detection** - Automated suspicious activity identification
- **Admin Dashboard** - Comprehensive monitoring and management tools
- **Analytics & Reporting** - Charts, PDF, and CSV export capabilities
- **Enterprise Ready** - Production-optimized with security-first design

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │  AdaptiveAuth   │    │    Backend      │
│   Interface     │◄──►│   Framework     │◄──►│   Services      │
│ (HTML/JS)       │    │                 │    │ (Your App)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                       ┌─────────────────┐
                       │  Risk Engine    │
                       │  (Real-time)    │
                       └─────────────────┘
                              │
                       ┌─────────────────┐
                       │  Analytics &    │
                       │  Monitoring     │
                       └─────────────────┘
```

## 📋 Security Levels

| Level | Name | Description | Requirements |
|-------|------|-------------|--------------|
| 0 | TRUSTED | Known device/IP/browser | Minimal authentication |
| 1 | BASIC | Standard login | Password only |
| 2 | VERIFIED | Unknown IP | Password + Email verification |
| 3 | SECURE | Unknown device | Password + 2FA |
| 4 | BLOCKED | Suspicious activity | Account locked |

## 🛠️ Tech Stack

- **Backend**: Python 3.8+, FastAPI
- **Database**: SQLAlchemy with SQLite/PostgreSQL support
- **Authentication**: JWT with refresh tokens
- **2FA**: TOTP with QR codes
- **Frontend**: HTML5, JavaScript, Chart.js
- **API**: RESTful endpoints with OpenAPI documentation
- **Security**: Rate limiting, input validation, OWASP compliance

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/adaptiveauth.git
cd adaptiveauth
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

4. **Configure environment**
```bash
cp .env.example .env
# Edit .env file with your configuration
```

5. **Start the server**
```bash
python main.py
```

6. **Access the application**
- API: `http://localhost:8080`
- Documentation: `http://localhost:8080/docs`
- Admin Interface: `http://localhost:8080/static/index.html`

## 🔐 Admin Access

Default admin credentials:
- **Email**: `admin@adaptiveauth.com`
- **Password**: `Admin@123`

**⚠️ SECURITY NOTICE**: Change these credentials immediately after first login!

## 📊 Admin Dashboard Features

### 1. User Management
- View all users
- Activate/deactivate accounts
- Manage user roles

### 2. System Statistics
- User counts and activity
- Session monitoring
- Security metrics

### 3. Risk Events
- Monitor authentication attempts
- View security alerts
- Track risk patterns

### 4. Framework Usage Analytics
- Track who uses your framework
- Identify integration patterns
- Monitor usage trends

### 5. Anomaly Detection
- Identify suspicious activity
- Automatic threat detection
- Pattern recognition

### 6. Data Export
- Export users to CSV
- Export sessions to CSV
- Export risk events to CSV
- Export framework usage to CSV

### 7. Analytics & Charts
- User statistics visualization
- Risk distribution charts
- PDF report generation
- CSV report generation

## 🎯 API Endpoints

### Authentication
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/adaptive-login` - Adaptive login with risk assessment
- `POST /api/v1/auth/refresh` - Token refresh
- `POST /api/v1/auth/logout` - User logout

### 2FA Management
- `POST /api/v1/auth/setup-2fa` - Setup two-factor authentication
- `POST /api/v1/auth/verify-2fa` - Verify TOTP code
- `POST /api/v1/auth/disable-2fa` - Disable 2FA

### User Management
- `GET /api/v1/user/profile` - Get user profile
- `PUT /api/v1/user/profile` - Update user profile
- `PUT /api/v1/user/change-password` - Change password
- `GET /api/v1/user/sessions` - Get active sessions

### Admin Endpoints
- `GET /api/v1/admin/users` - List users
- `GET /api/v1/admin/statistics` - System statistics
- `GET /api/v1/admin/risk-events` - Risk events
- `GET /api/v1/admin/anomalies` - Anomaly patterns
- `GET /api/v1/admin/framework-statistics` - Framework usage statistics

## 📈 Risk Assessment Factors

The framework evaluates multiple risk factors:

- **Device Recognition** (30%) - Known devices vs new devices
- **Location Analysis** (25%) - Geographic location patterns
- **Time Patterns** (15%) - Login time consistency
- **Velocity Checks** (15%) - Frequency of attempts
- **Behavioral Biometrics** (15%) - Typing patterns, mouse movements

## 🧪 Testing

Run the test suite:
```bash
python -m pytest test_framework.py
```

## 🚢 Deployment

### Docker Deployment
```bash
# Build and run with Docker
docker-compose up --build

# Or build standalone image
docker build -t adaptiveauth .
docker run -p 8080:8080 adaptiveauth
```

### Production Deployment
```bash
# Use the deployment script
./scripts/deploy.sh  # Linux/macOS
# or
scripts\deploy.bat   # Windows
```

## 🔒 Security Best Practices

- Always use HTTPS in production
- Rotate JWT secrets regularly
- Monitor authentication logs
- Implement rate limiting
- Use strong passwords
- Enable 2FA for admin accounts
- Regular security audits
- Keep dependencies updated
- Validate all inputs
- Sanitize all outputs

## 🤝 Contributing

We welcome contributions! Please read our [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

### Development Setup
```bash
# Fork the repository
git clone https://github.com/yourusername/adaptiveauth.git
cd adaptiveauth

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Built-in at `/docs`
- **Issues**: Report bugs on GitHub
- **Discussions**: Join our community forum
- **Contact**: [your-email@example.com]

## 📈 Changelog

### v1.0.0 - Initial Release
- Risk-based adaptive authentication (0-4 levels)
- Multi-factor authentication (2FA, email, SMS)
- Behavioral biometrics (typing patterns, mouse tracking)
- Admin dashboard with analytics
- Framework usage tracking
- Anomaly detection
- PDF/CSV reporting capabilities
- Real-time session monitoring

## 🙏 Acknowledgments

- FastAPI team for the excellent framework
- SQLAlchemy for robust ORM capabilities
- Chart.js for beautiful visualizations
- Open-source community for inspiration

---

<div align="center">

**SAGAR AdaptiveAuth Framework** - Making authentication smarter and more secure, one adaptive login at a time.

[⭐ Star this repository if you found it helpful!](https://github.com/yourusername/adaptiveauth)
[🐛 Report an issue](https://github.com/yourusername/adaptiveauth/issues)
[💡 Request a feature](https://github.com/yourusername/adaptiveauth/issues)

</div>