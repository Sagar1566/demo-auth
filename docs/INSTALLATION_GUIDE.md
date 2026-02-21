# SAGAR AdaptiveAuth Framework - Installation Guide

## Table of Contents
1. [System Requirements](#system-requirements)
2. [Quick Installation](#quick-installation)
3. [Manual Installation](#manual-installation)
4. [Configuration](#configuration)
5. [Initial Setup](#initial-setup)
6. [Testing Installation](#testing-installation)
7. [Troubleshooting](#troubleshooting)
8. [Next Steps](#next-steps)

## System Requirements

### Minimum Requirements
- **Operating System**: Windows 7+/macOS 10.12+/Linux (Ubuntu 18.04+, CentOS 7+)
- **Python**: 3.8 or higher
- **RAM**: 1 GB minimum (2 GB recommended)
- **Storage**: 500 MB free space
- **Network**: Internet access for initial setup

### Recommended Requirements
- **CPU**: Multi-core processor
- **RAM**: 2 GB or more
- **Storage**: SSD preferred
- **Network**: Stable broadband connection

### Platform-Specific Requirements

#### Windows
- Windows PowerShell or Command Prompt
- Python 3.8+ from Microsoft Store or python.org
- Administrative privileges for some operations

#### macOS
- Homebrew (recommended for package management)
- Xcode command line tools

#### Linux
- Package manager (apt, yum, pacman, etc.)
- Build tools for compiling dependencies

## Quick Installation

### Option 1: Using Git (Recommended)
```bash
# Clone the repository
git clone https://github.com/yourusername/adaptiveauth.git
cd adaptiveauth

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Start the server
python main.py
```

### Option 2: Download ZIP
1. Download the latest release from GitHub
2. Extract the ZIP file to your desired location
3. Navigate to the extracted directory
4. Follow steps 2-5 from Option 1

### Option 3: Using Docker (Production)
```bash
# Clone the repository
git clone https://github.com/yourusername/adaptiveauth.git
cd adaptiveauth

# Build and run with Docker Compose
docker-compose up --build
```

## Manual Installation

### Step 1: Install Python
1. **Download Python** from [python.org](https://www.python.org/downloads/)
2. **Install Python** with "Add Python to PATH" checked
3. **Verify Installation**:
```bash
python --version
pip --version
```

### Step 2: Download the Framework
Choose one method:

#### Method A: Git Clone
```bash
git clone https://github.com/yourusername/adaptiveauth.git
cd adaptiveauth
```

#### Method B: Direct Download
1. Go to the repository URL
2. Click "Code" → "Download ZIP"
3. Extract to your desired directory
4. Open terminal/command prompt in the extracted directory

### Step 3: Create Virtual Environment
```bash
# Create virtual environment
python -m venv adaptiveauth-env

# Activate virtual environment
# On Windows:
adaptiveauth-env\Scripts\activate
# On macOS/Linux:
source adaptiveauth-env/bin/activate

# Upgrade pip
pip install --upgrade pip
```

### Step 4: Install Dependencies
```bash
pip install -r requirements.txt
```

If requirements.txt is not available, install manually:
```bash
pip install fastapi uvicorn sqlalchemy pydantic pydantic-settings python-jose[cryptography] passlib[bcrypt] bcrypt python-multipart pyotp qrcode[pil] fastapi-mail httpx python-dateutil user-agents geoip2 aiofiles twilio
```

### Step 5: Configure Environment
1. Copy the example configuration:
```bash
cp .env.example .env
```

2. Edit the `.env` file with your preferred text editor:
```bash
# Open with default editor
# On Windows:
notepad .env
# On macOS/Linux:
nano .env
```

3. Update the configuration values:
```env
# Change the SECRET_KEY to a strong, random value
SECRET_KEY=your-very-secure-random-key-change-this-immediately

# Configure database (SQLite is default, fine for testing)
DATABASE_URL=sqlite:///./adaptiveauth.db

# Configure email service (optional but recommended)
EMAIL_SERVICE=gmail
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password

# Configure SMS service (optional)
TWILIO_ACCOUNT_SID=your-account-sid
TWILIO_AUTH_TOKEN=your-auth-token
TWILIO_PHONE_NUMBER=+1234567890
```

### Step 6: Initialize Database
```bash
# The application will automatically initialize the database on first run
# You can also manually initialize if needed
python -c "
from adaptiveauth.core.database import init_database
init_database()
print('Database initialized successfully!')
"
```

### Step 7: Start the Application
```bash
python main.py
```

## Configuration

### Environment Variables

#### Database Configuration
```env
# SQLite (default, good for development)
DATABASE_URL=sqlite:///./adaptiveauth.db

# PostgreSQL (recommended for production)
DATABASE_URL=postgresql://username:password@localhost/dbname

# MySQL (alternative)
DATABASE_URL=mysql+pymysql://username:password@localhost/dbname
```

#### Security Configuration
```env
# JWT Secret (CHANGE THIS FOR PRODUCTION)
SECRET_KEY=your-super-secret-key-change-in-production

# Token expiration
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
```

#### Email Configuration
```env
# Email service provider
EMAIL_SERVICE=gmail  # Options: gmail, sendgrid, mailgun

# Gmail configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password  # Use app password, not regular password
EMAIL_FROM=your-email@gmail.com
```

#### SMS Configuration (Twilio)
```env
TWILIO_ACCOUNT_SID=your-twilio-account-sid
TWILIO_AUTH_TOKEN=your-twilio-auth-token
TWILIO_PHONE_NUMBER=+1234567890
```

#### Risk Assessment Weights (Must sum to 100)
```env
ADAPTIVEAUTH_RISK_DEVICE_WEIGHT=30.0
ADAPTIVEAUTH_RISK_LOCATION_WEIGHT=25.0
ADAPTIVEAUTH_RISK_TIME_WEIGHT=15.0
ADAPTIVEAUTH_RISK_VELOCITY_WEIGHT=15.0
ADAPTIVEAUTH_RISK_BEHAVIOR_WEIGHT=15.0
```

### Feature Flags
```env
# Enable/disable features
ENABLE_2FA=true
ENABLE_RISK_ASSESSMENT=true
ENABLE_SESSION_MONITORING=true
ENABLE_BEHAVIORAL_BIOMETRICS=true
ENABLE_EMAIL_VERIFICATION=true
ENABLE_SMS_VERIFICATION=true
```

## Initial Setup

### First Run
1. **Start the application**:
```bash
python main.py
```

2. **Verify the server is running** by opening:
   - API Documentation: [http://localhost:8080/docs](http://localhost:8080/docs)
   - Health Check: [http://localhost:8080/health](http://localhost:8080/health)
   - Admin Interface: [http://localhost:8080/static/index.html](http://localhost:8080/static/index.html)

3. **Check the console output** for any warnings or errors

### Admin User Creation
The framework automatically creates an admin user on first run:
- **Email**: `admin@adaptiveauth.com`
- **Password**: `Admin@123`

**Important**: Change these credentials immediately after first login.

### Database Initialization
On first run, the application will:
1. Create the database file (if using SQLite)
2. Create all necessary tables
3. Insert the default admin user
4. Set up initial configurations

## Testing Installation

### Health Check
Verify the basic functionality:
```bash
curl http://localhost:8080/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "AdaptiveAuth"
}
```

### API Documentation
Visit [http://localhost:8080/docs](http://localhost:8080/docs) to access the interactive API documentation.

### Admin Interface Test
1. Open [http://localhost:8080/static/index.html](http://localhost:8080/static/index.html)
2. Navigate to "9. Admin" tab
3. Login with admin credentials:
   - Email: `admin@adaptiveauth.com`
   - Password: `Admin@123`
4. Verify admin dashboard loads correctly

### Authentication Test
Try registering a new user:
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "TestPass123!", "full_name": "Test User"}'
```

## Troubleshooting

### Common Issues

#### Issue: "ModuleNotFoundError" or "ImportError"
**Solution**: 
```bash
# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate
# Install dependencies
pip install -r requirements.txt
```

#### Issue: "Port already in use" 
**Solution**: Change the port in `main.py` or terminate the conflicting process:
```bash
# On Windows:
netstat -ano | findstr :8080
taskkill /PID <PID> /F

# On macOS/Linux:
lsof -i :8080
kill -9 <PID>
```

#### Issue: "Permission denied" on Windows
**Solution**: Run Command Prompt or PowerShell as Administrator

#### Issue: "SSL certificate verify failed"
**Solution**: 
```bash
pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r requirements.txt
```

#### Issue: "Database locked" error
**Solution**: This typically occurs with SQLite in multi-user scenarios. Consider switching to PostgreSQL for production use.

### Debug Mode
To run in debug mode with more verbose output:
```bash
# Modify main.py to set debug=True, or set environment variable
export DEBUG=true  # On Windows: set DEBUG=true
python main.py
```

### Log Files
Check log files for detailed error information:
- Default location: `logs/app.log` (if logging is configured)
- Console output during startup contains important information

### Database Connection Issues
If experiencing database issues:
```bash
# Test database connection
python -c "
from sqlalchemy import create_engine
engine = create_engine('sqlite:///./adaptiveauth.db')
connection = engine.connect()
print('Database connection successful!')
connection.close()
"
```

## Next Steps

### Post-Installation Tasks
1. **Change default admin credentials** immediately
2. **Update the SECRET_KEY** in your environment file
3. **Configure email/SMS services** for production use
4. **Set up SSL/TLS** for HTTPS in production
5. **Configure backup procedures** for your database
6. **Review security settings** and audit logs

### Production Deployment
For production deployment:
1. Use PostgreSQL instead of SQLite
2. Set up a reverse proxy (nginx/Apache)
3. Configure SSL certificates
4. Set up monitoring and alerting
5. Implement proper backup procedures
6. Configure firewall rules

### Customization
The framework can be customized by:
1. Modifying the risk assessment algorithms
2. Adding custom authentication methods
3. Extending the admin dashboard
4. Integrating with existing user databases
5. Adding custom business logic

### Support Resources
- **Documentation**: Available at `/docs` endpoint
- **GitHub Repository**: For issues and feature requests
- **Community**: Join our support channels

---

**Congratulations!** You have successfully installed the SAGAR AdaptiveAuth Framework. The system is now ready for use or further customization.