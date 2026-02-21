@echo off
REM SAGAR AdaptiveAuth Framework - Windows Deployment Script

echo ================================================
echo  SAGAR AdaptiveAuth Framework - Windows Deploy
echo ================================================

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Administrator privileges confirmed.
) else (
    echo Error: This script requires administrator privileges.
    echo Right-click on this file and select "Run as administrator".
    pause
    exit /b 1
)

REM Check prerequisites
echo Checking prerequisites...

python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: Python is not installed or not in PATH
    pause
    exit /b 1
)

pip --version >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: Pip is not installed or not in PATH
    pause
    exit /b 1
)

echo Prerequisites check passed!

REM Create virtual environment
echo Creating virtual environment...
python -m venv venv

REM Activate virtual environment and install dependencies
echo Activating virtual environment and installing dependencies...
call venv\Scripts\activate.bat
pip install --upgrade pip
pip install -r requirements-production.txt

REM Check if .env file exists
if not exist ".env" (
    echo .env file not found. Copying from .env.example...
    copy .env.example .env
    echo Please configure your .env file before proceeding!
    echo Deployment paused for configuration.
    pause
    exit /b 0
)

REM Create logs directory
if not exist "logs" (
    mkdir logs
)

REM Start the application
echo Starting SAGAR AdaptiveAuth Framework...
start /min cmd /c "uvicorn main:app --host 0.0.0.0 --port 8080 --workers 1"

echo ================================================
echo  Deployment Complete!
echo ================================================
echo The application should be running at:
echo   - Health Check: http://localhost:8080/health
echo   - API Docs: http://localhost:8080/docs
echo   - Admin Interface: http://localhost:8080/static/index.html
echo.
echo Default Admin Credentials:
echo   - Email: admin@adaptiveauth.com
echo   - Password: Admin@123
echo ================================================

pause