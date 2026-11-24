@echo off
setlocal enabledelayedexpansion

echo ===================================================
echo   BaitDetect - Phishing Analysis System Launcher
echo ===================================================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in your PATH.
    echo Please install Python 3.12+ from https://python.org
    pause
    exit /b 1
)

if not exist "venv" (
    echo [*] Creating virtual environment (venv)...
    python -m venv venv
)

echo [*] Activating virtual environment...
call .\venv\Scripts\activate

echo [*] Checking dependencies...
pip install -r requirements.txt --quiet

echo [*] Launching BaitDetect on http://127.0.0.1:5000 ...
start http://127.0.0.1:5000

python app.py
pause
