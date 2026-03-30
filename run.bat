@echo off
title RansomGuard - Early Warning System
color 0A

echo.
echo  ==========================================
echo   RansomGuard Early Warning System v2.4.1
echo  ==========================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Python not found!
    echo  Please install Python 3.9+ from https://python.org
    pause
    exit /b 1
)

echo  [1/3] Python found
echo  [2/3] Installing dependencies...
pip install -r backend\requirements.txt --quiet

echo  [3/3] Starting server...
echo.
echo  Dashboard : http://localhost:8000
echo  API Docs  : http://localhost:8000/docs
echo  Press Ctrl+C to stop
echo.

cd backend
python main.py
pause
