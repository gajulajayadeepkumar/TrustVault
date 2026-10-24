@echo off
title TrustVault Secure Document Management Platform
echo =========================================================================
echo  TRUSTVAULT SECURE DOCUMENT MANAGEMENT PLATFORM
echo  Zero-Trust Architecture * Deny-by-Default * SHA-256 Tamper-Evident Ledger
echo =========================================================================
echo.

echo [1/3] Checking environment & dependencies...
python -m pip install -r requirements.txt --quiet

echo [2/3] Seeding demo accounts and confidential sample documents...
python seed_data.py

echo [3/3] Starting TrustVault Server on http://127.0.0.1:8000 ...
echo.
echo =========================================================================
echo  Open your browser at:
echo  Application Dashboard : http://127.0.0.1:8000
echo  Interactive API Docs  : http://127.0.0.1:8000/docs
echo =========================================================================
echo.
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
pause
