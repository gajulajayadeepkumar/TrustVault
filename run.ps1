# TrustVault PowerShell Launcher
Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host " TRUSTVAULT SECURE DOCUMENT MANAGEMENT PLATFORM" -ForegroundColor White
Write-Host " Zero-Trust Architecture * Deny-by-Default * SHA-256 Tamper-Evident Ledger" -ForegroundColor Gray
Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/3] Checking environment & dependencies..." -ForegroundColor Yellow
python -m pip install -r requirements.txt --quiet

Write-Host "[2/3] Seeding demo accounts and confidential sample documents..." -ForegroundColor Yellow
python seed_data.py

Write-Host "[3/3] Starting TrustVault Server on http://127.0.0.1:8000 ..." -ForegroundColor Green
Write-Host ""
Write-Host " Application Dashboard : http://127.0.0.1:8000" -ForegroundColor Cyan
Write-Host " Interactive API Docs  : http://127.0.0.1:8000/docs" -ForegroundColor Cyan
Write-Host ""

python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
