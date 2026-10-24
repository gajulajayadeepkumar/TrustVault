from pathlib import Path
from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.database import init_db
from app.routes import (
    auth_routes,
    document_routes,
    permission_routes,
    admin_routes,
    audit_routes
)

# Initialize Database Schema on start
init_db()

app = FastAPI(
    title="TrustVault Secure Document Management Platform",
    description="Zero-Trust enterprise document vault with granular permissions and tamper-evident SHA-256 audit chaining.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Custom Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        # Defense in Depth: Security Headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Include API Routers
app.include_router(auth_routes.router)
app.include_router(document_routes.router)
app.include_router(permission_routes.router)
app.include_router(admin_routes.router)
app.include_router(audit_routes.router)

# Mount Static Assets & Frontend
BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/", include_in_schema=False)
async def serve_root(request: Request):
    if "tv_session" not in request.cookies:
        return RedirectResponse(url="/auth/login", status_code=302)
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return RedirectResponse(url="/auth/login", status_code=302)

@app.get("/dashboard", include_in_schema=False)
async def serve_dashboard():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return RedirectResponse(url="/auth/login", status_code=302)

@app.get("/login", include_in_schema=False)
@app.get("/auth/login", include_in_schema=False)
async def serve_login():
    login_file = STATIC_DIR / "login.html"
    if login_file.exists():
        return FileResponse(login_file)
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/register", include_in_schema=False)
@app.get("/auth/register", include_in_schema=False)
async def serve_register():
    return RedirectResponse(url="/auth/login?tab=register", status_code=302)

@app.get("/health", tags=["System"])
def health_check():
    return {"status": "HEALTHY", "platform": "TrustVault", "security_mode": "ZERO_TRUST"}
