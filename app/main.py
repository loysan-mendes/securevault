"""
app/main.py - FastAPI Application Entry Point

Wires together:
  - Database initialization
  - Route registration
  - Rate limiting middleware
  - Secure HTTP headers middleware
  - Exception handlers
"""
import logging
import sys
import os

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.template_filters import filesizeformat, file_icon

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings
from app.database import init_db
from app.routes import router

# ─────────────────────────────────────────────────────────────
# Logging Setup
# ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("securevault.log", encoding="utf-8"),
    ]
)
logger = logging.getLogger("securevault")


# ─────────────────────────────────────────────────────────────
# Rate Limiter
# ─────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])


# ─────────────────────────────────────────────────────────────
# Secure Headers Middleware
# ─────────────────────────────────────────────────────────────
class SecureHeadersMiddleware(BaseHTTPMiddleware):
    """
    Injects security headers into every response.
    
    - Content-Security-Policy: Restricts script/style sources to self and inline
      (inline needed for Jinja2 templates without a full CSP nonce system).
    - X-Frame-Options: DENY — prevents clickjacking.
    - X-Content-Type-Options: nosniff — prevents MIME sniffing.
    - Referrer-Policy: no-referrer — don't leak URL to external sites.
    - Permissions-Policy: Disable sensors/camera/mic.
    """
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        # HSTS: tell browsers to always use HTTPS (only meaningful over HTTPS)
        if not settings.DEBUG:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        return response


# ─────────────────────────────────────────────────────────────
# Application Factory
# ─────────────────────────────────────────────────────────────
def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        docs_url=None,    # Disable Swagger UI in non-debug mode
        redoc_url=None,
        openapi_url="/openapi.json" if settings.DEBUG else None,
    )

    # Rate limiting
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    # Secure headers
    app.add_middleware(SecureHeadersMiddleware)

    # Static files
    app.mount("/static", StaticFiles(directory="static"), name="static")

    # Routes
    app.include_router(router)

    # Register Jinja2 template filters
    from fastapi.templating import Jinja2Templates
    _templates = Jinja2Templates(directory="templates")
    _templates.env.filters["filesizeformat"] = filesizeformat
    _templates.env.filters["file_icon"] = file_icon
    # Patch all Jinja2Templates instances that use the same env
    from app import routes as _routes
    _routes.templates.env.filters["filesizeformat"] = filesizeformat
    _routes.templates.env.filters["file_icon"] = file_icon

    # Apply rate limits to specific sensitive routes
    @app.on_event("startup")
    async def startup():
        logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
        init_db()
        # Create vault directory
        os.makedirs(settings.VAULT_DIR, exist_ok=True)
        logger.info(f"Vault directory: {os.path.abspath(settings.VAULT_DIR)}")

    @app.exception_handler(404)
    async def not_found(request: Request, exc):
        templates = Jinja2Templates(directory="templates")
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": "Page not found.", "code": 404},
            status_code=404
        )

    @app.exception_handler(500)
    async def server_error(request: Request, exc):
        logger.error(f"Internal server error: {exc}")
        templates = Jinja2Templates(directory="templates")
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": "Internal server error.", "code": 500},
            status_code=500
        )

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=settings.DEBUG,
        log_level="debug" if settings.DEBUG else "info",
    )
