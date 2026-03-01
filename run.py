"""
run.py - Development server launcher

Usage:
    cd securevault_web
    python run.py
"""
import os
import sys

# Ensure we run from the project root
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uvicorn
from config import settings

if __name__ == "__main__":
    print(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    print(f"Vault directory: {os.path.abspath(settings.VAULT_DIR)}")
    print(f"Debug mode: {settings.DEBUG}")
    print(f"Open: http://127.0.0.1:8000")
    print("=" * 50)

    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=settings.DEBUG,
        log_level="debug" if settings.DEBUG else "info",
    )
