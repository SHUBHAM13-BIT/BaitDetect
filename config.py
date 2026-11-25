import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")

class Config:
    # Production Security: Disable debug mode by default unless explicitly enabled in dev
    is_cloud_prod = bool(os.getenv("RENDER") or os.getenv("RAILWAY_ENVIRONMENT") or os.getenv("FLY_APP_NAME"))
    default_debug = "False" if is_cloud_prod else "True"
    
    SECRET_KEY = os.getenv("SECRET_KEY", "prod-cybersecurity-secret-key-baitdetect-2026")
    DEBUG = os.getenv("DEBUG", default_debug).lower() in ("true", "1", "yes")
    PORT = int(os.getenv("PORT", 5000))
    HOST = os.getenv("HOST", "0.0.0.0")

    # Threat Intelligence API Keys
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

    # Uploads & Storage
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH_MB", 16)) * 1024 * 1024  # default 16MB
    ALLOWED_EXTENSIONS = {".eml", ".txt"}
    UPLOAD_FOLDER = BASE_DIR / os.getenv("UPLOAD_FOLDER", "uploads")
    REPORTS_FOLDER = BASE_DIR / os.getenv("REPORTS_FOLDER", "generated_reports")
    DATABASE_PATH = BASE_DIR / os.getenv("DATABASE_PATH", "database/phishing_analysis.db")

    # Risk Scoring Thresholds
    RISK_LEVELS = {
        "SAFE": (0, 20),
        "MODERATE": (21, 40),
        "SUSPICIOUS": (41, 60),
        "HIGH": (61, 80),
        "CRITICAL": (81, 100),
    }

# Ensure directories exist
Config.UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
Config.REPORTS_FOLDER.mkdir(parents=True, exist_ok=True)
Config.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
