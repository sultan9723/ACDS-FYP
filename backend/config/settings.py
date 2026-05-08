"""
ACDS Backend Configuration Settings
====================================
Central configuration for all backend services.
"""

import os
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# =============================================================================
# DATABASE SETTINGS
# =============================================================================
# For Docker: mongodb://acds:acds123@localhost:27017/acds?authSource=admin
# For local without auth: mongodb://localhost:27017
MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://acds:acds123@localhost:27017/acds?authSource=admin")
DB_NAME: str = os.getenv("DB_NAME", "acds")

# Collection names
ALERT_COLLECTION: str = "alerts"
THREAT_COLLECTION: str = "threats"
FEEDBACK_COLLECTION: str = "feedback"
REPORT_COLLECTION: str = "reports"
USER_COLLECTION: str = "users"
EMAIL_SCAN_COLLECTION: str = "email_scans"
AUDIT_LOG_COLLECTION: str = "audit_logs"

# =============================================================================
# JWT / AUTHENTICATION SETTINGS
# =============================================================================
JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "acds-secret-key-change-in-production-2024")
JWT_ALGORITHM: str = "HS256"
JWT_EXPIRATION_HOURS: int = 24

# Default admin credentials (for development only)
DEFAULT_ADMIN_EMAIL: str = "admin@acds.com"
DEFAULT_ADMIN_PASSWORD: str = "admin123"

# =============================================================================
# ML MODEL SETTINGS (v2.0.0 - TF-IDF + Logistic Regression)
# =============================================================================
MODEL_PATH: str = os.getenv("MODEL_PATH", "ml/models/phishing_model.pkl")
MODEL_INFO_PATH: str = os.getenv("MODEL_INFO_PATH", "ml/models/model_info.json")
PHISHING_CONFIDENCE_THRESHOLD: float = 0.35  # Lower threshold for better demo detection

# Incident Database (JSON-based)
INCIDENTS_DB_PATH: str = os.getenv("INCIDENTS_DB_PATH", "data/incidents.json")

# =============================================================================
# API SETTINGS
# =============================================================================
API_VERSION: str = "v1"
API_PREFIX: str = f"/api/{API_VERSION}"
CORS_ORIGINS: list = [
    "http://localhost:5173",  # Vite dev server
    "http://localhost:5174",  # Vite dev server alternate port
    "http://localhost:3000",  # Alternative React dev
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "http://127.0.0.1:3000",
]

# Rate limiting
RATE_LIMIT_REQUESTS: int = 100  # requests per minute
RATE_LIMIT_WINDOW: int = 60  # seconds

# =============================================================================
# THREAT DETECTION SETTINGS (Updated v2.0.0)
# =============================================================================
# Severity based on risk_score: LOW (0-39), MEDIUM (40-69), HIGH (70-100)
THREAT_SEVERITY_LEVELS = {
    "HIGH": {"min_risk_score": 70, "priority": 1, "auto_response": True},
    "MEDIUM": {"min_risk_score": 40, "priority": 2, "auto_response": True},
    "LOW": {"min_risk_score": 0, "priority": 3, "auto_response": False},
}

THREAT_TYPES = [
    "phishing",
    "malware",
    "ransomware",
    "spear_phishing",
    "business_email_compromise",
    "credential_harvesting",
    "suspicious_link",
    "suspicious_attachment",
]

# =============================================================================
# AUTOMATED RESPONSE SETTINGS
# =============================================================================
AUTO_QUARANTINE_ENABLED: bool = True
AUTO_BLOCK_SENDER_ENABLED: bool = True
AUTO_NOTIFY_ADMIN_ENABLED: bool = True

QUARANTINE_FOLDER: str = os.getenv("QUARANTINE_FOLDER", "data/quarantine")
BLOCKED_SENDERS_FILE: str = os.getenv("BLOCKED_SENDERS_FILE", "data/blocked_senders.json")

# =============================================================================
# LOGGING SETTINGS
# =============================================================================
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_FILE: str = os.getenv("LOG_FILE", "logs/acds.log")

# =============================================================================
# EMAIL SCANNING SETTINGS
# =============================================================================
MAX_EMAIL_SIZE_MB: int = 25  # Maximum email size to process
SCAN_ATTACHMENTS: bool = True
EXTRACT_URLS: bool = True

# Suspicious patterns to flag
SUSPICIOUS_URL_PATTERNS = [
    r"bit\.ly",
    r"tinyurl\.com",
    r"goo\.gl",
    r"t\.co",
    r"paypa[l1]",
    r"amaz[o0]n",
    r"micr[o0]s[o0]ft",
    r"app[l1]e",
    r"g[o0][o0]g[l1]e",
]

SUSPICIOUS_ATTACHMENT_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".jar", ".msi", ".dll", ".hta",
]

# =============================================================================
# REPORT GENERATION SETTINGS
# =============================================================================
REPORT_TYPES = [
    "threat_summary",
    "detection_analysis",
    "incident_log",
    "performance_metrics",
    "executive_summary",
    "compliance_report",
]

# =============================================================================
# FEEDBACK LOOP SETTINGS
# =============================================================================
FEEDBACK_TYPES = [
    "false_positive",
    "false_negative",
    "correct_detection",
    "severity_adjustment",
    "general_feedback",
]

MIN_FEEDBACK_FOR_RETRAIN: int = 100  # Minimum feedback entries before triggering retrain
RETRAIN_SCHEDULE: str = "weekly"  # daily, weekly, monthly

# =============================================================================
# INTEL AGENT SETTINGS
# =============================================================================
THREAT_INTEL_FEEDS = [
    {"name": "PhishTank", "url": "https://data.phishtank.com/data/online-valid.json", "enabled": True},
    {"name": "URLhaus", "url": "https://urlhaus.abuse.ch/downloads/json/", "enabled": True},
]

INTEL_UPDATE_INTERVAL_HOURS: int = 6

# =============================================================================
# NOTIFICATION SETTINGS
# =============================================================================
SMTP_SERVER: str = os.getenv("SMTP_SERVER", "")
SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER: str = os.getenv("SMTP_USER", "")
SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL", "admin@acds.com")

# Webhook for alerts (Slack, Teams, etc.)
WEBHOOK_URL: Optional[str] = os.getenv("WEBHOOK_URL", None)


# =============================================================================
# SETTINGS CLASS FOR EASY ACCESS
# =============================================================================
class Settings:
    """Settings class for easy attribute access."""
    
    # Database
    MONGO_URI = MONGO_URI
    DB_NAME = DB_NAME
    
    # Collections
    COLLECTION_USERS = USER_COLLECTION
    COLLECTION_THREATS = THREAT_COLLECTION
    COLLECTION_EMAIL_SCANS = EMAIL_SCAN_COLLECTION
    COLLECTION_FEEDBACK = FEEDBACK_COLLECTION
    COLLECTION_ALERTS = ALERT_COLLECTION
    COLLECTION_AUDIT_LOGS = AUDIT_LOG_COLLECTION
    COLLECTION_REPORTS = REPORT_COLLECTION
    
    # JWT
    JWT_SECRET_KEY = JWT_SECRET_KEY
    JWT_ALGORITHM = JWT_ALGORITHM
    JWT_EXPIRATION_HOURS = JWT_EXPIRATION_HOURS
    
    # Admin
    DEFAULT_ADMIN_EMAIL = DEFAULT_ADMIN_EMAIL
    DEFAULT_ADMIN_PASSWORD = DEFAULT_ADMIN_PASSWORD


# Singleton instance
settings = Settings()
