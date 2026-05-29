"""
EXAMPLE CONFIGURATION FILE
Copy this to config.py and add your own secrets.
config.py is ignored by git for security.
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    # REQUIRED: Set this in environment variables or .env file
    SECRET_KEY = os.environ.get('SECRET_KEY', 'CHANGE_THIS_IN_PRODUCTION')
    
    # Database - SQLite for development, PostgreSQL for production
    DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///compliance.db')
    
    # Session configuration
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    
    # Password policy
    PASSWORD_MIN_LENGTH = int(os.environ.get('PASSWORD_MIN_LENGTH', 12))
    PASSWORD_REQUIRE_UPPER = os.environ.get('PASSWORD_REQUIRE_UPPER', 'True').lower() == 'true'
    PASSWORD_REQUIRE_LOWER = os.environ.get('PASSWORD_REQUIRE_LOWER', 'True').lower() == 'true'
    PASSWORD_REQUIRE_DIGITS = os.environ.get('PASSWORD_REQUIRE_DIGITS', 'True').lower() == 'true'
    PASSWORD_REQUIRE_SPECIAL = os.environ.get('PASSWORD_REQUIRE_SPECIAL', 'True').lower() == 'true'
    PASSWORD_HISTORY_COUNT = int(os.environ.get('PASSWORD_HISTORY_COUNT', 5))
    
    # Account lockout
    MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))
    LOCKOUT_DURATION = timedelta(minutes=int(os.environ.get('LOCKOUT_DURATION_MINUTES', 30)))
    
    # File upload
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    UPLOAD_EXTENSIONS = ['.pdf', '.doc', '.docx', '.txt', '.png', '.jpg', '.jpeg']
    
    # Environment
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'