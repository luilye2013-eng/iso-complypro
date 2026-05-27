import sys
import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, date
import json
import csv
import io
import secrets
import string
from functools import wraps

# ========== FIX FOR VERCEL READ-ONLY FILESYSTEM ==========
# This MUST come before creating the Flask app
os.environ['FLASK_SQLALCHEMY_DISABLE_INSTANCE_FOLDER'] = '1'

# Create Flask app with custom instance path
app = Flask(__name__)

# Override instance path to /tmp (writable directory on Vercel)
app.instance_path = '/tmp/instance'
app.config['INSTANCE_FOLDER_PATH'] = '/tmp/instance'

# Ensure the directory exists
os.makedirs(app.instance_path, exist_ok=True)
# ==========================================================

# ========== CONFIGURATION ==========
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
    
    # Use /tmp for SQLite on Vercel - writable directory
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:////tmp/compliance.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    
    PASSWORD_MIN_LENGTH = int(os.environ.get('PASSWORD_MIN_LENGTH', 12))
    PASSWORD_REQUIRE_UPPER = os.environ.get('PASSWORD_REQUIRE_UPPER', 'True').lower() == 'true'
    PASSWORD_REQUIRE_LOWER = os.environ.get('PASSWORD_REQUIRE_LOWER', 'True').lower() == 'true'
    PASSWORD_REQUIRE_DIGITS = os.environ.get('PASSWORD_REQUIRE_DIGITS', 'True').lower() == 'true'
    PASSWORD_REQUIRE_SPECIAL = os.environ.get('PASSWORD_REQUIRE_SPECIAL', 'True').lower() == 'true'
    PASSWORD_HISTORY_COUNT = int(os.environ.get('PASSWORD_HISTORY_COUNT', 5))
    
    MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))
    LOCKOUT_DURATION = timedelta(minutes=int(os.environ.get('LOCKOUT_DURATION_MINUTES', 30)))
    
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    UPLOAD_EXTENSIONS = ['.pdf', '.doc', '.docx', '.txt', '.png', '.jpg', '.jpeg']
    
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

app.config.from_object(Config)

# ========== IMPORT MODULES (after config) ==========
from models import db, User, Control, Evidence, AuditLog, ComplianceReport, UserStatus, PasswordHistory, Industry, ControlIndustry
from auth import login_required, admin_required, audit_log, PasswordValidator

# Initialize database
db.init_app(app)

# Ensure upload directory exists in /tmp
UPLOAD_FOLDER = '/tmp/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ========== REMAINDER OF YOUR APP.PY CODE ==========
# (Keep all your existing routes here - @app.route functions)
# ... your existing code ...

# ========== INITIALIZE DATABASE ==========
with app.app_context():
    db.create_all()
    # Load controls if needed
    if Control.query.count() == 0:
        from app import load_initial_controls
        load_initial_controls()

if __name__ == '__main__':
    app.run(debug=Config.DEBUG, host='0.0.0.0', port=5000)