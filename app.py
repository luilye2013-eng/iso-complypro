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
os.environ['FLASK_SQLALCHEMY_DISABLE_INSTANCE_FOLDER'] = '1'

app = Flask(__name__)

# Override instance path to /tmp (writable directory on Vercel)
app.instance_path = '/tmp/instance'
app.config['INSTANCE_FOLDER_PATH'] = '/tmp/instance'
os.makedirs(app.instance_path, exist_ok=True)

# Upload folder in /tmp
UPLOAD_FOLDER = '/tmp/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# ==========================================================

# ========== CONFIGURATION ==========
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
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

# ========== IMPORT MODULES ==========
from models import db, User, Control, Evidence, AuditLog, ComplianceReport, UserStatus, PasswordHistory, Industry, ControlIndustry
from auth import login_required, admin_required, audit_log, PasswordValidator

# Initialize database
db.init_app(app)

# ========== INITIALIZATION FUNCTIONS ==========
def load_initial_controls():
    """Load controls directly from Python list - runs only once"""
    if Control.query.count() > 0:
        print(f"Controls already exist: {Control.query.count()} controls")
        return
    
    controls_data = [
        {"id": "ISO-27001-A.5.1", "name": "Information security policy", "description": "Policies for information security should be defined.", "category": "Information Security Policies"},
        {"id": "ISO-27001-A.6.1", "name": "Information security roles", "description": "Information security responsibilities should be defined.", "category": "Organization"},
        {"id": "ISO-27001-A.7.1", "name": "Screening", "description": "Background verification checks should be carried out.", "category": "Human Resources"},
        {"id": "ISO-27001-A.8.1", "name": "Inventory of assets", "description": "Assets should be identified and documented.", "category": "Asset Management"},
        {"id": "ISO-27001-A.9.1", "name": "Access control policy", "description": "An access control policy should be established.", "category": "Access Control"},
    ]
    
    for data in controls_data:
        control = Control(
            control_id=data["id"],
            name=data["name"],
            description=data["description"],
            category=data["category"],
            framework="ISO 27001",
            is_applicable=True,
            is_active_in_library=True
        )
        db.session.add(control)
    
    db.session.commit()
    print(f"✅ Loaded {len(controls_data)} controls")

def create_admin_user():
    """Create default admin user if none exists"""
    if User.query.count() == 0:
        temp_password = "AdminTemp2024!First"
        admin = User(
            username='admin',
            email='admin@isocomplypro.local',
            password_hash=PasswordValidator.hash_password(temp_password),
            role='admin',
            force_password_change=True,
            status='active',
            is_active=True
        )
        db.session.add(admin)
        db.session.commit()
        print(f"Admin created - Username: admin, Temp Password: {temp_password}")

# ========== ROUTES ==========
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    all_controls = Control.query.filter_by(is_active_in_library=True).all()
    total_controls = len(all_controls)
    implemented = sum(1 for c in all_controls if c.status == 'implemented')
    in_progress = sum(1 for c in all_controls if c.status == 'in_progress')
    not_started = sum(1 for c in all_controls if c.status == 'not_started')
    compliance_score = (implemented / total_controls * 100) if total_controls > 0 else 0
    recent_audits = AuditLog.query.filter_by(user_id=user.id).order_by(AuditLog.created_at.desc()).limit(10).all()
    return render_template('dashboard.html', user=user, total_controls=total_controls, implemented=implemented, in_progress=in_progress, not_started=not_started, compliance_score=compliance_score, assigned_controls=all_controls, recent_audits=recent_audits)

# ========== ADD YOUR OTHER ROUTES HERE ==========
# (Keep all your existing @app.route functions - login, logout, controls, etc.)

# ========== INITIALIZE DATABASE ==========
with app.app_context():
    db.create_all()
    load_initial_controls()
    create_admin_user()

if __name__ == '__main__':
    app.run(debug=Config.DEBUG, host='0.0.0.0', port=5000)