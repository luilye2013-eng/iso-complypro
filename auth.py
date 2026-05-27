import re
import hashlib
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session, request, flash, redirect, url_for
from functools import wraps
from models import User, PasswordHistory, AuditLog, db

# ========== CONFIGURATION FALLBACK (No external config.py needed) ==========
import os
from datetime import timedelta

class Config:
    """Configuration class - no external file needed"""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:////tmp/compliance.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
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
# ========== END CONFIGURATION ==========


class PasswordValidator:
    """Enforce password complexity requirements"""
    
    @staticmethod
    def validate(password, user=None):
        """Validate password against security policy"""
        errors = []
        
        # Length check
        if len(password) < Config.PASSWORD_MIN_LENGTH:
            errors.append(f"Password must be at least {Config.PASSWORD_MIN_LENGTH} characters")
        
        # Uppercase check
        if Config.PASSWORD_REQUIRE_UPPER and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        # Lowercase check
        if Config.PASSWORD_REQUIRE_LOWER and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        # Digit check
        if Config.PASSWORD_REQUIRE_DIGITS and not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        # Special character check
        if Config.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        # Common password check
        common_passwords = ['Password123!', 'Admin2024!', 'Welcome1!', 'Pass@123']
        if password in common_passwords:
            errors.append("Password is too common and easily guessable")
        
        # Check against password history (prevent reuse)
        if user and user.id:
            recent_passwords = PasswordHistory.query.filter_by(user_id=user.id)\
                .order_by(PasswordHistory.created_at.desc())\
                .limit(Config.PASSWORD_HISTORY_COUNT)\
                .all()
            
            for old in recent_passwords:
                if check_password_hash(old.password_hash, password):
                    errors.append(f"Password cannot be one of the last {Config.PASSWORD_HISTORY_COUNT} passwords used")
        
        return errors
    
    @staticmethod
    def hash_password(password):
        """Hash password with secure defaults"""
        return generate_password_hash(password, method='scrypt')


def login_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        
        # Check if session is expired
        user = User.query.get(session['user_id'])
        if not user or not user.is_active or user.status != 'active':
            session.clear()
            flash('Your account is no longer active', 'danger')
            return redirect(url_for('login'))
        
        # Check for force password change
        if user.force_password_change and request.endpoint != 'force_password_change':
            flash('You must change your password before continuing', 'warning')
            return redirect(url_for('force_password_change'))
        
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def audit_log(user_id, action, entity_type=None, entity_id=None, old_value=None, new_value=None):
    """Create audit log entry"""
    log = AuditLog(
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        old_value=str(old_value) if old_value else None,
        new_value=str(new_value) if new_value else None,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string if request.user_agent else None
    )
    db.session.add(log)
    db.session.commit()