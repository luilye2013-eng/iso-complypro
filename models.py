from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json
from enum import Enum

db = SQLAlchemy()

class UserStatus(Enum):
    ACTIVE = 'active'
    SUSPENDED = 'suspended'
    DEACTIVATED = 'deactivated'
    ARCHIVED = 'archived'

class User(db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    password_updated_at = db.Column(db.DateTime, default=datetime.utcnow)  # Keep UTC for model
    status = db.Column(db.String(20), default=UserStatus.ACTIVE.value)
    force_password_change = db.Column(db.Boolean, default=True)
    is_active = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(50), default='control_owner')
    organization_id = db.Column(db.Integer, default=1)
    industry_focus = db.Column(db.String(100), nullable=True)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(45), nullable=True)
    last_password_change = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, nullable=True)
    deactivated_at = db.Column(db.DateTime, nullable=True)
    deactivated_by = db.Column(db.Integer, nullable=True)
    archived_at = db.Column(db.DateTime, nullable=True)
    
    password_history = db.relationship('PasswordHistory', backref='user', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'status': self.status,
            'is_active': self.is_active,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def is_locked_out(self):
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False
    
    def increment_login_attempts(self):
        from config import Config
        self.login_attempts += 1
        if self.login_attempts >= Config.MAX_LOGIN_ATTEMPTS:
            from datetime import timedelta
            self.locked_until = datetime.utcnow() + Config.LOCKOUT_DURATION
        db.session.commit()
    
    def reset_login_attempts(self):
        self.login_attempts = 0
        self.locked_until = None
        db.session.commit()

class PasswordHistory(db.Model):
    __tablename__ = 'password_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Control(db.Model):
    __tablename__ = 'control'
    id = db.Column(db.Integer, primary_key=True)
    control_id = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100))
    framework = db.Column(db.String(50), default='CMMC')
    status = db.Column(db.String(50), default='not_started')
    implementation_notes = db.Column(db.Text)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    due_date = db.Column(db.DateTime, nullable=True)
    is_applicable = db.Column(db.Boolean, default=True)
    is_active_in_library = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, nullable=True)
    
    assignee = db.relationship('User', foreign_keys=[assigned_to])
    
    def to_dict(self):
        return {
            'id': self.id,
            'control_id': self.control_id,
            'name': self.name,
            'description': self.description,
            'category': self.category,
            'framework': self.framework,
            'status': self.status,
            'implementation_notes': self.implementation_notes,
            'assigned_to': self.assigned_to,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'is_applicable': self.is_applicable,
            'is_active_in_library': self.is_active_in_library
        }
    
    def get_due_date_status(self):
        from datetime import date
        if not self.due_date:
            return None, None
        today = date.today()
        due = self.due_date.date() if hasattr(self.due_date, 'date') else self.due_date
        days_remaining = (due - today).days
        if days_remaining < 0:
            return "Past Due", "danger"
        elif days_remaining <= 7:
            return f"Due in {days_remaining} days", "warning"
        else:
            return f"Due in {days_remaining} days", "success"

class Evidence(db.Model):
    __tablename__ = 'evidence'
    id = db.Column(db.Integer, primary_key=True)
    control_id = db.Column(db.Integer, db.ForeignKey('control.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    filename = db.Column(db.String(200))
    file_path = db.Column(db.String(500))
    file_size = db.Column(db.Integer)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)
    
    control = db.relationship('Control', backref='evidence')
    uploader = db.relationship('User', foreign_keys=[user_id])

class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    entity_type = db.Column(db.String(50))
    entity_id = db.Column(db.Integer)
    old_value = db.Column(db.Text, nullable=True)
    new_value = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ComplianceReport(db.Model):
    __tablename__ = 'compliance_report'
    id = db.Column(db.Integer, primary_key=True)
    report_name = db.Column(db.String(200))
    generated_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    overall_score = db.Column(db.Float)
    report_data = db.Column(db.Text)

class Industry(db.Model):
    __tablename__ = 'industry'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)

class ControlIndustry(db.Model):
    __tablename__ = 'control_industry'
    control_id = db.Column(db.Integer, db.ForeignKey('control.id'), primary_key=True)
    industry_id = db.Column(db.Integer, db.ForeignKey('industry.id'), primary_key=True)