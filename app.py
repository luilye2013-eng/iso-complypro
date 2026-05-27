from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, date
import json
import csv
import io
import os
import secrets
import string
from functools import wraps

# Try to import from config.py, but fall back to environment variables
try:
    from config import Config
except ImportError:
    import os
    from datetime import timedelta
    class Config:
        SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback-dev-key-change-in-production')
        SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///compliance.db')
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
from models import db, User, Control, Evidence, AuditLog, ComplianceReport, UserStatus, PasswordHistory, Industry, ControlIndustry
from auth import login_required, admin_required, audit_log, PasswordValidator

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)

# Ensure required directories exist
os.makedirs('uploads', exist_ok=True)
os.makedirs('data', exist_ok=True)

# ==================== INITIALIZATION FUNCTIONS ====================

def load_initial_controls():
    """Load controls directly from Python list (no JSON dependency)"""
    
    # Check if controls already exist
    if Control.query.count() > 0:
        print(f"Controls already exist: {Control.query.count()} controls in database")
        return
    
    # Define controls directly in Python
    controls_data = [
        {"id": "ISO-27001-A.5.1", "name": "Information security policy", "description": "Policies for information security should be defined, approved by management, published, and communicated.", "category": "Information Security Policies"},
        {"id": "ISO-27001-A.5.2", "name": "Review of the policies for information security", "description": "The policies for information security should be reviewed at planned intervals or if significant changes occur.", "category": "Information Security Policies"},
        {"id": "ISO-27001-A.6.1", "name": "Information security roles and responsibilities", "description": "Information security responsibilities should be defined and allocated.", "category": "Organization of Information Security"},
        {"id": "ISO-27001-A.6.2", "name": "Segregation of duties", "description": "Conflicting duties and areas of responsibility should be segregated.", "category": "Organization of Information Security"},
        {"id": "ISO-27001-A.7.1", "name": "Screening", "description": "Background verification checks should be carried out on all candidates for employment.", "category": "Human Resource Security"},
        {"id": "ISO-27001-A.7.2", "name": "Terms and conditions of employment", "description": "Employment contracts should state the employee's and the organization's responsibilities for information security.", "category": "Human Resource Security"},
        {"id": "ISO-27001-A.8.1", "name": "Inventory of assets", "description": "Assets associated with information and information processing facilities should be identified and documented.", "category": "Asset Management"},
        {"id": "ISO-27001-A.8.2", "name": "Ownership of assets", "description": "Assets maintained should be assigned an owner.", "category": "Asset Management"},
        {"id": "ISO-27001-A.9.1", "name": "Access control policy", "description": "An access control policy should be established, documented, and reviewed.", "category": "Access Control"},
        {"id": "ISO-27001-A.9.2", "name": "User registration and de-registration", "description": "A formal user registration and de-registration process should be implemented.", "category": "Access Control"},
        {"id": "ISO-27001-A.10.1", "name": "Cryptographic controls policy", "description": "A policy on the use of cryptographic controls should be developed and implemented.", "category": "Cryptography"},
        {"id": "ISO-27001-A.11.1", "name": "Physical security perimeter", "description": "Security perimeters should be defined and used to protect areas that contain sensitive information.", "category": "Physical Security"},
        {"id": "ISO-27001-A.12.1", "name": "Documented operating procedures", "description": "Operating procedures should be documented and made available.", "category": "Operations Security"},
        {"id": "ISO-27001-A.12.4", "name": "Event logging", "description": "Event logs recording user activities should be produced and retained.", "category": "Operations Security"},
        {"id": "ISO-27001-A.12.6", "name": "Management of technical vulnerabilities", "description": "Information about technical vulnerabilities should be obtained.", "category": "Operations Security"},
        {"id": "ISO-27001-A.13.1", "name": "Network security management", "description": "Networks should be managed and controlled to protect information.", "category": "Communications Security"},
        {"id": "ISO-27001-A.14.2", "name": "Secure development policy", "description": "Rules for the development of software and systems should be established.", "category": "System Acquisition and Development"},
        {"id": "ISO-27001-A.15.1", "name": "Supplier relationships policy", "description": "Information security requirements should be agreed with suppliers.", "category": "Supplier Relationships"},
        {"id": "ISO-27001-A.16.1", "name": "Incident management responsibilities", "description": "Responsibilities and procedures should be established for incident response.", "category": "Incident Management"},
        {"id": "ISO-27001-A.17.1", "name": "Business continuity planning", "description": "Information security continuity should be embedded in business continuity plans.", "category": "Business Continuity Management"},
        {"id": "ISO-27001-A.18.1", "name": "Compliance with legal requirements", "description": "All relevant legislative and contractual requirements should be identified.", "category": "Compliance"}
    ]
    
    controls_added = 0
    
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
        controls_added += 1
    
    db.session.commit()
    print(f"✅ Master library loaded: {controls_added} new controls added")
    print(f"📊 Total controls in database: {Control.query.count()}")

def create_admin_user():
    """Create default admin user if none exists"""
    if User.query.count() == 0:
        # Try to get from environment, otherwise generate
        temp_password = os.environ.get('ADMIN_TEMP_PASSWORD')
        if not temp_password:
            import secrets
            import string
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
            temp_password = ''.join(secrets.choice(alphabet) for _ in range(14))
        
        admin = User(
            username=os.environ.get('ADMIN_USERNAME', 'admin'),
            email=os.environ.get('ADMIN_EMAIL', 'admin@isocomplypro.local'),
            password_hash=PasswordValidator.hash_password(temp_password),
            role='admin',
            force_password_change=True,
            status='active',
            is_active=True
        )
        db.session.add(admin)
        db.session.commit()
        
        print(f"\n{'='*60}")
        print(f"ADMIN ACCOUNT CREATED")
        print(f"Username: {admin.username}")
        print(f"Temporary Password: {temp_password}")
        print(f"YOU WILL BE REQUIRED TO CHANGE THIS PASSWORD ON FIRST LOGIN")
        print(f"{'='*60}\n")

def load_master_control_library():
    """Load the master control library from JSON - only runs if library is empty"""
    json_path = 'data/master_control_library.json'
    
    if not os.path.exists(json_path):
        print(f"Warning: {json_path} not found. Using sample controls.")
        return
    
    with open(json_path, 'r') as f:
        library = json.load(f)
    
    controls_loaded = 0
    
    # Load ISO 27001 controls
    if "ISO 27001:2022" in library:
        iso_data = library["ISO 27001:2022"]
        for annex_id, annex_data in iso_data["annexes"].items():
            category = f"{annex_id}: {annex_data['name']}"
            for control_data in annex_data["controls"]:
                existing = Control.query.filter_by(control_id=control_data["id"]).first()
                if not existing:
                    control = Control(
                        control_id=control_data["id"],
                        name=control_data["name"],
                        description=control_data["description"],
                        category=category,
                        framework="ISO 27001",
                        is_applicable=True,
                        is_active_in_library=True
                    )
                    db.session.add(control)
                    controls_loaded += 1
    
    # Load CMMC controls
    if "CMMC Level 1" in library:
        cmmc_data = library["CMMC Level 1"]
        for domain in cmmc_data["domains"]:
            for control_data in domain["controls"]:
                existing = Control.query.filter_by(control_id=control_data["id"]).first()
                if not existing:
                    control = Control(
                        control_id=control_data["id"],
                        name=control_data["name"],
                        description=control_data["description"],
                        category=domain["name"],
                        framework="CMMC Level 1",
                        is_applicable=True,
                        is_active_in_library=True
                    )
                    db.session.add(control)
                    controls_loaded += 1
    
    db.session.commit()
    print(f"Loaded {controls_loaded} controls into master library")

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if not user:
            flash('Invalid username or password', 'danger')
            return render_template('login.html')
        
        if user.status == 'suspended':
            flash('Account suspended. Please contact system administrator.', 'danger')
            return render_template('login.html')
        
        if user.status == 'deactivated':
            flash('Account deactivated. Please contact system administrator.', 'danger')
            return render_template('login.html')
        
        if user.is_locked_out():
            flash(f'Account is locked. Try again after {user.locked_until.strftime("%H:%M:%S")}', 'danger')
            return render_template('login.html')
        
        if check_password_hash(user.password_hash, password):
            user.reset_login_attempts()
            user.last_login = datetime.utcnow()
            user.last_login_ip = request.remote_addr
            db.session.commit()
            
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            audit_log(user.id, 'LOGIN_SUCCESS', 'user', user.id)
            
            if user.force_password_change:
                flash('You must change your password before continuing', 'warning')
                return redirect(url_for('force_password_change'))
            
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            user.increment_login_attempts()
            audit_log(user.id, 'LOGIN_FAILED', 'user', user.id)
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/force-password-change', methods=['GET', 'POST'])
@login_required
def force_password_change():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Check if current password is provided (for non-first-time changes)
        if not user.force_password_change:
            if not current_password:
                flash('Current password is required', 'danger')
                return redirect(url_for('force_password_change'))
            if not check_password_hash(user.password_hash, current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('force_password_change'))
        
        # Validate new password
        if not new_password:
            flash('New password cannot be empty', 'danger')
            return redirect(url_for('force_password_change'))
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('force_password_change'))
        
        # Validate password strength
        errors = PasswordValidator.validate(new_password, user)
        if errors:
            for error in errors:
                flash(error, 'danger')
            return redirect(url_for('force_password_change'))
        
        # Save old password to history
        old_history = PasswordHistory(
            user_id=user.id,
            password_hash=user.password_hash
        )
        db.session.add(old_history)
        
        # Update password
        user.password_hash = PasswordValidator.hash_password(new_password)
        user.force_password_change = False
        user.password_updated_at = datetime.utcnow()
        user.last_password_change = datetime.utcnow()
        db.session.commit()
        
        audit_log(user.id, 'PASSWORD_CHANGED', 'user', user.id)
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('force_password_change.html', user=user)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        audit_log(session['user_id'], 'LOGOUT', 'user', session['user_id'])
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        email = request.form.get('email')
        if email != user.email:
            existing = User.query.filter_by(email=email).first()
            if existing:
                flash('Email already in use', 'danger')
            else:
                user.email = email
                db.session.commit()
                flash('Profile updated successfully', 'success')
        
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=user)

# ==================== DASHBOARD & CONTROLS ====================

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard with compliance metrics"""
    user = User.query.get(session['user_id'])
    
    # Determine which controls to show based on role
    if user.role == 'admin':
        all_controls = Control.query.filter_by(is_active_in_library=True).all()
        assigned_controls = all_controls
    else:
        # For regular users, show only applicable controls
        all_controls = Control.query.filter_by(is_active_in_library=True, is_applicable=True).all()
        assigned_controls = Control.query.filter_by(assigned_to=user.id, is_active_in_library=True).all()
    
    total_controls = len(all_controls)
    implemented = sum(1 for c in all_controls if c.status == 'implemented')
    in_progress = sum(1 for c in all_controls if c.status == 'in_progress')
    not_started = sum(1 for c in all_controls if c.status == 'not_started')
    
    compliance_score = (implemented / total_controls * 100) if total_controls > 0 else 0
    
    # Get recent activity
    recent_audits = AuditLog.query.filter_by(user_id=user.id)\
        .order_by(AuditLog.created_at.desc())\
        .limit(10).all()
    
    return render_template('dashboard.html',
                         user=user,
                         total_controls=total_controls,
                         implemented=implemented,
                         in_progress=in_progress,
                         not_started=not_started,
                         compliance_score=compliance_score,
                         assigned_controls=assigned_controls,
                         recent_audits=recent_audits)



@app.route('/controls')
@login_required
def controls():
    all_controls = Control.query.all()
    categories = {}
    
    for control in all_controls:
        if control.category not in categories:
            categories[control.category] = []
        categories[control.category].append(control)
    
    return render_template('controls.html', categories=categories)

@app.route('/control/<int:control_id>', methods=['GET', 'POST'])
@login_required
def control_detail(control_id):
    control = Control.query.get_or_404(control_id)
    
    if request.method == 'POST':
        new_status = request.form.get('status')
        old_status = control.status
        notes = request.form.get('notes', '')
        
        control.status = new_status
        control.implementation_notes = notes
        control.updated_by = session['user_id']
        db.session.commit()
        
        audit_log(session['user_id'], 'CONTROL_UPDATED', 'control', control.id,
                  old_status, new_status)
        
        flash('Control updated successfully', 'success')
        return redirect(url_for('control_detail', control_id=control_id))
    
    evidence_list = Evidence.query.filter_by(control_id=control_id).all()
    return render_template('control_detail.html', control=control, evidence=evidence_list)

@app.route('/select-controls', methods=['GET', 'POST'])
@login_required
def select_controls():
    user = User.query.get(session['user_id'])
    
    # Block auditors from POSTing changes
    if request.method == 'POST' and user.role == 'auditor':
        flash('Auditors cannot modify control selections', 'danger')
        return redirect(url_for('select_controls'))
    
    if request.method == 'POST':
        if user.role == 'auditor':
            flash('Auditors cannot modify control selections', 'danger')
            return redirect(url_for('dashboard'))
        
        all_controls = Control.query.filter_by(is_active_in_library=True).all()
        for control in all_controls:
            is_selected = request.form.get(f'control_{control.id}') == 'true'
            control.is_applicable = is_selected
        db.session.commit()
        flash('Your control selections have been saved', 'success')
        return redirect(url_for('dashboard'))
    
    # GET request - show controls (read-only for auditors)
    all_controls = Control.query.filter_by(is_active_in_library=True).order_by(Control.framework, Control.category).all()
    
    grouped_controls = {}
    for control in all_controls:
        if control.framework not in grouped_controls:
            grouped_controls[control.framework] = {}
        if control.category not in grouped_controls[control.framework]:
            grouped_controls[control.framework][control.category] = []
        grouped_controls[control.framework][control.category].append(control)
    
    return render_template('select_controls.html', grouped_controls=grouped_controls, user_role=user.role)
# ==================== EVIDENCE MANAGEMENT ====================

@app.route('/upload-evidence/<int:control_id>', methods=['POST'])
@login_required
def upload_evidence(control_id):
    control = Control.query.get_or_404(control_id)
    
    if 'evidence_file' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('control_detail', control_id=control_id))
    
    file = request.files['evidence_file']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('control_detail', control_id=control_id))
    
    filename = secure_filename(file.filename)
    ext = os.path.splitext(filename)[1].lower()
    
    if ext not in app.config['UPLOAD_EXTENSIONS']:
        flash(f'File type not allowed. Allowed: {", ".join(app.config["UPLOAD_EXTENSIONS"])}', 'danger')
        return redirect(url_for('control_detail', control_id=control_id))
    
    safe_filename = f"{control.control_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
    filepath = os.path.join('uploads', safe_filename)
    file.save(filepath)
    
    evidence = Evidence(
        control_id=control_id,
        user_id=session['user_id'],
        filename=filename,
        file_path=filepath,
        file_size=os.path.getsize(filepath),
        notes=request.form.get('notes', '')
    )
    db.session.add(evidence)
    db.session.commit()
    
    audit_log(session['user_id'], 'EVIDENCE_UPLOADED', 'evidence', evidence.id)
    
    flash('Evidence uploaded successfully', 'success')
    return redirect(url_for('control_detail', control_id=control_id))

# ==================== REPORTING ====================

@app.route('/report')
@login_required
def report():
    """Generate compliance report"""
    controls = Control.query.all()
    
    # Handle case when there are no controls
    total_controls = len(controls)
    
    if total_controls == 0:
        # Return empty report when no controls exist
        report_data = {
            'generated_at': datetime.now().isoformat(),
            'total_controls': 0,
            'implemented': 0,
            'in_progress': 0,
            'not_started': 0,
            'by_category': {},
            'overall_score': 0
        }
        flash('No controls found in the system. Please add controls first.', 'warning')
        return render_template('report.html', report=report_data)
    
    implemented = sum(1 for c in controls if c.status == 'implemented')
    in_progress = sum(1 for c in controls if c.status == 'in_progress')
    not_started = sum(1 for c in controls if c.status == 'not_started')
    
    report_data = {
        'generated_at': datetime.now().isoformat(),
        'total_controls': total_controls,
        'implemented': implemented,
        'in_progress': in_progress,
        'not_started': not_started,
        'by_category': {}
    }
    
    for control in controls:
        if control.category not in report_data['by_category']:
            report_data['by_category'][control.category] = {
                'total': 0,
                'implemented': 0
            }
        report_data['by_category'][control.category]['total'] += 1
        if control.status == 'implemented':
            report_data['by_category'][control.category]['implemented'] += 1
    
    report_data['overall_score'] = (implemented / total_controls * 100)
    
    # Save report to database (optional)
    try:
        report = ComplianceReport(
            report_name=f"Compliance Report {datetime.now().strftime('%Y-%m-%d')}",
            generated_by=session['user_id'],
            overall_score=report_data['overall_score'],
            report_data=json.dumps(report_data)
        )
        db.session.add(report)
        db.session.commit()
    except Exception as e:
        print(f"Warning: Could not save report: {e}")
    
    return render_template('report.html', report=report_data)

@app.route('/export/csv')
@login_required
def export_csv():
    controls = Control.query.all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(['Control ID', 'Name', 'Description', 'Category', 'Status', 'Implementation Notes'])
    
    for control in controls:
        writer.writerow([
            control.control_id,
            control.name,
            control.description,
            control.category,
            control.status,
            control.implementation_notes or ''
        ])
    
    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=compliance_report.csv'
    
    audit_log(session['user_id'], 'EXPORT_CSV', 'report', None)
    
    return response

# ==================== ADMIN USER MANAGEMENT ====================

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/add-user', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role')
        
        existing = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing:
            flash('Username or email already exists', 'danger')
            return redirect(url_for('add_user'))
        
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        temp_password = ''.join(secrets.choice(alphabet) for _ in range(14))
        
        new_user = User(
            username=username,
            email=email,
            password_hash=PasswordValidator.hash_password(temp_password),
            role=role,
            force_password_change=True,
            status='active',
            created_by=session['user_id']
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        audit_log(session['user_id'], 'USER_CREATED', 'user', new_user.id)
        
        flash(f'User {username} created successfully! Temporary password: {temp_password}', 'success')
        flash('The user MUST change this password on first login', 'warning')
        
        return redirect(url_for('admin_users'))
    
    return render_template('add_user.html')

@app.route('/admin/change-user-status/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def change_user_status(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.id == session['user_id']:
        flash('You cannot change your own account status', 'danger')
        return redirect(url_for('admin_users'))
    
    new_status = request.form.get('status')
    old_status = user.status
    reason = request.form.get('reason', '')
    
    user.status = new_status
    
    if new_status == 'deactivated':
        user.deactivated_at = datetime.utcnow()
        user.deactivated_by = session['user_id']
        user.is_active = False
    elif new_status == 'suspended':
        user.locked_until = datetime.utcnow() + Config.LOCKOUT_DURATION
    elif new_status == 'active':
        user.deactivated_at = None
        user.deactivated_by = None
        user.is_active = True
        user.locked_until = None
        user.login_attempts = 0
    
    db.session.commit()
    
    audit_log(session['user_id'], f'USER_STATUS_CHANGED: {old_status} -> {new_status}', 
              'user', user.id, old_status, f"{new_status} | Reason: {reason}")
    
    flash(f'User {user.username} status changed to {new_status}', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/reset-user-password/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def reset_user_password(user_id):
    user = User.query.get_or_404(user_id)
    
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    temp_password = ''.join(secrets.choice(alphabet) for _ in range(14))
    
    old_history = PasswordHistory(
        user_id=user.id,
        password_hash=user.password_hash
    )
    db.session.add(old_history)
    
    user.password_hash = PasswordValidator.hash_password(temp_password)
    user.force_password_change = True
    user.password_updated_at = datetime.utcnow()
    db.session.commit()
    
    audit_log(session['user_id'], 'PASSWORD_RESET_BY_ADMIN', 'user', user.id)
    
    flash(f'Password reset for {user.username}. Temporary password: {temp_password}', 'warning')
    flash('User must change password on next login', 'info')
    
    return redirect(url_for('admin_users'))

@app.route('/audit-log')
@login_required
@admin_required
def audit_log_view():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()
    return render_template('audit_log.html', logs=logs)



@app.route('/controls/<status>')
@login_required
def controls_filtered(status):
    """Show controls filtered by status"""
    if status in ['not_started', 'in_progress', 'implemented']:
        all_controls = Control.query.filter_by(status=status).all()
    else:
        all_controls = Control.query.all()
    
    categories = {}
    for control in all_controls:
        if control.category not in categories:
            categories[control.category] = []
        categories[control.category].append(control)
    
    return render_template('controls.html', categories=categories, current_filter=status)


@app.route('/admin/add-control', methods=['GET', 'POST'])
@login_required
@admin_required
def add_control():
    if request.method == 'POST':
        control_id = request.form.get('control_id')
        name = request.form.get('name')
        description = request.form.get('description')
        category = request.form.get('category')
        framework = request.form.get('framework')
        
        existing = Control.query.filter_by(control_id=control_id).first()
        if existing:
            flash(f'Control ID {control_id} already exists', 'danger')
            return redirect(url_for('add_control'))
        
        new_control = Control(
            control_id=control_id,
            name=name,
            description=description,
            category=category,
            framework=framework,
            status='not_started'
        )
        db.session.add(new_control)
        db.session.commit()
        
        audit_log(session['user_id'], 'CONTROL_CREATED', 'control', new_control.id)
        flash(f'Control {control_id} created successfully', 'success')
        return redirect(url_for('controls'))
    
    return render_template('add_control.html')


@app.route('/admin/delete-control/<int:control_id>')
@login_required
@admin_required
def delete_control(control_id):
    control = Control.query.get_or_404(control_id)
    
    # Delete associated evidence first
    Evidence.query.filter_by(control_id=control_id).delete()
    
    control_id_str = control.control_id
    db.session.delete(control)
    db.session.commit()
    
    audit_log(session['user_id'], 'CONTROL_DELETED', 'control', control_id)
    flash(f'Control {control_id_str} deleted successfully', 'success')
    return redirect(url_for('controls'))

# ==================== INITIALIZE DATABASE ====================

with app.app_context():
    db.create_all()
    load_initial_controls()
    create_admin_user()

if __name__ == '__main__':
    print("\n" + "="*60)
    print("ISO COMPLYPRO STARTING")
    print("="*60)
    print(f"Access at: http://127.0.0.1:5000")
    print("="*60 + "\n")
    app.run(debug=Config.DEBUG, host='127.0.0.1', port=5000)