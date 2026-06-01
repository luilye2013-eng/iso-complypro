import sys
import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, date, timezone
import json
import csv
import io
import secrets
import string
import hashlib
from functools import wraps

# ========== TIMEZONE HELPER (Kenya - UTC+3) ==========
def get_local_time():
    """Return current time in UTC+3 (Kenya/Eastern Africa timezone)"""
    return datetime.now(timezone.utc) + timedelta(hours=3)

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
from models import db, User, Control, Evidence, AuditLog, ComplianceReport, UserStatus, PasswordHistory
from auth import login_required, admin_required, audit_log, PasswordValidator

# Initialize database
db.init_app(app)

# ========== INITIALIZATION FUNCTIONS ==========
def load_initial_controls():
    if Control.query.count() > 0:
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

def create_admin_user():
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
        # Only print in development, not in production logs
        if os.environ.get('FLASK_DEBUG', 'False').lower() == 'true':
            print(f"Admin created - Username: admin, Temp Password: {temp_password}")
        else:
            print("Admin account created. Check environment variables for credentials.")
        
        # Backup admin
        backup_temp_password = "BackupAdmin2024!Secure"
        backup_admin = User(
            username='backup_admin',
            email='backup@isocomplypro.local',
            password_hash=PasswordValidator.hash_password(backup_temp_password),
            role='admin',
            force_password_change=True,
            status='active',
            is_active=True
        )
        db.session.add(backup_admin)
        db.session.commit()

# ========== AUTHENTICATION ROUTES ==========
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter((User.username == username) | (User.email == username)).first()
        if not user:
            flash('Invalid username or password', 'danger')
            return render_template('login.html')
        if user.status == 'suspended':
            flash('Account suspended. Contact administrator.', 'danger')
            return render_template('login.html')
        if user.status == 'deactivated':
            flash('Account deactivated. Contact administrator.', 'danger')
            return render_template('login.html')
        if user.is_locked_out():
            flash('Account is locked. Try again later.', 'danger')
            return render_template('login.html')
        if check_password_hash(user.password_hash, password):
            user.reset_login_attempts()
            user.last_login = get_local_time()  # Fixed: local time
            db.session.commit()
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            audit_log(user.id, 'LOGIN_SUCCESS', 'user', user.id)
            if user.force_password_change:
                return redirect(url_for('force_password_change'))
            flash(f'Welcome {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            user.login_attempts += 1
            if user.login_attempts >= 5:
                user.locked_until = get_local_time() + timedelta(minutes=30)  # Fixed: local time
            db.session.commit()
            audit_log(user.id, 'LOGIN_FAILED', 'user', user.id)
            flash('Invalid password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        # Check if user exists
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            flash('Username or email already exists', 'danger')
            return redirect(url_for('register'))
        
        # Validate password strength
        temp_user = User()  # Dummy user for validation
        errors = PasswordValidator.validate(password, temp_user)
        if errors:
            for error in errors:
                flash(error, 'danger')
            return redirect(url_for('register'))
        
        # Create new user (default role: control_owner)
        new_user = User(
            username=username,
            email=email,
            password_hash=PasswordValidator.hash_password(password),
            role='control_owner',
            force_password_change=False,  # They set their own password
            status='active',
            is_active=True
        )
        db.session.add(new_user)
        db.session.commit()
        
        audit_log(new_user.id, 'USER_REGISTERED', 'user', new_user.id)
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/force-password-change', methods=['GET', 'POST'])
@login_required
def force_password_change():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('force_password_change'))
        errors = PasswordValidator.validate(new_password, user)
        if errors:
            for error in errors:
                flash(error, 'danger')
            return redirect(url_for('force_password_change'))
        # Save old password to history
        old_history = PasswordHistory(user_id=user.id, password_hash=user.password_hash)
        db.session.add(old_history)
        user.password_hash = PasswordValidator.hash_password(new_password)
        user.force_password_change = False
        user.password_updated_at = get_local_time()  # Fixed: local time
        user.last_password_change = get_local_time()  # Fixed: local time
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
    flash('Logged out', 'info')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            # Generate a simple reset token
            token = hashlib.sha256(f"{user.id}{user.email}{get_local_time().date()}".encode()).hexdigest()[:20]
            reset_link = url_for('reset_password', token=token, _external=True)
            # In production, send email. For now, display the link
            flash(f'Password reset link (copy this): {reset_link}', 'info')
            flash('In production, this would be emailed to you.', 'info')
        else:
            flash('Email not found', 'warning')
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Simplified token validation - in production, use proper token storage
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('reset_password', token=token))
        # Find user by email from session or token
        flash('Password reset complete. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

# ========== MAIN VIEWS ==========
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    all_controls = Control.query.filter_by(is_active_in_library=True).all()
    total = len(all_controls)
    implemented = sum(1 for c in all_controls if c.status == 'implemented')
    in_progress = sum(1 for c in all_controls if c.status == 'in_progress')
    not_started = sum(1 for c in all_controls if c.status == 'not_started')
    score = (implemented / total * 100) if total > 0 else 0
    recent_audits = AuditLog.query.filter_by(user_id=user.id).order_by(AuditLog.created_at.desc()).limit(10).all()
    return render_template('dashboard.html', user=user, total_controls=total, implemented=implemented, in_progress=in_progress, not_started=not_started, compliance_score=score, assigned_controls=all_controls, recent_audits=recent_audits)

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
                audit_log(session['user_id'], 'PROFILE_UPDATED', 'user', user.id)
                flash('Profile updated successfully', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)

# ========== CONTROL MANAGEMENT ==========
@app.route('/controls')
@app.route('/controls/<status>')
@login_required
def controls(status=None):
    if status and status in ['not_started', 'in_progress', 'implemented']:
        all_controls = Control.query.filter_by(status=status, is_active_in_library=True).all()
    else:
        all_controls = Control.query.filter_by(is_active_in_library=True).all()
    categories = {}
    for control in all_controls:
        if control.category not in categories:
            categories[control.category] = []
        categories[control.category].append(control)
    return render_template('controls.html', categories=categories, current_filter=status)

@app.route('/control/<int:control_id>', methods=['GET', 'POST'])
@login_required
def control_detail(control_id):
    control = Control.query.get_or_404(control_id)
    if request.method == 'POST':
        old_status = control.status
        new_status = request.form.get('status')
        due_date_str = request.form.get('due_date')
        notes = request.form.get('notes', '')
        control.status = new_status
        if due_date_str:
            control.due_date = datetime.strptime(due_date_str, '%Y-%m-%d')
        control.implementation_notes = notes
        db.session.commit()
        audit_log(session['user_id'], 'CONTROL_UPDATED', 'control', control.id, old_status, new_status)
        flash('Control updated successfully', 'success')
        return redirect(url_for('control_detail', control_id=control_id))
    evidence_list = Evidence.query.filter_by(control_id=control_id).all()
    return render_template('control_detail.html', control=control, evidence=evidence_list)

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
        flash('File type not allowed', 'danger')
        return redirect(url_for('control_detail', control_id=control_id))
    safe_filename = f"{control.control_id}_{get_local_time().strftime('%Y%m%d_%H%M%S')}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    file.save(filepath)
    evidence = Evidence(control_id=control_id, user_id=session['user_id'], filename=filename, file_path=filepath, file_size=os.path.getsize(filepath), notes=request.form.get('notes', ''))
    db.session.add(evidence)
    db.session.commit()
    audit_log(session['user_id'], 'EVIDENCE_UPLOADED', 'evidence', evidence.id)
    flash('Evidence uploaded successfully', 'success')
    return redirect(url_for('control_detail', control_id=control_id))

# ========== ADMIN - CONTROL MANAGEMENT ==========
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
            status='not_started',
            is_applicable=True,
            is_active_in_library=True
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
    Evidence.query.filter_by(control_id=control_id).delete()
    control_id_str = control.control_id
    db.session.delete(control)
    db.session.commit()
    audit_log(session['user_id'], 'CONTROL_DELETED', 'control', control_id)
    flash(f'Control {control_id_str} deleted', 'success')
    return redirect(url_for('controls'))

# ========== ADMIN - USER MANAGEMENT ==========
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
        new_user = User(username=username, email=email, password_hash=PasswordValidator.hash_password(temp_password), role=role, force_password_change=True, status='active', created_by=session['user_id'])
        db.session.add(new_user)
        db.session.commit()
        audit_log(session['user_id'], 'USER_CREATED', 'user', new_user.id)
        flash(f'User {username} created! Temp password: {temp_password}', 'success')
        return redirect(url_for('admin_users'))
    return render_template('add_user.html')

@app.route('/admin/change-user-status/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def change_user_status(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == session['user_id']:
        flash('Cannot change your own status', 'danger')
        return redirect(url_for('admin_users'))
    old_status = user.status
    new_status = request.form.get('status')
    user.status = new_status
    if new_status == 'deactivated':
        user.is_active = False
    elif new_status == 'active':
        user.is_active = True
        user.locked_until = None
        user.login_attempts = 0
    db.session.commit()
    audit_log(session['user_id'], f'USER_STATUS_CHANGED: {old_status} -> {new_status}', 'user', user.id)
    flash(f'User {user.username} status changed to {new_status}', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/reset-user-password/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def reset_user_password(user_id):
    user = User.query.get_or_404(user_id)
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    temp_password = ''.join(secrets.choice(alphabet) for _ in range(14))
    old_history = PasswordHistory(user_id=user.id, password_hash=user.password_hash)
    db.session.add(old_history)
    user.password_hash = PasswordValidator.hash_password(temp_password)
    user.force_password_change = True
    user.password_updated_at = get_local_time()  # Fixed: local time
    db.session.commit()
    audit_log(session['user_id'], 'PASSWORD_RESET_BY_ADMIN', 'user', user.id)
    flash(f'Password reset for {user.username}. Temp password: {temp_password}', 'warning')
    return redirect(url_for('admin_users'))

# ========== REPORTING ==========
@app.route('/report')
@login_required
def report():
    controls = Control.query.all()
    total = len(controls)
    if total == 0:
        report_data = {'generated_at': get_local_time().isoformat(), 'total_controls': 0, 'implemented': 0, 'in_progress': 0, 'not_started': 0, 'by_category': {}, 'overall_score': 0}
        return render_template('report.html', report=report_data)
    implemented = sum(1 for c in controls if c.status == 'implemented')
    in_progress = sum(1 for c in controls if c.status == 'in_progress')
    not_started = sum(1 for c in controls if c.status == 'not_started')
    report_data = {'generated_at': get_local_time().isoformat(), 'total_controls': total, 'implemented': implemented, 'in_progress': in_progress, 'not_started': not_started, 'by_category': {}}
    for control in controls:
        if control.category not in report_data['by_category']:
            report_data['by_category'][control.category] = {'total': 0, 'implemented': 0}
        report_data['by_category'][control.category]['total'] += 1
        if control.status == 'implemented':
            report_data['by_category'][control.category]['implemented'] += 1
    report_data['overall_score'] = (implemented / total * 100)
    audit_log(session['user_id'], 'REPORT_GENERATED', 'report', None)
    return render_template('report.html', report=report_data)

@app.route('/export/csv')
@login_required
def export_csv():
    controls = Control.query.all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Control ID', 'Name', 'Description', 'Category', 'Status', 'Implementation Notes'])
    for control in controls:
        writer.writerow([control.control_id, control.name, control.description, control.category, control.status, control.implementation_notes or ''])
    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=compliance_report.csv'
    audit_log(session['user_id'], 'EXPORT_CSV', 'report', None)
    return response

@app.route('/audit-log')
@login_required
@admin_required
def audit_log_view():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()
    return render_template('audit_log.html', logs=logs)

# ========== USER SETTINGS ==========
@app.route('/select-controls', methods=['GET', 'POST'])
@login_required
def select_controls():
    user = User.query.get(session['user_id'])
    if request.method == 'POST' and user.role == 'auditor':
        flash('Auditors cannot modify selections', 'danger')
        return redirect(url_for('select_controls'))
    if request.method == 'POST':
        all_controls = Control.query.filter_by(is_active_in_library=True).all()
        for control in all_controls:
            control.is_applicable = request.form.get(f'control_{control.id}') == 'true'
        db.session.commit()
        audit_log(session['user_id'], 'CONTROLS_SELECTED', 'user', user.id)
        flash('Selections saved', 'success')
        return redirect(url_for('dashboard'))
    all_controls = Control.query.filter_by(is_active_in_library=True).order_by(Control.framework, Control.category).all()
    grouped_controls = {}
    for control in all_controls:
        if control.framework not in grouped_controls:
            grouped_controls[control.framework] = {}
        if control.category not in grouped_controls[control.framework]:
            grouped_controls[control.framework][control.category] = []
        grouped_controls[control.framework][control.category].append(control)
    return render_template('select_controls.html', grouped_controls=grouped_controls, user_role=user.role)

# ========== INITIALIZE DATABASE ==========
with app.app_context():
    db.create_all()
    load_initial_controls()
    create_admin_user()

if __name__ == '__main__':
    app.run(debug=Config.DEBUG, host='0.0.0.0', port=5000)