"""
Magnolia Health PLLC - Controlled Substance Inventory Management System
Compliant with DEA 21 CFR 1304 and NC DHHS Drug Control Unit Requirements

Features:
- Perpetual inventory tracking
- Daily counts with dual verification
- Dispensing records with running balance
- Wasting documentation with witness verification
- Packing slip/document storage
- Biennial inventory reporting
- Complete audit trail
- Role-based access control
"""

import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import (Flask, render_template, request, redirect, url_for, flash,
                   session, jsonify, send_from_directory, abort, Response)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, and_, or_

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///controlled_substances.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
LOGO_FOLDER = os.path.join(app.config['UPLOAD_FOLDER'], 'logo')

db = SQLAlchemy(app)

# Ensure upload directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(LOGO_FOLDER, exist_ok=True)


# ==================== DATABASE MODELS ====================

class User(db.Model):
    """User accounts with role-based access"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin, provider, staff
    credentials = db.Column(db.String(50))  # NP-C, PA-C, RN, etc.
    dea_number = db.Column(db.String(20))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Medication(db.Model):
    """Controlled substance medication catalog"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    generic_name = db.Column(db.String(120))
    schedule = db.Column(db.String(10), nullable=False)  # II, III, IV, V
    ndc = db.Column(db.String(20))
    form = db.Column(db.String(50))  # tablet, capsule, liquid, injection, etc.
    strength = db.Column(db.String(50))
    unit = db.Column(db.String(20))  # mg, ml, mcg, etc.
    manufacturer = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    inventory_items = db.relationship('InventoryItem', backref='medication', lazy='dynamic')


class InventoryItem(db.Model):
    """Individual inventory items/lots"""
    id = db.Column(db.Integer, primary_key=True)
    medication_id = db.Column(db.Integer, db.ForeignKey('medication.id'), nullable=False)
    lot_number = db.Column(db.String(50))
    expiration_date = db.Column(db.Date)
    quantity_received = db.Column(db.Float, nullable=False)
    current_quantity = db.Column(db.Float, nullable=False)
    unit_count = db.Column(db.String(20))  # tablets, ml, vials, etc.
    date_received = db.Column(db.DateTime, default=datetime.utcnow)
    received_date = db.Column(db.Date)
    received_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    supplier = db.Column(db.String(100))
    invoice_number = db.Column(db.String(50))
    acquisition_document_id = db.Column(db.Integer, db.ForeignKey('document.id'))
    storage_location = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    acquisition_document = db.relationship('Document', foreign_keys=[acquisition_document_id])
    
    @property
    def is_expired(self):
        if not self.expiration_date:
            return False
        return self.expiration_date < datetime.now().date()
    
    @property
    def days_until_expiration(self):
        if not self.expiration_date:
            return 999
        return (self.expiration_date - datetime.now().date()).days


class Transaction(db.Model):
    """All transactions: dispensing, wasting, adjustments, transfers"""
    id = db.Column(db.Integer, primary_key=True)
    inventory_item_id = db.Column(db.Integer, db.ForeignKey('inventory_item.id'), nullable=False)
    transaction_type = db.Column(db.String(20), nullable=False)  # dispense, waste, adjust, return, transfer
    quantity = db.Column(db.Float, nullable=False)
    balance_before = db.Column(db.Float, nullable=False)
    balance_after = db.Column(db.Float, nullable=False)
    
    # For dispensing
    patient_name = db.Column(db.String(120))
    patient_dob = db.Column(db.Date)
    patient_mrn = db.Column(db.String(50))
    prescription_number = db.Column(db.String(50))
    prescriber_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # For wasting
    waste_reason = db.Column(db.String(200))
    witness_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    witness_signature_time = db.Column(db.DateTime)
    
    # For adjustments
    adjustment_reason = db.Column(db.String(200))
    
    # Common fields
    performed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    performed_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)
    
    # Relationships
    inventory_item = db.relationship('InventoryItem', backref='transactions')
    performer = db.relationship('User', foreign_keys=[performed_by], backref='performed_transactions')
    witness = db.relationship('User', foreign_keys=[witness_id])
    prescriber = db.relationship('User', foreign_keys=[prescriber_id])


class DailyCount(db.Model):
    """Daily physical counts with dual verification"""
    id = db.Column(db.Integer, primary_key=True)
    inventory_item_id = db.Column(db.Integer, db.ForeignKey('inventory_item.id'), nullable=False)
    count_date = db.Column(db.Date, nullable=False)
    expected_quantity = db.Column(db.Float, nullable=False)
    actual_quantity = db.Column(db.Float, nullable=False)
    discrepancy = db.Column(db.Float, default=0)
    
    # Primary counter
    counted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    counted_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Witness/verifier
    verified_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    verified_at = db.Column(db.DateTime)
    
    # Discrepancy handling
    discrepancy_resolved = db.Column(db.Boolean, default=True)
    resolution_notes = db.Column(db.Text)
    resolved_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    resolved_at = db.Column(db.DateTime)
    
    notes = db.Column(db.Text)
    
    # Relationships
    inventory_item = db.relationship('InventoryItem', backref='daily_counts')
    counter = db.relationship('User', foreign_keys=[counted_by])
    verifier = db.relationship('User', foreign_keys=[verified_by])
    resolver = db.relationship('User', foreign_keys=[resolved_by])


class BiennialInventory(db.Model):
    """Biennial inventory records per DEA requirements"""
    id = db.Column(db.Integer, primary_key=True)
    inventory_date = db.Column(db.Date, nullable=False)
    inventory_time = db.Column(db.String(20))  # Opening or Close of business
    dea_registration = db.Column(db.String(20))
    nc_registration = db.Column(db.String(20))
    conducted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    witnessed_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)
    is_complete = db.Column(db.Boolean, default=False)
    
    # Relationships
    conductor = db.relationship('User', foreign_keys=[conducted_by])
    witness = db.relationship('User', foreign_keys=[witnessed_by])
    items = db.relationship('BiennialInventoryItem', backref='inventory', lazy='dynamic')


class BiennialInventoryItem(db.Model):
    """Individual items in biennial inventory"""
    id = db.Column(db.Integer, primary_key=True)
    biennial_inventory_id = db.Column(db.Integer, db.ForeignKey('biennial_inventory.id'), nullable=False)
    medication_id = db.Column(db.Integer, db.ForeignKey('medication.id'), nullable=False)
    inventory_item_id = db.Column(db.Integer, db.ForeignKey('inventory_item.id'))
    
    drug_name = db.Column(db.String(120), nullable=False)
    schedule = db.Column(db.String(10), nullable=False)
    ndc = db.Column(db.String(20))
    form = db.Column(db.String(50))
    strength = db.Column(db.String(50))
    lot_number = db.Column(db.String(50))
    expiration_date = db.Column(db.Date)
    
    container_opened = db.Column(db.Boolean, default=False)
    quantity_counted = db.Column(db.Float, nullable=False)
    unit = db.Column(db.String(20))
    count_method = db.Column(db.String(20))  # exact, estimated
    
    # Relationships
    medication = db.relationship('Medication')


class Document(db.Model):
    """Document storage for packing slips, DEA forms, etc."""
    id = db.Column(db.Integer, primary_key=True)
    document_type = db.Column(db.String(50), nullable=False)  # packing_slip, dea_222, invoice, other
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255))
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer)
    mime_type = db.Column(db.String(100))
    
    description = db.Column(db.Text)
    reference_number = db.Column(db.String(100))  # Invoice #, DEA Form #, etc.
    document_date = db.Column(db.Date)
    
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    uploader = db.relationship('User', backref='uploaded_documents')


class TheftLossReport(db.Model):
    """DEA Form 106 - Theft/Loss Reports"""
    id = db.Column(db.Integer, primary_key=True)
    report_date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    discovery_date = db.Column(db.Date, nullable=False)
    report_type = db.Column(db.String(20), nullable=False)  # theft, loss, breakage
    
    medication_id = db.Column(db.Integer, db.ForeignKey('medication.id'), nullable=False)
    inventory_item_id = db.Column(db.Integer, db.ForeignKey('inventory_item.id'))
    
    quantity_lost = db.Column(db.Float, nullable=False)
    circumstances = db.Column(db.Text, nullable=False)
    police_notified = db.Column(db.Boolean, default=False)
    police_report_number = db.Column(db.String(50))
    dea_notified = db.Column(db.Boolean, default=False)
    dea_notification_date = db.Column(db.Date)
    dea_form_106_submitted = db.Column(db.Boolean, default=False)
    nc_dcu_notified = db.Column(db.Boolean, default=False)
    
    reported_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    medication = db.relationship('Medication')
    inventory_item = db.relationship('InventoryItem')
    reporter = db.relationship('User')


class AuditLog(db.Model):
    """Comprehensive audit logging"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(50), nullable=False)
    entity_type = db.Column(db.String(50))
    entity_id = db.Column(db.Integer)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    
    # Relationships
    user = db.relationship('User', backref='audit_logs')


class RegistrationInfo(db.Model):
    """DEA and NC-DCU registration information"""
    id = db.Column(db.Integer, primary_key=True)
    registration_type = db.Column(db.String(20), nullable=False)  # DEA, NC-DCU
    registration_number = db.Column(db.String(50), nullable=False)
    registrant_name = db.Column(db.String(120))
    business_name = db.Column(db.String(120))
    address = db.Column(db.Text)
    issue_date = db.Column(db.Date)
    expiration_date = db.Column(db.Date)
    schedules_authorized = db.Column(db.String(50))  # II,III,IV,V
    is_active = db.Column(db.Boolean, default=True)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    @property
    def days_until_expiration(self):
        if not self.expiration_date:
            return 999
        return (self.expiration_date - datetime.now().date()).days


# ==================== HELPER FUNCTIONS ====================

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def log_audit(action, entity_type=None, entity_id=None, details=None):
    """Log an audit entry"""
    audit = AuditLog(
        user_id=session.get('user_id'),
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details,
        ip_address=request.remote_addr
    )
    db.session.add(audit)
    db.session.commit()


def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            flash('Administrator access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def provider_required(f):
    """Decorator to require provider role or higher"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role not in ['admin', 'provider']:
            flash('Provider access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


# ==================== CONTEXT PROCESSORS ====================

@app.context_processor
def inject_globals():
    """Inject global variables into templates"""
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    
    # Get pending items for alerts
    pending_counts = 0
    expiring_soon = 0
    if user:
        # Get unverified daily counts from today
        today = datetime.now().date()
        pending_counts = DailyCount.query.filter(
            DailyCount.count_date == today,
            DailyCount.verified_by == None,
            DailyCount.discrepancy != 0
        ).count()
        
        # Get items expiring within 90 days
        ninety_days = today + timedelta(days=90)
        expiring_soon = InventoryItem.query.filter(
            InventoryItem.is_active == True,
            InventoryItem.current_quantity > 0,
            InventoryItem.expiration_date <= ninety_days,
            InventoryItem.expiration_date >= today
        ).count()
    
    # Check for uploaded logo
    logo_path = None
    for ext in ['png', 'jpg', 'jpeg', 'gif']:
        logo_file = os.path.join(LOGO_FOLDER, f'logo.{ext}')
        if os.path.exists(logo_file):
            logo_path = f'logo.{ext}'
            break
    
    return dict(
        current_user=user,
        pending_counts=pending_counts,
        expiring_soon=expiring_soon,
        now=datetime.now(),
        logo_path=logo_path
    )


# ==================== AUTHENTICATION ROUTES ====================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_active:
                flash('Your account has been deactivated. Contact an administrator.', 'danger')
                return render_template('login.html')
            
            session.permanent = True
            session['user_id'] = user.id
            session['user_name'] = user.full_name
            session['user_role'] = user.role
            
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            log_audit('login', 'user', user.id, f'User {user.username} logged in')
            
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            log_audit('failed_login', details=f'Failed login attempt for username: {username}')
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_audit('logout', 'user', session['user_id'])
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ==================== DASHBOARD ROUTES ====================

@app.route('/')
@login_required
def dashboard():
    today = datetime.now().date()
    
    # Get summary statistics
    total_medications = Medication.query.filter_by(is_active=True).count()
    total_inventory_items = InventoryItem.query.filter(
        InventoryItem.is_active == True,
        InventoryItem.current_quantity > 0
    ).count()
    
    # Today's activity
    todays_transactions = Transaction.query.filter(
        func.date(Transaction.performed_at) == today
    ).count()
    
    todays_counts = DailyCount.query.filter_by(count_date=today).count()
    
    # Pending verifications
    pending_verifications = DailyCount.query.filter(
        DailyCount.count_date == today,
        DailyCount.verified_by == None
    ).all()
    
    # Discrepancies needing resolution
    unresolved_discrepancies = DailyCount.query.filter(
        DailyCount.discrepancy != 0,
        DailyCount.discrepancy_resolved == False
    ).all()
    
    # Expiring inventory (within 90 days)
    ninety_days = today + timedelta(days=90)
    expiring_items = InventoryItem.query.filter(
        InventoryItem.is_active == True,
        InventoryItem.current_quantity > 0,
        InventoryItem.expiration_date <= ninety_days
    ).order_by(InventoryItem.expiration_date).limit(10).all()
    
    # Low inventory items (less than 10 units)
    low_inventory = InventoryItem.query.filter(
        InventoryItem.is_active == True,
        InventoryItem.current_quantity > 0,
        InventoryItem.current_quantity < 10
    ).all()
    
    # Recent transactions
    recent_transactions = Transaction.query.order_by(
        Transaction.performed_at.desc()
    ).limit(10).all()
    
    # Check biennial inventory status
    last_biennial = BiennialInventory.query.filter_by(is_complete=True).order_by(
        BiennialInventory.inventory_date.desc()
    ).first()
    
    biennial_due = True
    days_until_biennial = 0
    if last_biennial:
        next_biennial = last_biennial.inventory_date + timedelta(days=730)  # 2 years
        days_until_biennial = (next_biennial - today).days
        biennial_due = days_until_biennial <= 30
    
    # Registration expiration check
    registrations = RegistrationInfo.query.filter_by(is_active=True).all()
    expiring_registrations = [r for r in registrations 
                              if r.expiration_date and (r.expiration_date - today).days <= 60]
    
    return render_template('dashboard.html',
                          total_medications=total_medications,
                          total_inventory_items=total_inventory_items,
                          todays_transactions=todays_transactions,
                          todays_counts=todays_counts,
                          pending_verifications=pending_verifications,
                          unresolved_discrepancies=unresolved_discrepancies,
                          expiring_items=expiring_items,
                          low_inventory=low_inventory,
                          recent_transactions=recent_transactions,
                          biennial_due=biennial_due,
                          days_until_biennial=days_until_biennial,
                          last_biennial=last_biennial,
                          expiring_registrations=expiring_registrations)


# ==================== MEDICATION ROUTES ====================

@app.route('/medications')
@login_required
def medications():
    schedule_filter = request.args.get('schedule', '')
    search = request.args.get('search', '')
    
    query = Medication.query.filter_by(is_active=True)
    
    if schedule_filter:
        query = query.filter_by(schedule=schedule_filter)
    
    if search:
        query = query.filter(
            or_(
                Medication.name.ilike(f'%{search}%'),
                Medication.generic_name.ilike(f'%{search}%'),
                Medication.ndc.ilike(f'%{search}%')
            )
        )
    
    medications = query.order_by(Medication.name).all()
    
    return render_template('medications.html', 
                          medications=medications,
                          schedule_filter=schedule_filter,
                          search=search)


@app.route('/medications/add', methods=['GET', 'POST'])
@provider_required
def add_medication():
    if request.method == 'POST':
        medication = Medication(
            name=request.form['name'],
            generic_name=request.form.get('generic_name'),
            schedule=request.form['schedule'],
            ndc=request.form.get('ndc'),
            form=request.form.get('form'),
            strength=request.form.get('strength'),
            unit=request.form.get('unit'),
            manufacturer=request.form.get('manufacturer'),
            created_by=session['user_id']
        )
        db.session.add(medication)
        db.session.commit()
        
        log_audit('add_medication', 'medication', medication.id, 
                 f'Added medication: {medication.name}')
        
        flash(f'Medication "{medication.name}" added successfully.', 'success')
        return redirect(url_for('medications'))
    
    return render_template('medication_form.html', medication=None)


@app.route('/medications/<int:id>/edit', methods=['GET', 'POST'])
@provider_required
def edit_medication(id):
    medication = Medication.query.get_or_404(id)
    
    if request.method == 'POST':
        medication.name = request.form['name']
        medication.generic_name = request.form.get('generic_name')
        medication.schedule = request.form['schedule']
        medication.ndc = request.form.get('ndc')
        medication.form = request.form.get('form')
        medication.strength = request.form.get('strength')
        medication.unit = request.form.get('unit')
        medication.manufacturer = request.form.get('manufacturer')
        
        db.session.commit()
        
        log_audit('edit_medication', 'medication', medication.id,
                 f'Updated medication: {medication.name}')
        
        flash(f'Medication "{medication.name}" updated successfully.', 'success')
        return redirect(url_for('medications'))
    
    return render_template('medication_form.html', medication=medication)


@app.route('/medications/<int:id>/delete', methods=['POST'])
@admin_required
def delete_medication(id):
    medication = Medication.query.get_or_404(id)
    
    # Check if medication has any inventory items
    active_inventory = InventoryItem.query.filter_by(
        medication_id=id,
        is_active=True
    ).filter(InventoryItem.current_quantity > 0).first()
    
    if active_inventory:
        flash(f'Cannot delete "{medication.name}" - there is still inventory in stock. Dispense or waste all inventory first.', 'danger')
        return redirect(url_for('medications'))
    
    # Check for any transactions linked to this medication's inventory items
    has_transactions = Transaction.query.join(InventoryItem).filter(
        InventoryItem.medication_id == id
    ).first()
    
    med_name = medication.name
    
    if has_transactions:
        # Soft delete - deactivate but keep for records
        medication.is_active = False
        # Also deactivate any inventory items
        InventoryItem.query.filter_by(medication_id=id).update({'is_active': False})
        db.session.commit()
        
        log_audit('deactivate_medication', 'medication', id,
                 f'Deactivated medication (has transaction history): {med_name}')
        
        flash(f'Medication "{med_name}" has been deactivated (kept for historical records).', 'warning')
    else:
        # Hard delete - no transaction history
        # Delete any empty inventory items first
        InventoryItem.query.filter_by(medication_id=id).delete()
        db.session.delete(medication)
        db.session.commit()
        
        log_audit('delete_medication', 'medication', id,
                 f'Deleted medication: {med_name}')
        
        flash(f'Medication "{med_name}" deleted successfully.', 'success')
    
    return redirect(url_for('medications'))


# ==================== INVENTORY ROUTES ====================

@app.route('/inventory')
@login_required
def inventory():
    schedule_filter = request.args.get('schedule', '')
    show_empty = request.args.get('show_empty', 'false') == 'true'
    search = request.args.get('search', '')
    
    query = InventoryItem.query.join(Medication).filter(InventoryItem.is_active == True)
    
    if not show_empty:
        query = query.filter(InventoryItem.current_quantity > 0)
    
    if schedule_filter:
        query = query.filter(Medication.schedule == schedule_filter)
    
    if search:
        query = query.filter(
            or_(
                Medication.name.ilike(f'%{search}%'),
                InventoryItem.lot_number.ilike(f'%{search}%')
            )
        )
    
    items = query.order_by(Medication.schedule, Medication.name).all()
    
    # Group by schedule for DEA compliance (Schedule II separate)
    schedule_ii_items = [i for i in items if i.medication.schedule == 'II']
    other_items = [i for i in items if i.medication.schedule != 'II']
    
    return render_template('inventory.html',
                          schedule_ii_items=schedule_ii_items,
                          other_items=other_items,
                          schedule_filter=schedule_filter,
                          show_empty=show_empty,
                          search=search)


@app.route('/inventory/receive', methods=['GET', 'POST'])
@login_required
def receive_inventory():
    if request.method == 'POST':
        medication_id = request.form['medication_id']
        
        # Handle document upload
        document_id = None
        if 'packing_slip' in request.files:
            file = request.files['packing_slip']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                
                document = Document(
                    document_type='packing_slip',
                    filename=unique_filename,
                    original_filename=filename,
                    file_path=file_path,
                    file_size=os.path.getsize(file_path),
                    mime_type=file.content_type,
                    reference_number=request.form.get('invoice_number'),
                    document_date=datetime.strptime(request.form['date_received'], '%Y-%m-%d').date() if request.form.get('date_received') else datetime.now().date(),
                    description=f"Packing slip for {request.form.get('invoice_number', 'N/A')}",
                    uploaded_by=session['user_id']
                )
                db.session.add(document)
                db.session.flush()
                document_id = document.id
        
        # Parse expiration date
        expiration_date = None
        if request.form.get('expiration_date'):
            expiration_date = datetime.strptime(request.form['expiration_date'], '%Y-%m-%d').date()
        
        # Parse received date
        date_received = datetime.now()
        if request.form.get('date_received'):
            date_received = datetime.strptime(request.form['date_received'], '%Y-%m-%d')
        
        quantity = float(request.form['quantity'])
        
        item = InventoryItem(
            medication_id=medication_id,
            lot_number=request.form.get('lot_number'),
            expiration_date=expiration_date,
            quantity_received=quantity,
            current_quantity=quantity,
            unit_count=request.form.get('unit_count'),
            date_received=date_received,
            received_by=session['user_id'],
            supplier=request.form.get('supplier'),
            invoice_number=request.form.get('invoice_number'),
            acquisition_document_id=document_id,
            storage_location=request.form.get('storage_location'),
            notes=request.form.get('notes')
        )
        db.session.add(item)
        db.session.commit()
        
        med = Medication.query.get(medication_id)
        log_audit('receive_inventory', 'inventory_item', item.id,
                 f'Received {quantity} units of {med.name}, Lot: {item.lot_number}')
        
        flash(f'Inventory received successfully. {quantity} units of {med.name} added.', 'success')
        return redirect(url_for('inventory'))
    
    medications = Medication.query.filter_by(is_active=True).order_by(Medication.name).all()
    return render_template('receive_inventory.html', medications=medications)


@app.route('/inventory/<int:id>')
@login_required
def inventory_detail(id):
    item = InventoryItem.query.get_or_404(id)
    
    transactions = Transaction.query.filter_by(inventory_item_id=id).order_by(
        Transaction.performed_at.desc()
    ).all()
    
    daily_counts = DailyCount.query.filter_by(inventory_item_id=id).order_by(
        DailyCount.count_date.desc()
    ).limit(30).all()
    
    return render_template('inventory_detail.html',
                          item=item,
                          transactions=transactions,
                          daily_counts=daily_counts)


# ==================== DISPENSING ROUTES ====================

@app.route('/dispense', methods=['GET', 'POST'])
@login_required
def dispense():
    if request.method == 'POST':
        inventory_item_id = int(request.form['inventory_item_id'])
        quantity = float(request.form['quantity'])
        
        item = InventoryItem.query.get_or_404(inventory_item_id)
        
        if quantity > item.current_quantity:
            flash('Insufficient quantity available.', 'danger')
            return redirect(url_for('dispense'))
        
        balance_before = item.current_quantity
        item.current_quantity -= quantity
        balance_after = item.current_quantity
        
        # Parse patient DOB if provided
        patient_dob = None
        if request.form.get('patient_dob'):
            patient_dob = datetime.strptime(request.form['patient_dob'], '%Y-%m-%d').date()
        
        transaction = Transaction(
            inventory_item_id=inventory_item_id,
            transaction_type='dispense',
            quantity=quantity,
            balance_before=balance_before,
            balance_after=balance_after,
            patient_name=request.form.get('patient_name'),
            patient_dob=patient_dob,
            patient_mrn=request.form.get('patient_mrn'),
            prescription_number=request.form.get('prescription_number'),
            prescriber_id=request.form.get('prescriber_id') or None,
            performed_by=session['user_id'],
            notes=request.form.get('notes')
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        log_audit('dispense', 'transaction', transaction.id,
                 f'Dispensed {quantity} units of {item.medication.name} to {request.form.get("patient_name", "Unknown")}')
        
        flash(f'Successfully dispensed {quantity} units. New balance: {balance_after}', 'success')
        return redirect(url_for('inventory'))
    
    # Get available inventory items
    items = InventoryItem.query.join(Medication).filter(
        InventoryItem.is_active == True,
        InventoryItem.current_quantity > 0
    ).order_by(Medication.schedule, Medication.name).all()
    
    providers = User.query.filter(
        User.is_active == True,
        User.role.in_(['admin', 'provider'])
    ).all()
    
    return render_template('dispense.html', items=items, providers=providers)


# ==================== WASTING ROUTES ====================

@app.route('/waste', methods=['GET', 'POST'])
@login_required
def waste():
    if request.method == 'POST':
        inventory_item_id = int(request.form['inventory_id'])
        quantity = float(request.form['quantity'])
        
        # Verify witness credentials
        witness_username = request.form.get('witness_username', '').strip().lower()
        witness_password = request.form.get('witness_password', '')
        
        witness = User.query.filter_by(username=witness_username, is_active=True).first()
        
        if not witness:
            flash('Invalid witness username.', 'danger')
            return redirect(url_for('waste'))
        
        if not witness.check_password(witness_password):
            flash('Invalid witness password.', 'danger')
            return redirect(url_for('waste'))
        
        if witness.id == session['user_id']:
            flash('Witness must be a different person than the one performing the waste.', 'danger')
            return redirect(url_for('waste'))
        
        item = InventoryItem.query.get_or_404(inventory_item_id)
        
        if quantity > item.current_quantity:
            flash('Insufficient quantity available.', 'danger')
            return redirect(url_for('waste'))
        
        balance_before = item.current_quantity
        item.current_quantity -= quantity
        balance_after = item.current_quantity
        
        transaction = Transaction(
            inventory_item_id=inventory_item_id,
            transaction_type='waste',
            quantity=quantity,
            balance_before=balance_before,
            balance_after=balance_after,
            waste_reason=request.form.get('reason'),
            witness_id=witness.id,
            witness_signature_time=datetime.utcnow(),
            performed_by=session['user_id'],
            notes=request.form.get('notes')
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        log_audit('waste', 'transaction', transaction.id,
                 f'Wasted {quantity} units of {item.medication.name}, witnessed by {witness.full_name}')
        
        flash(f'Waste documented successfully. {quantity} units wasted. New balance: {balance_after}', 'success')
        return redirect(url_for('inventory'))
    
    items = InventoryItem.query.join(Medication).filter(
        InventoryItem.is_active == True,
        InventoryItem.current_quantity > 0
    ).order_by(Medication.schedule, Medication.name).all()
    
    return render_template('waste.html', inventory_items=items)


# ==================== DAILY COUNT ROUTES ====================

@app.route('/daily-count', methods=['GET', 'POST'])
@login_required
def daily_count():
    today = datetime.now().date()
    
    if request.method == 'POST':
        notes = request.form.get('notes', '').strip()
        counts_created = 0
        discrepancies_found = 0
        
        # Process all submitted counts
        for key in request.form:
            if key.startswith('count_') and request.form[key]:
                item_id = int(key.replace('count_', ''))
                actual_quantity = float(request.form[key])
                expected_quantity = float(request.form.get(f'expected_{item_id}', 0))
                
                item = InventoryItem.query.get(item_id)
                if not item:
                    continue
                
                discrepancy = actual_quantity - expected_quantity
                
                # Check if already counted today
                existing = DailyCount.query.filter_by(
                    inventory_item_id=item_id,
                    count_date=today
                ).first()
                
                if existing:
                    # Update existing count - reset verification since count changed
                    existing.actual_quantity = actual_quantity
                    existing.expected_quantity = expected_quantity
                    existing.discrepancy = discrepancy
                    existing.notes = notes
                    existing.counted_at = datetime.utcnow()
                    existing.counted_by = session['user_id']
                    existing.verified_by = None  # Reset verification
                    existing.verified_at = None
                    existing.discrepancy_resolved = (discrepancy == 0)
                else:
                    # Create new count
                    count = DailyCount(
                        inventory_item_id=item_id,
                        count_date=today,
                        expected_quantity=expected_quantity,
                        actual_quantity=actual_quantity,
                        discrepancy=discrepancy,
                        counted_by=session['user_id'],
                        counted_at=datetime.utcnow(),
                        discrepancy_resolved=(discrepancy == 0),
                        notes=notes if discrepancy != 0 else None
                    )
                    db.session.add(count)
                
                counts_created += 1
                if discrepancy != 0:
                    discrepancies_found += 1
        
        db.session.commit()
        
        log_audit('daily_count', 'daily_count', None,
                 f'Daily count completed: {counts_created} items counted, {discrepancies_found} discrepancies')
        
        if discrepancies_found > 0:
            flash(f'Daily count submitted: {counts_created} items counted, {discrepancies_found} discrepancies found requiring investigation.', 'warning')
        else:
            flash(f'Daily count submitted successfully: {counts_created} items counted, all matched.', 'success')
        
        return redirect(url_for('daily_count'))
    
    # Get all inventory items with stock
    inventory_items = InventoryItem.query.join(Medication).filter(
        InventoryItem.is_active == True,
        InventoryItem.current_quantity > 0
    ).order_by(Medication.schedule, Medication.name).all()
    
    # Get today's counts
    todays_counts = DailyCount.query.filter_by(count_date=today).all()
    already_counted_ids = [c.inventory_item_id for c in todays_counts]
    already_counted_values = {c.inventory_item_id: c.actual_quantity for c in todays_counts}
    
    # Get counts awaiting verification (from today, not verified yet)
    pending_verification = DailyCount.query.filter(
        DailyCount.count_date == today,
        DailyCount.verified_by == None
    ).all()
    
    return render_template('daily_count.html',
                          inventory_items=inventory_items,
                          already_counted_ids=already_counted_ids,
                          already_counted_values=already_counted_values,
                          pending_verification=pending_verification,
                          today=today)


@app.route('/daily-count/<int:id>/verify', methods=['POST'])
@login_required
def verify_count(id):
    # Get count ID from form or URL
    count_id = request.form.get('count_id', id)
    count = DailyCount.query.get_or_404(int(count_id))
    
    # Verify credentials
    verifier_username = request.form.get('verifier_username', '').strip().lower()
    verifier_password = request.form.get('verifier_password', '')
    
    verifier = User.query.filter_by(username=verifier_username, is_active=True).first()
    
    if not verifier:
        flash('Invalid username.', 'danger')
        return redirect(url_for('daily_count'))
    
    if not verifier.check_password(verifier_password):
        flash('Invalid password.', 'danger')
        return redirect(url_for('daily_count'))
    
    if verifier.id == count.counted_by:
        flash('Count must be verified by a different person than the one who performed the count.', 'danger')
        return redirect(url_for('daily_count'))
    
    count.verified_by = verifier.id
    count.verified_at = datetime.utcnow()
    
    db.session.commit()
    
    log_audit('verify_count', 'daily_count', count.id, f'Verified daily count by {verifier.full_name}')
    
    flash('Count verified successfully.', 'success')
    return redirect(url_for('daily_count'))


@app.route('/daily-count/<int:id>/resolve', methods=['GET', 'POST'])
@login_required
def resolve_discrepancy(id):
    count = DailyCount.query.get_or_404(id)
    
    if request.method == 'POST':
        resolution_notes = request.form.get('resolution_notes')
        adjust_inventory = request.form.get('adjust_inventory') == 'yes'
        
        count.discrepancy_resolved = True
        count.resolution_notes = resolution_notes
        count.resolved_by = session['user_id']
        count.resolved_at = datetime.utcnow()
        
        if adjust_inventory:
            item = count.inventory_item
            balance_before = item.current_quantity
            item.current_quantity = count.actual_quantity
            
            # Create adjustment transaction
            transaction = Transaction(
                inventory_item_id=item.id,
                transaction_type='adjust',
                quantity=count.discrepancy,
                balance_before=balance_before,
                balance_after=item.current_quantity,
                adjustment_reason=f"Daily count discrepancy resolution: {resolution_notes}",
                performed_by=session['user_id']
            )
            db.session.add(transaction)
        
        db.session.commit()
        
        log_audit('resolve_discrepancy', 'daily_count', count.id,
                 f'Resolved discrepancy: {resolution_notes}')
        
        flash('Discrepancy resolved successfully.', 'success')
        return redirect(url_for('daily_count'))
    
    return render_template('resolve_discrepancy.html', count=count)


# ==================== BIENNIAL INVENTORY ROUTES ====================

@app.route('/biennial-inventory')
@login_required
def biennial_inventory():
    inventories = BiennialInventory.query.order_by(
        BiennialInventory.inventory_date.desc()
    ).all()
    
    # Check when next one is due
    last_complete = BiennialInventory.query.filter_by(is_complete=True).order_by(
        BiennialInventory.inventory_date.desc()
    ).first()
    
    next_due = None
    if last_complete:
        next_due = last_complete.inventory_date + timedelta(days=730)
    
    return render_template('biennial_inventory.html',
                          inventories=inventories,
                          last_complete=last_complete,
                          next_due=next_due)


@app.route('/biennial-inventory/new', methods=['GET', 'POST'])
@provider_required
def new_biennial_inventory():
    if request.method == 'POST':
        inventory_date = datetime.strptime(request.form['inventory_date'], '%Y-%m-%d').date()
        
        # Get registration info
        dea_reg = RegistrationInfo.query.filter_by(
            registration_type='DEA',
            is_active=True
        ).first()
        nc_reg = RegistrationInfo.query.filter_by(
            registration_type='NC-DCU',
            is_active=True
        ).first()
        
        biennial = BiennialInventory(
            inventory_date=inventory_date,
            inventory_time=request.form['inventory_time'],
            dea_registration=dea_reg.registration_number if dea_reg else request.form.get('dea_registration'),
            nc_registration=nc_reg.registration_number if nc_reg else request.form.get('nc_registration'),
            conducted_by=session['user_id'],
            notes=request.form.get('notes')
        )
        db.session.add(biennial)
        db.session.flush()
        
        # Add all current inventory items
        items = InventoryItem.query.join(Medication).filter(
            InventoryItem.is_active == True
        ).all()
        
        for item in items:
            # Schedule II requires exact count
            count_method = 'exact' if item.medication.schedule == 'II' else 'estimated'
            
            biennial_item = BiennialInventoryItem(
                biennial_inventory_id=biennial.id,
                medication_id=item.medication_id,
                inventory_item_id=item.id,
                drug_name=item.medication.name,
                schedule=item.medication.schedule,
                ndc=item.medication.ndc,
                form=item.medication.form,
                strength=item.medication.strength,
                lot_number=item.lot_number,
                expiration_date=item.expiration_date,
                container_opened=(item.current_quantity < item.quantity_received),
                quantity_counted=item.current_quantity,
                unit=item.unit_count,
                count_method=count_method
            )
            db.session.add(biennial_item)
        
        db.session.commit()
        
        log_audit('create_biennial_inventory', 'biennial_inventory', biennial.id,
                 f'Created biennial inventory for {inventory_date}')
        
        flash('Biennial inventory started. Please verify all counts.', 'success')
        return redirect(url_for('edit_biennial_inventory', id=biennial.id))
    
    # Get registration info for defaults
    dea_reg = RegistrationInfo.query.filter_by(
        registration_type='DEA',
        is_active=True
    ).first()
    nc_reg = RegistrationInfo.query.filter_by(
        registration_type='NC-DCU',
        is_active=True
    ).first()
    
    return render_template('new_biennial_inventory.html',
                          dea_reg=dea_reg,
                          nc_reg=nc_reg)


@app.route('/biennial-inventory/<int:id>')
@login_required
def view_biennial_inventory(id):
    inventory = BiennialInventory.query.get_or_404(id)
    
    # Group items by schedule
    schedule_ii = [i for i in inventory.items if i.schedule == 'II']
    other_schedules = [i for i in inventory.items if i.schedule != 'II']
    
    return render_template('view_biennial_inventory.html',
                          inventory=inventory,
                          schedule_ii=schedule_ii,
                          other_schedules=other_schedules)


@app.route('/biennial-inventory/<int:id>/edit', methods=['GET', 'POST'])
@provider_required
def edit_biennial_inventory(id):
    inventory = BiennialInventory.query.get_or_404(id)
    
    if inventory.is_complete:
        flash('This inventory has been completed and cannot be edited.', 'warning')
        return redirect(url_for('view_biennial_inventory', id=id))
    
    if request.method == 'POST':
        # Update individual item counts
        for item in inventory.items:
            field_name = f'count_{item.id}'
            if field_name in request.form:
                item.quantity_counted = float(request.form[field_name])
                item.container_opened = request.form.get(f'opened_{item.id}') == 'yes'
        
        db.session.commit()
        flash('Counts updated.', 'success')
        return redirect(url_for('edit_biennial_inventory', id=id))
    
    schedule_ii = [i for i in inventory.items if i.schedule == 'II']
    other_schedules = [i for i in inventory.items if i.schedule != 'II']
    
    return render_template('edit_biennial_inventory.html',
                          inventory=inventory,
                          schedule_ii=schedule_ii,
                          other_schedules=other_schedules)


@app.route('/biennial-inventory/<int:id>/complete', methods=['POST'])
@provider_required
def complete_biennial_inventory(id):
    inventory = BiennialInventory.query.get_or_404(id)
    
    witness_id = request.form.get('witness_id')
    if witness_id:
        if int(witness_id) == session['user_id']:
            flash('Witness must be a different person.', 'danger')
            return redirect(url_for('edit_biennial_inventory', id=id))
        inventory.witnessed_by = int(witness_id)
    
    inventory.is_complete = True
    inventory.completed_at = datetime.utcnow()
    
    db.session.commit()
    
    log_audit('complete_biennial_inventory', 'biennial_inventory', inventory.id,
             'Completed biennial inventory')
    
    flash('Biennial inventory completed successfully.', 'success')
    return redirect(url_for('view_biennial_inventory', id=id))


@app.route('/biennial-inventory/<int:id>/print')
@login_required
def print_biennial_inventory(id):
    inventory = BiennialInventory.query.get_or_404(id)
    
    schedule_ii = [i for i in inventory.items if i.schedule == 'II']
    other_schedules = [i for i in inventory.items if i.schedule != 'II']
    
    return render_template('print_biennial_inventory.html',
                          inventory=inventory,
                          schedule_ii=schedule_ii,
                          other_schedules=other_schedules)


# ==================== DOCUMENT ROUTES ====================

@app.route('/documents')
@login_required
def documents():
    doc_type = request.args.get('type', '')
    search = request.args.get('search', '')
    
    query = Document.query
    
    if doc_type:
        query = query.filter_by(document_type=doc_type)
    
    if search:
        query = query.filter(
            or_(
                Document.original_filename.ilike(f'%{search}%'),
                Document.reference_number.ilike(f'%{search}%'),
                Document.description.ilike(f'%{search}%')
            )
        )
    
    documents = query.order_by(Document.uploaded_at.desc()).all()
    
    return render_template('documents.html',
                          documents=documents,
                          doc_type=doc_type,
                          search=search)


@app.route('/documents/upload', methods=['GET', 'POST'])
@login_required
def upload_document():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected.', 'danger')
            return redirect(url_for('upload_document'))
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(url_for('upload_document'))
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            
            document_date = None
            if request.form.get('document_date'):
                document_date = datetime.strptime(request.form['document_date'], '%Y-%m-%d').date()
            
            document = Document(
                document_type=request.form['document_type'],
                filename=unique_filename,
                original_filename=filename,
                file_path=file_path,
                file_size=os.path.getsize(file_path),
                mime_type=file.content_type,
                reference_number=request.form.get('reference_number'),
                document_date=document_date,
                description=request.form.get('description'),
                uploaded_by=session['user_id']
            )
            
            db.session.add(document)
            db.session.commit()
            
            log_audit('upload_document', 'document', document.id,
                     f'Uploaded document: {filename}')
            
            flash('Document uploaded successfully.', 'success')
            return redirect(url_for('documents'))
        else:
            flash('File type not allowed.', 'danger')
    
    return render_template('upload_document.html')


@app.route('/documents/<int:id>/view')
@login_required
def view_document(id):
    document = Document.query.get_or_404(id)
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        document.filename,
        as_attachment=False
    )


@app.route('/documents/<int:id>/download')
@login_required
def download_document(id):
    document = Document.query.get_or_404(id)
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        document.filename,
        as_attachment=True,
        download_name=document.original_filename
    )


# ==================== THEFT/LOSS REPORTING ====================

@app.route('/theft-loss')
@login_required
def theft_loss():
    reports = TheftLossReport.query.order_by(
        TheftLossReport.report_date.desc()
    ).all()
    
    return render_template('theft_loss.html', reports=reports)


@app.route('/theft-loss/new', methods=['GET', 'POST'])
@provider_required
def new_theft_loss():
    if request.method == 'POST':
        discovery_date = datetime.strptime(request.form['discovery_date'], '%Y-%m-%d').date()
        
        report = TheftLossReport(
            discovery_date=discovery_date,
            report_type=request.form['report_type'],
            medication_id=request.form['medication_id'],
            inventory_item_id=request.form.get('inventory_item_id') or None,
            quantity_lost=float(request.form['quantity_lost']),
            circumstances=request.form['circumstances'],
            police_notified=request.form.get('police_notified') == 'yes',
            police_report_number=request.form.get('police_report_number'),
            reported_by=session['user_id']
        )
        
        db.session.add(report)
        db.session.commit()
        
        log_audit('theft_loss_report', 'theft_loss_report', report.id,
                 f'Created {report.report_type} report for {report.quantity_lost} units')
        
        # Alert message
        flash(f'''⚠️ {report.report_type.upper()} REPORT CREATED
        
        IMPORTANT: DEA regulations require notification within 1 business day.
        1. Submit DEA Form 106 online at: https://apps.deadiversion.usdoj.gov/TLROnline/
        2. Notify NC-DCU at NCCSAREG@dhhs.nc.gov
        3. Contact local law enforcement if theft is suspected
        ''', 'warning')
        
        return redirect(url_for('theft_loss'))
    
    medications = Medication.query.filter_by(is_active=True).order_by(Medication.name).all()
    inventory_items = InventoryItem.query.filter(
        InventoryItem.is_active == True,
        InventoryItem.current_quantity > 0
    ).all()
    
    return render_template('new_theft_loss.html',
                          medications=medications,
                          inventory_items=inventory_items)


@app.route('/theft-loss/<int:id>/update', methods=['POST'])
@provider_required
def update_theft_loss(id):
    report = TheftLossReport.query.get_or_404(id)
    
    if request.form.get('dea_notified') == 'yes':
        report.dea_notified = True
        report.dea_notification_date = datetime.now().date()
    
    if request.form.get('dea_form_106_submitted') == 'yes':
        report.dea_form_106_submitted = True
    
    if request.form.get('nc_dcu_notified') == 'yes':
        report.nc_dcu_notified = True
    
    db.session.commit()
    
    log_audit('update_theft_loss', 'theft_loss_report', report.id, 'Updated report status')
    
    flash('Report updated.', 'success')
    return redirect(url_for('theft_loss'))


# ==================== REPORTS ====================

@app.route('/reports')
@login_required
def reports():
    # Calculate stats for last 30 days
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    
    total_transactions = Transaction.query.filter(
        Transaction.performed_at >= thirty_days_ago
    ).count()
    
    total_dispensed = db.session.query(func.sum(Transaction.quantity)).filter(
        Transaction.transaction_type == 'dispense',
        Transaction.performed_at >= thirty_days_ago
    ).scalar() or 0
    
    total_wasted = db.session.query(func.sum(Transaction.quantity)).filter(
        Transaction.transaction_type == 'waste',
        Transaction.performed_at >= thirty_days_ago
    ).scalar() or 0
    
    daily_counts = DailyCount.query.filter(
        DailyCount.count_date >= thirty_days_ago.date()
    ).count()
    
    discrepancies = DailyCount.query.filter(
        DailyCount.count_date >= thirty_days_ago.date(),
        DailyCount.discrepancy != 0
    ).count()
    
    stats = {
        'total_transactions': total_transactions,
        'total_dispensed': int(total_dispensed),
        'total_wasted': int(total_wasted),
        'daily_counts': daily_counts,
        'discrepancies': discrepancies
    }
    
    return render_template('reports.html', stats=stats)


@app.route('/reports/usage')
@login_required
def usage_report():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    medication_id = request.args.get('medication_id')
    
    query = Transaction.query.join(InventoryItem).join(Medication)
    
    if start_date:
        start = datetime.strptime(start_date, '%Y-%m-%d')
        query = query.filter(Transaction.performed_at >= start)
    
    if end_date:
        end = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
        query = query.filter(Transaction.performed_at < end)
    
    if medication_id:
        query = query.filter(Medication.id == medication_id)
    
    transactions = query.order_by(Transaction.performed_at.desc()).all()
    
    # Summary by medication
    summary = db.session.query(
        Medication.name,
        Medication.schedule,
        Transaction.transaction_type,
        func.sum(Transaction.quantity).label('total_quantity'),
        func.count(Transaction.id).label('count')
    ).join(InventoryItem, Transaction.inventory_item_id == InventoryItem.id
    ).join(Medication, InventoryItem.medication_id == Medication.id)
    
    if start_date:
        summary = summary.filter(Transaction.performed_at >= start)
    if end_date:
        summary = summary.filter(Transaction.performed_at < end)
    if medication_id:
        summary = summary.filter(Medication.id == medication_id)
    
    summary = summary.group_by(
        Medication.name,
        Medication.schedule,
        Transaction.transaction_type
    ).all()
    
    medications = Medication.query.filter_by(is_active=True).order_by(Medication.name).all()
    
    return render_template('usage_report.html',
                          transactions=transactions,
                          summary=summary,
                          medications=medications,
                          start_date=start_date,
                          end_date=end_date,
                          medication_id=medication_id)


@app.route('/reports/audit-log')
@admin_required
def audit_log():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    user_id = request.args.get('user_id')
    action = request.args.get('action')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    query = AuditLog.query
    
    if user_id:
        query = query.filter_by(user_id=user_id)
    if action:
        query = query.filter(AuditLog.action.ilike(f'%{action}%'))
    if start_date:
        start = datetime.strptime(start_date, '%Y-%m-%d')
        query = query.filter(AuditLog.timestamp >= start)
    if end_date:
        end = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
        query = query.filter(AuditLog.timestamp < end)
    
    logs = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    users = User.query.order_by(User.full_name).all()
    
    return render_template('audit_log.html',
                          logs=logs,
                          users=users,
                          user_id=user_id,
                          action=action,
                          start_date=start_date,
                          end_date=end_date)


@app.route('/reports/discrepancy')
@login_required
def discrepancy_report():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    show_resolved = request.args.get('show_resolved', 'false') == 'true'
    
    query = DailyCount.query.filter(DailyCount.discrepancy != 0)
    
    if not show_resolved:
        query = query.filter_by(discrepancy_resolved=False)
    
    if start_date:
        start = datetime.strptime(start_date, '%Y-%m-%d').date()
        query = query.filter(DailyCount.count_date >= start)
    
    if end_date:
        end = datetime.strptime(end_date, '%Y-%m-%d').date()
        query = query.filter(DailyCount.count_date <= end)
    
    discrepancies = query.order_by(DailyCount.count_date.desc()).all()
    
    return render_template('discrepancy_report.html',
                          discrepancies=discrepancies,
                          start_date=start_date,
                          end_date=end_date,
                          show_resolved=show_resolved)


# ==================== SETTINGS/ADMIN ====================

@app.route('/settings')
@admin_required
def settings():
    users = User.query.order_by(User.full_name).all()
    registrations = RegistrationInfo.query.order_by(RegistrationInfo.expiration_date).all()
    
    # Get or create default settings
    settings_data = {
        'practice_name': 'Magnolia Health PLLC',
        'practice_address': '',
        'practice_phone': '',
        'practice_fax': '',
        'low_inventory_threshold': 10,
        'expiration_warning_days': 90,
        'require_daily_counts': True,
        'require_dual_verification': True
    }
    
    return render_template('settings.html', 
                          settings=settings_data, 
                          users=users, 
                          registrations=registrations)


@app.route('/settings/practice', methods=['POST'])
@admin_required
def update_practice_info():
    # In a real implementation, this would save to database or config
    flash('Practice information updated.', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/logo', methods=['POST'])
@admin_required
def upload_logo():
    if 'logo' not in request.files:
        flash('No file selected.', 'danger')
        return redirect(url_for('settings'))
    
    file = request.files['logo']
    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('settings'))
    
    # Check file extension
    allowed_ext = {'png', 'jpg', 'jpeg', 'gif'}
    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    
    if ext not in allowed_ext:
        flash('Invalid file type. Please upload a PNG, JPG, or GIF image.', 'danger')
        return redirect(url_for('settings'))
    
    # Remove old logo files
    for old_ext in allowed_ext:
        old_file = os.path.join(LOGO_FOLDER, f'logo.{old_ext}')
        if os.path.exists(old_file):
            os.remove(old_file)
    
    # Save new logo
    filename = f'logo.{ext}'
    file.save(os.path.join(LOGO_FOLDER, filename))
    
    log_audit('upload_logo', 'settings', None, 'Uploaded new practice logo')
    flash('Logo uploaded successfully.', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/logo/remove', methods=['POST'])
@admin_required
def remove_logo():
    # Remove all logo files
    for ext in ['png', 'jpg', 'jpeg', 'gif']:
        logo_file = os.path.join(LOGO_FOLDER, f'logo.{ext}')
        if os.path.exists(logo_file):
            os.remove(logo_file)
    
    log_audit('remove_logo', 'settings', None, 'Removed practice logo')
    flash('Logo removed.', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/system', methods=['POST'])
@admin_required
def update_system_settings():
    # In a real implementation, this would save to database or config
    flash('System settings updated.', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/users/<int:id>/toggle', methods=['POST'])
@admin_required
def toggle_user(id):
    user = User.query.get_or_404(id)
    if user.id == session.get('user_id'):
        flash('You cannot deactivate your own account.', 'danger')
        return redirect(url_for('manage_users'))
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'activated' if user.is_active else 'deactivated'
    log_audit(f'user_{status}', 'user', user.id, f'{status.title()} user: {user.username}')
    flash(f'User {user.full_name} has been {status}.', 'success')
    return redirect(url_for('manage_users'))


@app.route('/settings/export-all')
@admin_required
def export_all_data():
    # Export complete database backup as JSON
    import json
    from io import BytesIO
    
    data = {
        'exported_at': datetime.utcnow().isoformat(),
        'medications': [{'id': m.id, 'name': m.name, 'schedule': m.schedule, 
                        'ndc': m.ndc, 'strength': m.strength} 
                       for m in Medication.query.all()],
        'inventory': [{'id': i.id, 'medication_id': i.medication_id,
                      'lot_number': i.lot_number, 'current_quantity': i.current_quantity}
                     for i in InventoryItem.query.all()],
        'transactions': [{'id': t.id, 'type': t.transaction_type, 
                         'quantity': t.quantity, 'date': t.performed_at.isoformat()}
                        for t in Transaction.query.all()]
    }
    
    output = BytesIO()
    output.write(json.dumps(data, indent=2).encode())
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename=cs_inventory_backup.json'}
    )


@app.route('/settings/reset-demo', methods=['POST'])
@admin_required
def reset_demo_data():
    # Clear transactions, counts, and documents
    Transaction.query.delete()
    DailyCount.query.delete()
    BiennialInventoryItem.query.delete()
    BiennialInventory.query.delete()
    Document.query.delete()
    TheftLossReport.query.delete()
    
    # Reset inventory quantities to 0
    InventoryItem.query.update({'current_quantity': 0})
    
    db.session.commit()
    
    log_audit('reset_demo_data', 'system', None, 'Demo data reset performed')
    flash('All transactions, counts, and documents have been cleared.', 'warning')
    return redirect(url_for('settings'))


@app.route('/reports/export')
@login_required
def export_report():
    report_type = request.args.get('type', 'transactions')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    format_type = request.args.get('format', 'csv')
    
    # Build query based on report type
    if report_type == 'transactions':
        query = Transaction.query.join(InventoryItem).join(Medication)
        if start_date:
            query = query.filter(Transaction.performed_at >= datetime.strptime(start_date, '%Y-%m-%d'))
        if end_date:
            query = query.filter(Transaction.performed_at < datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1))
        
        data = [['Date', 'Type', 'Medication', 'Quantity', 'User']]
        for t in query.all():
            data.append([
                t.performed_at.strftime('%Y-%m-%d %H:%M'),
                t.transaction_type,
                t.inventory_item.medication.name,
                t.quantity,
                t.performer.full_name if t.performer else 'Unknown'
            ])
    elif report_type == 'inventory':
        data = [['Medication', 'Schedule', 'Lot', 'Quantity', 'Expiration']]
        for i in InventoryItem.query.filter(InventoryItem.current_quantity > 0).all():
            data.append([
                i.medication.name,
                i.medication.schedule,
                i.lot_number or 'N/A',
                i.current_quantity,
                i.expiration_date.strftime('%Y-%m-%d') if i.expiration_date else 'N/A'
            ])
    else:
        data = [['No data']]
    
    # Generate CSV
    import csv
    from io import StringIO
    
    output = StringIO()
    writer = csv.writer(output)
    for row in data:
        writer.writerow(row)
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={report_type}_report.csv'}
    )


@app.route('/settings/users')
@admin_required
def manage_users():
    users = User.query.order_by(User.full_name).all()
    return render_template('manage_users.html', users=users)


@app.route('/settings/users/add', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('add_user'))
        
        user = User(
            username=username,
            full_name=request.form['full_name'],
            role=request.form['role'],
            credentials=request.form.get('credentials'),
            dea_number=request.form.get('dea_number')
        )
        user.set_password(request.form['password'])
        
        db.session.add(user)
        db.session.commit()
        
        log_audit('add_user', 'user', user.id, f'Created user: {user.username}')
        
        flash(f'User "{user.full_name}" created successfully.', 'success')
        return redirect(url_for('manage_users'))
    
    return render_template('user_form.html', user=None)


@app.route('/settings/users/<int:id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_user(id):
    user = User.query.get_or_404(id)
    
    if request.method == 'POST':
        user.full_name = request.form['full_name']
        user.role = request.form['role']
        user.credentials = request.form.get('credentials')
        user.dea_number = request.form.get('dea_number')
        user.is_active = request.form.get('is_active') == 'yes'
        
        if request.form.get('new_password'):
            user.set_password(request.form['new_password'])
        
        db.session.commit()
        
        log_audit('edit_user', 'user', user.id, f'Updated user: {user.username}')
        
        flash(f'User "{user.full_name}" updated successfully.', 'success')
        return redirect(url_for('manage_users'))
    
    return render_template('user_form.html', user=user)


@app.route('/settings/registrations')
@admin_required
def manage_registrations():
    registrations = RegistrationInfo.query.order_by(
        RegistrationInfo.registration_type,
        RegistrationInfo.expiration_date
    ).all()
    return render_template('manage_registrations.html', registrations=registrations)


@app.route('/settings/registrations/add', methods=['GET', 'POST'])
@admin_required
def add_registration():
    if request.method == 'POST':
        issue_date = None
        if request.form.get('issue_date'):
            issue_date = datetime.strptime(request.form['issue_date'], '%Y-%m-%d').date()
        
        expiration_date = None
        if request.form.get('expiration_date'):
            expiration_date = datetime.strptime(request.form['expiration_date'], '%Y-%m-%d').date()
        
        registration = RegistrationInfo(
            registration_type=request.form['registration_type'],
            registration_number=request.form['registration_number'],
            registrant_name=request.form.get('registrant_name'),
            business_name=request.form.get('business_name'),
            address=request.form.get('address'),
            issue_date=issue_date,
            expiration_date=expiration_date,
            schedules_authorized=request.form.get('schedules_authorized'),
            notes=request.form.get('notes')
        )
        
        db.session.add(registration)
        db.session.commit()
        
        log_audit('add_registration', 'registration', registration.id,
                 f'Added {registration.registration_type} registration')
        
        flash('Registration added successfully.', 'success')
        return redirect(url_for('manage_registrations'))
    
    return render_template('registration_form.html', registration=None)


@app.route('/settings/registrations/<int:id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_registration(id):
    registration = RegistrationInfo.query.get_or_404(id)
    
    if request.method == 'POST':
        registration.registration_number = request.form['registration_number']
        registration.registrant_name = request.form.get('registrant_name')
        registration.business_name = request.form.get('business_name')
        registration.address = request.form.get('address')
        registration.schedules_authorized = request.form.get('schedules_authorized')
        registration.is_active = request.form.get('is_active') == 'yes'
        registration.notes = request.form.get('notes')
        
        if request.form.get('issue_date'):
            registration.issue_date = datetime.strptime(request.form['issue_date'], '%Y-%m-%d').date()
        if request.form.get('expiration_date'):
            registration.expiration_date = datetime.strptime(request.form['expiration_date'], '%Y-%m-%d').date()
        
        db.session.commit()
        
        log_audit('edit_registration', 'registration', registration.id, 'Updated registration')
        
        flash('Registration updated successfully.', 'success')
        return redirect(url_for('manage_registrations'))
    
    return render_template('registration_form.html', registration=registration)


# ==================== API ENDPOINTS ====================

@app.route('/api/inventory/<int:id>')
@login_required
def api_inventory_item(id):
    item = InventoryItem.query.get_or_404(id)
    return jsonify({
        'id': item.id,
        'medication_name': item.medication.name,
        'schedule': item.medication.schedule,
        'current_quantity': item.current_quantity,
        'lot_number': item.lot_number,
        'expiration_date': item.expiration_date.isoformat() if item.expiration_date else None
    })


@app.route('/api/medications/<int:id>/inventory')
@login_required
def api_medication_inventory(id):
    items = InventoryItem.query.filter(
        InventoryItem.medication_id == id,
        InventoryItem.is_active == True,
        InventoryItem.current_quantity > 0
    ).all()
    
    return jsonify([{
        'id': item.id,
        'lot_number': item.lot_number,
        'current_quantity': item.current_quantity,
        'expiration_date': item.expiration_date.isoformat() if item.expiration_date else None
    } for item in items])


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', 
                          error_code=404,
                          error_message='Page not found'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html',
                          error_code=500,
                          error_message='Internal server error'), 500


# ==================== DATABASE INITIALIZATION ====================

def init_db():
    """Initialize database with default admin user"""
    with app.app_context():
        db.create_all()
        
        # Check if admin exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                full_name='System Administrator',
                role='admin'
            )
            admin.set_password('changeme123')  # CHANGE THIS IN PRODUCTION
            db.session.add(admin)
            db.session.commit()
            print("Default admin user created. Username: admin, Password: changeme123")
            print("⚠️  IMPORTANT: Change this password immediately!")


# Initialize database on startup (needed for Railway/Gunicorn)
init_db()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
