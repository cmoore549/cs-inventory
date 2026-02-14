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
from zoneinfo import ZoneInfo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import (Flask, render_template, request, redirect, url_for, flash,
                   session, jsonify, send_from_directory, abort, Response)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, and_, or_

# Timezone configuration
TIMEZONE = ZoneInfo(os.environ.get('TZ', 'America/New_York'))

def get_current_time():
    """Get current time in configured timezone"""
    return datetime.now(TIMEZONE)

def get_current_date():
    """Get current date in configured timezone"""
    return datetime.now(TIMEZONE).date()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Database configuration - use PostgreSQL if DATABASE_URL is set, otherwise SQLite
database_url = os.environ.get('DATABASE_URL')
if database_url:
    # Railway uses postgres:// but SQLAlchemy needs postgresql://
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
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

def validate_dea_number(dea):
    """Basic DEA number format validation"""
    if not dea or len(dea) != 9:
        return False
    # DEA format: 2 letters + 6 digits + check digit
    if not dea[0].isalpha() or not dea[1].isalpha():
        return False
    if not dea[2:8].isdigit():
        return False
    # Checksum validation
    try:
        digits = [int(d) for d in dea[2:9]]
        checksum = (digits[0] + digits[2] + digits[4] + 
                   2 * (digits[1] + digits[3] + digits[5])) % 10
        return checksum == digits[6]
    except:
        return False


class User(db.Model):
    """User accounts with role-based access"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin, provider, staff
    credentials = db.Column(db.String(50))  # NP-C, PA-C, RN, etc.
    dea_number = db.Column(db.String(20))
    dea_expiration = db.Column(db.Date)  # DEA registration expiration
    can_prescribe_schedule_2 = db.Column(db.Boolean, default=False)  # Schedule II prescribing authority
    state_license = db.Column(db.String(30))  # State license number
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @property
    def dea_is_valid(self):
        """Check if DEA registration is valid"""
        if not self.dea_number:
            return False
        if self.dea_expiration and self.dea_expiration < get_current_date():
            return False
        return validate_dea_number(self.dea_number)
    
    def can_prescribe(self, schedule):
        """Check if user can prescribe a given schedule"""
        if self.role not in ['admin', 'provider']:
            return False
        if not self.dea_is_valid:
            return False
        if schedule == 'II' and not self.can_prescribe_schedule_2:
            return False
        return True


class Patient(db.Model):
    """Patient database for controlled substance tracking"""
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(60), nullable=False)
    last_name = db.Column(db.String(60), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    mrn = db.Column(db.String(50), unique=True)  # Medical Record Number
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    address = db.Column(db.String(200))
    city = db.Column(db.String(60))
    state = db.Column(db.String(2))
    zip_code = db.Column(db.String(10))
    insurance_id = db.Column(db.String(50))
    notes = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by])
    
    @property
    def full_name(self):
        return f"{self.last_name}, {self.first_name}"
    
    @property
    def full_name_display(self):
        return f"{self.first_name} {self.last_name}"


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
    low_stock_threshold = db.Column(db.Integer, default=10)  # Alert when total inventory falls below this
    reorder_point = db.Column(db.Integer)  # Trigger reorder alert when below this
    reorder_quantity = db.Column(db.Integer)  # Suggested quantity to reorder
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    inventory_items = db.relationship('InventoryItem', backref='medication', lazy='dynamic')
    
    @property
    def total_quantity(self):
        """Get total quantity across all active inventory items"""
        return db.session.query(func.sum(InventoryItem.current_quantity)).filter(
            InventoryItem.medication_id == self.id,
            InventoryItem.is_active == True,
            InventoryItem.current_quantity > 0
        ).scalar() or 0
    
    @property
    def is_low_stock(self):
        """Check if medication is below low stock threshold"""
        if self.low_stock_threshold is None:
            return False
        return self.total_quantity < self.low_stock_threshold
    
    @property
    def needs_reorder(self):
        """Check if medication needs to be reordered"""
        if self.reorder_point is None:
            return False
        return self.total_quantity <= self.reorder_point


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
    supplier = db.Column(db.String(100))  # Legacy text field
    supplier_id = db.Column(db.Integer)  # Link to Supplier table (no FK constraint for compatibility)
    invoice_number = db.Column(db.String(50))
    form222_id = db.Column(db.Integer)  # For Schedule II (no FK constraint for compatibility)
    acquisition_document_id = db.Column(db.Integer, db.ForeignKey('document.id'))
    storage_location = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    is_quarantined = db.Column(db.Boolean, default=False)  # For expired/recalled items
    quarantine_reason = db.Column(db.String(200))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    acquisition_document = db.relationship('Document', foreign_keys=[acquisition_document_id], lazy='select')
    receiver = db.relationship('User', foreign_keys=[received_by], lazy='select')
    
    @property
    def is_expired(self):
        if not self.expiration_date:
            return False
        return self.expiration_date < get_current_date()
    
    @property
    def days_until_expiration(self):
        if not self.expiration_date:
            return 999
        return (self.expiration_date - get_current_date()).days
    
    @property
    def is_available(self):
        """Check if item is available for dispensing"""
        return (self.is_active and 
                not self.is_quarantined and 
                not self.is_expired and 
                self.current_quantity > 0)


class Transaction(db.Model):
    """All transactions: dispensing, wasting, adjustments, transfers"""
    id = db.Column(db.Integer, primary_key=True)
    inventory_item_id = db.Column(db.Integer, db.ForeignKey('inventory_item.id'), nullable=False)
    transaction_type = db.Column(db.String(20), nullable=False)  # dispense, waste, adjust, return, transfer
    quantity = db.Column(db.Float, nullable=False)
    balance_before = db.Column(db.Float, nullable=False)
    balance_after = db.Column(db.Float, nullable=False)
    
    # For dispensing - link to patient database
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'))
    patient_name = db.Column(db.String(120))  # Keep for backwards compatibility
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
    patient = db.relationship('Patient', backref='transactions', lazy='select')
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


class DismissedAlert(db.Model):
    """Track dismissed alerts per user"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    alert_type = db.Column(db.String(50), nullable=False)  # biennial_due, registration_expiring_X
    alert_key = db.Column(db.String(100))  # For specific alerts like registration ID
    dismissed_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Store when the alert condition was true - if condition changes and comes back, re-show
    condition_value = db.Column(db.String(100))  # e.g., last biennial date or registration expiration date
    
    user = db.relationship('User', backref='dismissed_alerts')


class PatientMedication(db.Model):
    """Patient-specific controlled substance inventory"""
    id = db.Column(db.Integer, primary_key=True)
    
    # Patient Information - link to patient database
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'))
    patient_name = db.Column(db.String(120), nullable=False)  # Keep for backwards compatibility
    patient_dob = db.Column(db.Date, nullable=False)
    patient_mrn = db.Column(db.String(50))
    patient_phone = db.Column(db.String(20))
    
    # Medication Information
    medication_id = db.Column(db.Integer, db.ForeignKey('medication.id'), nullable=False)
    source_inventory_id = db.Column(db.Integer, db.ForeignKey('inventory_item.id'))  # Where it came from
    
    # Preparation Details
    preparation_date = db.Column(db.Date, nullable=False)
    prepared_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    lot_number = db.Column(db.String(50))
    expiration_date = db.Column(db.Date)
    
    # Quantity Tracking
    quantity_prepared = db.Column(db.Float, nullable=False)
    quantity_remaining = db.Column(db.Float, nullable=False)
    unit = db.Column(db.String(20))  # ml, mg, doses, etc.
    
    # Prescriber
    prescriber_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    prescription_number = db.Column(db.String(50))
    
    # Status
    status = db.Column(db.String(20), default='active')  # active, completed, expired, destroyed
    storage_location = db.Column(db.String(100))
    notes = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    patient = db.relationship('Patient', backref='patient_medications', lazy='select')
    medication = db.relationship('Medication', backref='patient_medications')
    source_inventory = db.relationship('InventoryItem', backref='patient_preparations')
    preparer = db.relationship('User', foreign_keys=[prepared_by], backref='preparations_made')
    prescriber = db.relationship('User', foreign_keys=[prescriber_id], backref='patient_prescriptions')
    
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


class PatientMedicationLog(db.Model):
    """Log of administrations/dispensing from patient-specific inventory"""
    id = db.Column(db.Integer, primary_key=True)
    patient_medication_id = db.Column(db.Integer, db.ForeignKey('patient_medication.id'), nullable=False)
    
    log_type = db.Column(db.String(20), nullable=False)  # administered, wasted, destroyed, returned
    quantity = db.Column(db.Float, nullable=False)
    quantity_before = db.Column(db.Float, nullable=False)
    quantity_after = db.Column(db.Float, nullable=False)
    
    administered_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    witness_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    administration_date = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)
    waste_reason = db.Column(db.String(200))
    
    # Relationships
    patient_medication = db.relationship('PatientMedication', backref='logs')
    administrator = db.relationship('User', foreign_keys=[administered_by])
    witness = db.relationship('User', foreign_keys=[witness_id])


class Supplier(db.Model):
    """Authorized controlled substance suppliers/distributors"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    dea_number = db.Column(db.String(20))  # Optional - not all suppliers need DEA
    address = db.Column(db.String(200))
    city = db.Column(db.String(60))
    state = db.Column(db.String(2))
    zip_code = db.Column(db.String(10))
    phone = db.Column(db.String(20))
    fax = db.Column(db.String(20))
    email = db.Column(db.String(120))
    contact_name = db.Column(db.String(100))
    account_number = db.Column(db.String(50))
    notes = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by])
    
    @staticmethod
    def validate_dea_number(dea):
        """Basic DEA number format validation - wrapper for standalone function"""
        return validate_dea_number(dea)


class Form222(db.Model):
    """DEA Form 222 tracking for Schedule II substances"""
    id = db.Column(db.Integer, primary_key=True)
    form_number = db.Column(db.String(20), nullable=False, unique=True)
    supplier_id = db.Column(db.Integer, db.ForeignKey('supplier.id'))
    
    # Form details
    order_date = db.Column(db.Date, nullable=False)
    received_date = db.Column(db.Date)
    
    # Status: pending, partial, complete, void
    status = db.Column(db.String(20), default='pending')
    
    # Related inventory receipts
    notes = db.Column(db.Text)
    voided_reason = db.Column(db.String(200))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    supplier = db.relationship('Supplier', backref='form222s')
    creator = db.relationship('User', foreign_keys=[created_by])
    line_items = db.relationship('Form222LineItem', backref='form222', cascade='all, delete-orphan')


class Form222LineItem(db.Model):
    """Line items on DEA Form 222"""
    id = db.Column(db.Integer, primary_key=True)
    form222_id = db.Column(db.Integer, db.ForeignKey('form222.id'), nullable=False)
    line_number = db.Column(db.Integer, nullable=False)
    
    medication_id = db.Column(db.Integer, db.ForeignKey('medication.id'), nullable=False)
    quantity_ordered = db.Column(db.Float, nullable=False)
    quantity_received = db.Column(db.Float, default=0)
    
    # Link to inventory item when received
    inventory_item_id = db.Column(db.Integer, db.ForeignKey('inventory_item.id'))
    
    # Relationships
    medication = db.relationship('Medication')
    inventory_item = db.relationship('InventoryItem')


class ReorderAlert(db.Model):
    """Reorder points and alerts for medications"""
    id = db.Column(db.Integer, primary_key=True)
    medication_id = db.Column(db.Integer, db.ForeignKey('medication.id'), nullable=False, unique=True)
    
    min_quantity = db.Column(db.Float, nullable=False)  # Reorder when below this
    max_quantity = db.Column(db.Float)  # Target stock level
    reorder_quantity = db.Column(db.Float)  # Suggested order quantity
    
    preferred_supplier_id = db.Column(db.Integer)  # No FK constraint for compatibility
    
    # Pending order tracking
    pending_order = db.Column(db.Boolean, default=False)
    pending_order_date = db.Column(db.Date)
    pending_order_quantity = db.Column(db.Float)
    
    notes = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    medication = db.relationship('Medication', backref='reorder_alert', uselist=False)


class PhysicalInventory(db.Model):
    """Periodic physical inventory counts (beyond daily counts)"""
    id = db.Column(db.Integer, primary_key=True)
    
    inventory_date = db.Column(db.Date, nullable=False)
    inventory_type = db.Column(db.String(20), nullable=False)  # full, schedule2, spot_check
    
    status = db.Column(db.String(20), default='in_progress')  # in_progress, completed, reviewed
    
    started_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    completed_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    completed_at = db.Column(db.DateTime)
    
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    reviewed_at = db.Column(db.DateTime)
    
    notes = db.Column(db.Text)
    
    # Relationships
    starter = db.relationship('User', foreign_keys=[started_by])
    completer = db.relationship('User', foreign_keys=[completed_by])
    reviewer = db.relationship('User', foreign_keys=[reviewed_by])
    count_items = db.relationship('PhysicalInventoryItem', backref='physical_inventory', cascade='all, delete-orphan')
    
    @property
    def total_items(self):
        return len(self.count_items)
    
    @property
    def counted_items(self):
        return len([i for i in self.count_items if i.actual_quantity is not None])
    
    @property
    def discrepancy_count(self):
        return len([i for i in self.count_items if i.actual_quantity is not None and i.discrepancy != 0])


class PhysicalInventoryItem(db.Model):
    """Individual item counts in a physical inventory"""
    id = db.Column(db.Integer, primary_key=True)
    physical_inventory_id = db.Column(db.Integer, db.ForeignKey('physical_inventory.id'), nullable=False)
    inventory_item_id = db.Column(db.Integer, db.ForeignKey('inventory_item.id'), nullable=False)
    
    expected_quantity = db.Column(db.Float, nullable=False)
    actual_quantity = db.Column(db.Float)
    
    counted_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    counted_at = db.Column(db.DateTime)
    
    discrepancy_notes = db.Column(db.Text)
    discrepancy_resolved = db.Column(db.Boolean, default=False)
    resolution_notes = db.Column(db.Text)
    
    # Relationships
    inventory_item = db.relationship('InventoryItem')
    counter = db.relationship('User', foreign_keys=[counted_by])
    
    @property
    def discrepancy(self):
        if self.actual_quantity is None:
            return 0
        return self.actual_quantity - self.expected_quantity


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
    pending_counts = 0
    expiring_soon = 0
    
    try:
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
        
        # Get pending items for alerts
        if user:
            # Get unverified daily counts from today
            today = get_current_date()
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
    except Exception as e:
        # Handle database errors gracefully during startup/migration
        print(f"Context processor error (may be normal during migration): {e}")
    
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
        now=get_current_time(),
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
    today = get_current_date()
    user_id = session.get('user_id')
    
    # Initialize all variables with defaults
    total_medications = 0
    total_inventory_items = 0
    todays_transactions = 0
    todays_counts = 0
    pending_verifications = []
    unresolved_discrepancies = []
    expiring_items = []
    low_inventory_meds = []
    recent_transactions = []
    last_biennial = None
    biennial_due = False
    days_until_biennial = 0
    biennial_condition_value = "none"
    show_biennial_alert = False
    expiring_registrations = []
    
    try:
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
        
        # Low inventory - check each medication against its threshold
        active_meds = Medication.query.filter_by(is_active=True).all()
        for med in active_meds:
            if med.is_low_stock:
                low_inventory_meds.append({
                    'medication': med,
                    'total_quantity': med.total_quantity,
                    'threshold': med.low_stock_threshold
                })
        
        # Recent transactions
        recent_transactions = Transaction.query.order_by(
            Transaction.performed_at.desc()
        ).limit(10).all()
        
        # Check biennial inventory status
        last_biennial = BiennialInventory.query.filter_by(is_complete=True).order_by(
            BiennialInventory.inventory_date.desc()
        ).first()
        
        biennial_due = True
        if last_biennial:
            next_biennial = last_biennial.inventory_date + timedelta(days=730)  # 2 years
            days_until_biennial = (next_biennial - today).days
            biennial_due = days_until_biennial <= 30
            biennial_condition_value = last_biennial.inventory_date.isoformat()
        
        # Check if biennial alert was dismissed for this condition
        show_biennial_alert = biennial_due
        if biennial_due:
            dismissed = DismissedAlert.query.filter_by(
                user_id=user_id,
                alert_type='biennial_due',
                condition_value=biennial_condition_value
            ).first()
            if dismissed:
                show_biennial_alert = False
        
        # Registration expiration check
        registrations = RegistrationInfo.query.filter_by(is_active=True).all()
        for r in registrations:
            if r.expiration_date and (r.expiration_date - today).days <= 60:
                # Check if this alert was dismissed
                condition_value = r.expiration_date.isoformat()
                dismissed = DismissedAlert.query.filter_by(
                    user_id=user_id,
                    alert_type='registration_expiring',
                    alert_key=str(r.id),
                    condition_value=condition_value
                ).first()
                if not dismissed:
                    expiring_registrations.append(r)
    except Exception as e:
        print(f"Dashboard error: {e}")
        flash('Some dashboard data could not be loaded.', 'warning')
    
    return render_template('dashboard.html',
                          total_medications=total_medications,
                          total_inventory_items=total_inventory_items,
                          todays_transactions=todays_transactions,
                          todays_counts=todays_counts,
                          pending_verifications=pending_verifications,
                          unresolved_discrepancies=unresolved_discrepancies,
                          expiring_items=expiring_items,
                          low_inventory_meds=low_inventory_meds,
                          recent_transactions=recent_transactions,
                          biennial_due=show_biennial_alert,
                          days_until_biennial=days_until_biennial,
                          last_biennial=last_biennial,
                          biennial_condition_value=biennial_condition_value,
                          expiring_registrations=expiring_registrations)


@app.route('/dismiss-alert', methods=['POST'])
@login_required
def dismiss_alert():
    """Dismiss an alert for the current user"""
    alert_type = request.form.get('alert_type')
    alert_key = request.form.get('alert_key', '')
    condition_value = request.form.get('condition_value', '')
    
    user_id = session.get('user_id')
    
    # Check if already dismissed
    existing = DismissedAlert.query.filter_by(
        user_id=user_id,
        alert_type=alert_type,
        alert_key=alert_key,
        condition_value=condition_value
    ).first()
    
    if not existing:
        dismissed = DismissedAlert(
            user_id=user_id,
            alert_type=alert_type,
            alert_key=alert_key,
            condition_value=condition_value
        )
        db.session.add(dismissed)
        db.session.commit()
        log_audit('dismiss_alert', 'alert', None, f'Dismissed {alert_type} alert')
    
    flash('Alert dismissed. It will reappear if conditions change.', 'info')
    return redirect(url_for('dashboard'))


@app.route('/restore-alerts', methods=['POST'])
@login_required
def restore_alerts():
    """Restore all dismissed alerts for the current user"""
    user_id = session.get('user_id')
    DismissedAlert.query.filter_by(user_id=user_id).delete()
    db.session.commit()
    log_audit('restore_alerts', 'alert', None, 'Restored all dismissed alerts')
    flash('All alerts restored.', 'success')
    return redirect(url_for('dashboard'))


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
        # Parse low stock threshold
        low_stock = request.form.get('low_stock_threshold', '10')
        low_stock_threshold = int(low_stock) if low_stock and low_stock.strip() else 10
        
        medication = Medication(
            name=request.form['name'],
            generic_name=request.form.get('generic_name'),
            schedule=request.form['schedule'],
            ndc=request.form.get('ndc'),
            form=request.form.get('form'),
            strength=request.form.get('strength'),
            unit=request.form.get('unit'),
            manufacturer=request.form.get('manufacturer'),
            low_stock_threshold=low_stock_threshold,
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
        
        # Parse low stock threshold
        low_stock = request.form.get('low_stock_threshold', '10')
        medication.low_stock_threshold = int(low_stock) if low_stock and low_stock.strip() else 10
        
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
        
        # Handle supplier - either from dropdown or typed in
        supplier_id = request.form.get('supplier_id')
        supplier_id = int(supplier_id) if supplier_id else None
        supplier_text = request.form.get('supplier', '').strip() or None
        
        # If supplier selected from dropdown, get the name for the text field too
        if supplier_id:
            supplier_obj = Supplier.query.get(supplier_id)
            if supplier_obj:
                supplier_text = supplier_obj.name
        
        item = InventoryItem(
            medication_id=medication_id,
            lot_number=request.form.get('lot_number'),
            expiration_date=expiration_date,
            quantity_received=quantity,
            current_quantity=quantity,
            unit_count=request.form.get('unit_count'),
            date_received=date_received,
            received_by=session['user_id'],
            supplier=supplier_text,
            supplier_id=supplier_id,
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
    suppliers = Supplier.query.filter_by(is_active=True).order_by(Supplier.name).all()
    return render_template('receive_inventory.html', medications=medications, suppliers=suppliers)


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


@app.route('/inventory/<int:id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_inventory(id):
    """Admin-only: Edit lot numbers and expiration dates"""
    item = InventoryItem.query.get_or_404(id)
    
    if request.method == 'POST':
        old_lot = item.lot_number
        old_exp = item.expiration_date.strftime('%Y-%m-%d') if item.expiration_date else 'None'
        
        item.lot_number = request.form.get('lot_number', '').strip() or None
        item.supplier = request.form.get('supplier', '').strip() or None
        item.invoice_number = request.form.get('invoice_number', '').strip() or None
        item.storage_location = request.form.get('storage_location', '').strip() or None
        item.notes = request.form.get('notes', '').strip() or None
        
        if request.form.get('expiration_date'):
            item.expiration_date = datetime.strptime(request.form['expiration_date'], '%Y-%m-%d').date()
        else:
            item.expiration_date = None
        
        new_lot = item.lot_number or 'None'
        new_exp = item.expiration_date.strftime('%Y-%m-%d') if item.expiration_date else 'None'
        
        db.session.commit()
        
        # Log the change
        changes = []
        if old_lot != (item.lot_number or 'None'):
            changes.append(f"Lot: {old_lot} → {new_lot}")
        if old_exp != new_exp:
            changes.append(f"Exp: {old_exp} → {new_exp}")
        
        change_details = "; ".join(changes) if changes else "Updated inventory details"
        log_audit('edit_inventory', 'inventory_item', item.id, 
                  f"{item.medication.name}: {change_details}")
        
        flash(f'Inventory item updated successfully.', 'success')
        return redirect(url_for('inventory_detail', id=id))
    
    return render_template('edit_inventory.html', item=item)


# ==================== PATIENT-SPECIFIC INVENTORY ROUTES ====================

@app.route('/patient-inventory')
@login_required
def patient_inventory():
    status_filter = request.args.get('status', 'active')
    search = request.args.get('search', '')
    
    query = PatientMedication.query
    
    if status_filter and status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    if search:
        query = query.filter(or_(
            PatientMedication.patient_name.ilike(f'%{search}%'),
            PatientMedication.patient_mrn.ilike(f'%{search}%')
        ))
    
    items = query.order_by(PatientMedication.created_at.desc()).all()
    
    # Count by status
    status_counts = {
        'active': PatientMedication.query.filter_by(status='active').count(),
        'completed': PatientMedication.query.filter_by(status='completed').count(),
        'expired': PatientMedication.query.filter_by(status='expired').count(),
        'destroyed': PatientMedication.query.filter_by(status='destroyed').count()
    }
    
    return render_template('patient_inventory.html',
                          items=items,
                          status_filter=status_filter,
                          search=search,
                          status_counts=status_counts)


@app.route('/patient-inventory/add', methods=['GET', 'POST'])
@login_required
def add_patient_medication():
    if request.method == 'POST':
        # Get source inventory item if specified
        source_id = request.form.get('source_inventory_id')
        source_item = None
        quantity = float(request.form['quantity_prepared'])
        
        if source_id:
            source_item = InventoryItem.query.get(int(source_id))
            if source_item and quantity > source_item.current_quantity:
                flash('Insufficient quantity in source inventory.', 'danger')
                return redirect(url_for('add_patient_medication'))
        
        # Check if patient_id was provided (from patient database)
        patient_id = request.form.get('patient_id')
        patient_name = request.form['patient_name'].strip()
        patient_dob = datetime.strptime(request.form['patient_dob'], '%Y-%m-%d').date()
        patient_mrn = request.form.get('patient_mrn', '').strip() or None
        patient_phone = request.form.get('patient_phone', '').strip() or None
        
        if patient_id:
            # Use existing patient from database
            patient = Patient.query.get(int(patient_id))
            if patient:
                patient_name = patient.full_name
                patient_dob = patient.date_of_birth
                patient_mrn = patient.mrn
                patient_phone = patient.phone
        else:
            # No patient selected - create new patient record
            # First check if patient already exists by name and DOB
            # Parse name - expect "Last, First" format
            name_parts = patient_name.split(',', 1)
            if len(name_parts) == 2:
                last_name = name_parts[0].strip()
                first_name = name_parts[1].strip()
            else:
                # If no comma, treat as single name
                last_name = patient_name
                first_name = ''
            
            # Check for existing patient with same name and DOB
            existing_patient = Patient.query.filter(
                Patient.last_name.ilike(last_name),
                Patient.first_name.ilike(first_name),
                Patient.date_of_birth == patient_dob
            ).first()
            
            if existing_patient:
                patient = existing_patient
                patient_id = patient.id
            else:
                # Create new patient
                patient = Patient(
                    first_name=first_name or last_name,
                    last_name=last_name if first_name else '',
                    date_of_birth=patient_dob,
                    mrn=patient_mrn,
                    phone=patient_phone,
                    created_by=session['user_id']
                )
                db.session.add(patient)
                db.session.flush()  # Get the ID without committing
                patient_id = patient.id
                
                log_audit('add_patient', 'patient', patient.id, 
                         f"Auto-created patient from patient-specific medication: {patient.full_name}")
        
        patient_med = PatientMedication(
            patient_id=patient_id,
            patient_name=patient_name,
            patient_dob=patient_dob,
            patient_mrn=patient_mrn,
            patient_phone=patient_phone,
            medication_id=int(request.form['medication_id']),
            source_inventory_id=int(source_id) if source_id else None,
            preparation_date=datetime.strptime(request.form['preparation_date'], '%Y-%m-%d').date(),
            prepared_by=session['user_id'],
            lot_number=request.form.get('lot_number'),
            expiration_date=datetime.strptime(request.form['expiration_date'], '%Y-%m-%d').date() if request.form.get('expiration_date') else None,
            quantity_prepared=quantity,
            quantity_remaining=quantity,
            unit=request.form.get('unit', 'doses'),
            prescriber_id=int(request.form['prescriber_id']),
            prescription_number=request.form.get('prescription_number'),
            storage_location=request.form.get('storage_location'),
            notes=request.form.get('notes')
        )
        
        db.session.add(patient_med)
        
        # Deduct from source inventory if specified
        if source_item:
            balance_before = source_item.current_quantity
            source_item.current_quantity -= quantity
            
            # Record transaction
            transaction = Transaction(
                inventory_item_id=source_item.id,
                transaction_type='dispense',
                quantity=quantity,
                balance_before=balance_before,
                balance_after=source_item.current_quantity,
                patient_id=int(patient_id) if patient_id else None,
                patient_name=patient_name,
                patient_dob=patient_dob,
                patient_mrn=patient_mrn,
                performed_by=session['user_id'],
                notes=f"Prepared for patient-specific inventory"
            )
            db.session.add(transaction)
        
        db.session.commit()
        
        log_audit('add_patient_medication', 'patient_medication', patient_med.id,
                  f"Created patient-specific: {patient_med.medication.name} for {patient_med.patient_name}")
        
        flash(f'Patient-specific medication created for {patient_med.patient_name}.', 'success')
        return redirect(url_for('patient_inventory'))
    
    medications = Medication.query.filter_by(is_active=True).order_by(Medication.name).all()
    providers = User.query.filter(User.role.in_(['admin', 'provider']), User.is_active == True).all()
    
    # Get inventory items with stock
    inventory_items = InventoryItem.query.filter(
        InventoryItem.is_active == True,
        InventoryItem.current_quantity > 0
    ).all()
    
    # Get patients for selection
    patients = Patient.query.filter_by(is_active=True).order_by(Patient.last_name, Patient.first_name).all()
    
    return render_template('patient_medication_form.html',
                          patient_med=None,
                          medications=medications,
                          providers=providers,
                          inventory_items=inventory_items,
                          patients=patients)


@app.route('/patient-inventory/<int:id>')
@login_required
def patient_medication_detail(id):
    patient_med = PatientMedication.query.get_or_404(id)
    logs = PatientMedicationLog.query.filter_by(patient_medication_id=id).order_by(
        PatientMedicationLog.administration_date.desc()
    ).all()
    
    return render_template('patient_medication_detail.html',
                          patient_med=patient_med,
                          logs=logs)


@app.route('/patient-inventory/<int:id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_patient_medication(id):
    """Admin-only: Edit lot numbers and expiration dates for patient-specific inventory"""
    patient_med = PatientMedication.query.get_or_404(id)
    
    if request.method == 'POST':
        old_lot = patient_med.lot_number
        old_exp = patient_med.expiration_date.strftime('%Y-%m-%d') if patient_med.expiration_date else 'None'
        
        patient_med.lot_number = request.form.get('lot_number', '').strip() or None
        patient_med.storage_location = request.form.get('storage_location', '').strip() or None
        patient_med.prescription_number = request.form.get('prescription_number', '').strip() or None
        patient_med.notes = request.form.get('notes', '').strip() or None
        
        if request.form.get('expiration_date'):
            patient_med.expiration_date = datetime.strptime(request.form['expiration_date'], '%Y-%m-%d').date()
        else:
            patient_med.expiration_date = None
        
        new_lot = patient_med.lot_number or 'None'
        new_exp = patient_med.expiration_date.strftime('%Y-%m-%d') if patient_med.expiration_date else 'None'
        
        db.session.commit()
        
        # Log the change
        changes = []
        if old_lot != (patient_med.lot_number or 'None'):
            changes.append(f"Lot: {old_lot} → {new_lot}")
        if old_exp != new_exp:
            changes.append(f"Exp: {old_exp} → {new_exp}")
        
        change_details = "; ".join(changes) if changes else "Updated patient medication details"
        log_audit('edit_patient_medication', 'patient_medication', patient_med.id, 
                  f"{patient_med.medication.name} for {patient_med.patient_name}: {change_details}")
        
        flash(f'Patient medication updated successfully.', 'success')
        return redirect(url_for('patient_medication_detail', id=id))
    
    return render_template('edit_patient_medication.html', patient_med=patient_med)


@app.route('/patient-inventory/<int:id>/administer', methods=['GET', 'POST'])
@login_required
def administer_patient_medication(id):
    patient_med = PatientMedication.query.get_or_404(id)
    
    if patient_med.status != 'active':
        flash('Cannot administer from inactive patient medication.', 'danger')
        return redirect(url_for('patient_medication_detail', id=id))
    
    if request.method == 'POST':
        quantity = float(request.form['quantity'])
        
        if quantity > patient_med.quantity_remaining:
            flash('Insufficient quantity remaining.', 'danger')
            return redirect(url_for('administer_patient_medication', id=id))
        
        log_entry = PatientMedicationLog(
            patient_medication_id=id,
            log_type='administered',
            quantity=quantity,
            quantity_before=patient_med.quantity_remaining,
            quantity_after=patient_med.quantity_remaining - quantity,
            administered_by=session['user_id'],
            witness_id=int(request.form['witness_id']) if request.form.get('witness_id') else None,
            notes=request.form.get('notes')
        )
        
        patient_med.quantity_remaining -= quantity
        
        # Check if completed
        if patient_med.quantity_remaining <= 0:
            patient_med.status = 'completed'
        
        db.session.add(log_entry)
        db.session.commit()
        
        log_audit('administer_patient_med', 'patient_medication', id,
                  f"Administered {quantity} {patient_med.unit} to {patient_med.patient_name}")
        
        flash(f'Administered {quantity} {patient_med.unit}. Remaining: {patient_med.quantity_remaining}', 'success')
        return redirect(url_for('patient_medication_detail', id=id))
    
    users = User.query.filter_by(is_active=True).all()
    return render_template('administer_patient_medication.html',
                          patient_med=patient_med,
                          users=users)


@app.route('/patient-inventory/<int:id>/waste', methods=['GET', 'POST'])
@login_required
def waste_patient_medication(id):
    patient_med = PatientMedication.query.get_or_404(id)
    
    if patient_med.status != 'active':
        flash('Cannot waste from inactive patient medication.', 'danger')
        return redirect(url_for('patient_medication_detail', id=id))
    
    if request.method == 'POST':
        quantity = float(request.form['quantity'])
        
        if quantity > patient_med.quantity_remaining:
            flash('Cannot waste more than remaining quantity.', 'danger')
            return redirect(url_for('waste_patient_medication', id=id))
        
        log_entry = PatientMedicationLog(
            patient_medication_id=id,
            log_type='wasted',
            quantity=quantity,
            quantity_before=patient_med.quantity_remaining,
            quantity_after=patient_med.quantity_remaining - quantity,
            administered_by=session['user_id'],
            witness_id=int(request.form['witness_id']),
            waste_reason=request.form['waste_reason'],
            notes=request.form.get('notes')
        )
        
        patient_med.quantity_remaining -= quantity
        
        # Check if completed
        if patient_med.quantity_remaining <= 0:
            patient_med.status = 'completed'
        
        db.session.add(log_entry)
        db.session.commit()
        
        log_audit('waste_patient_med', 'patient_medication', id,
                  f"Wasted {quantity} {patient_med.unit} for {patient_med.patient_name}. Reason: {request.form['waste_reason']}")
        
        flash(f'Wasted {quantity} {patient_med.unit}. Remaining: {patient_med.quantity_remaining}', 'success')
        return redirect(url_for('patient_medication_detail', id=id))
    
    users = User.query.filter(User.id != session['user_id'], User.is_active == True).all()
    return render_template('waste_patient_medication.html',
                          patient_med=patient_med,
                          users=users)


@app.route('/patient-inventory/<int:id>/destroy', methods=['GET', 'POST'])
@login_required
def destroy_patient_medication(id):
    patient_med = PatientMedication.query.get_or_404(id)
    
    if patient_med.quantity_remaining <= 0:
        flash('No quantity remaining to destroy.', 'warning')
        return redirect(url_for('patient_medication_detail', id=id))
    
    if request.method == 'POST':
        log_entry = PatientMedicationLog(
            patient_medication_id=id,
            log_type='destroyed',
            quantity=patient_med.quantity_remaining,
            quantity_before=patient_med.quantity_remaining,
            quantity_after=0,
            administered_by=session['user_id'],
            witness_id=int(request.form['witness_id']),
            waste_reason=request.form['destruction_reason'],
            notes=request.form.get('notes')
        )
        
        destroyed_qty = patient_med.quantity_remaining
        patient_med.quantity_remaining = 0
        patient_med.status = 'destroyed'
        
        db.session.add(log_entry)
        db.session.commit()
        
        log_audit('destroy_patient_med', 'patient_medication', id,
                  f"Destroyed {destroyed_qty} {patient_med.unit} for {patient_med.patient_name}. Reason: {request.form['destruction_reason']}")
        
        flash(f'Patient medication destroyed and documented.', 'success')
        return redirect(url_for('patient_medication_detail', id=id))
    
    users = User.query.filter(User.id != session['user_id'], User.is_active == True).all()
    return render_template('destroy_patient_medication.html',
                          patient_med=patient_med,
                          users=users)


@app.route('/patient-inventory/<int:id>/delete', methods=['GET', 'POST'])
@admin_required
def delete_patient_medication(id):
    """Admin-only: Delete a patient medication record with documented reason"""
    patient_med = PatientMedication.query.get_or_404(id)
    
    if request.method == 'POST':
        deletion_reason = request.form.get('deletion_reason', '').strip()
        
        if not deletion_reason:
            flash('A deletion reason is required.', 'danger')
            return redirect(url_for('delete_patient_medication', id=id))
        
        # Store info for audit log before deletion
        patient_name = patient_med.patient_name
        med_name = patient_med.medication.name
        qty_received = patient_med.quantity_prepared
        qty_remaining = patient_med.quantity_remaining
        
        # Delete associated logs first
        PatientMedicationLog.query.filter_by(patient_medication_id=id).delete()
        
        # Delete the patient medication record
        db.session.delete(patient_med)
        db.session.commit()
        
        # Log the deletion with full details
        log_audit('delete_patient_med', 'patient_medication', id,
                  f"DELETED patient medication record: {med_name} for {patient_name}. "
                  f"Qty received: {qty_received}, Qty remaining at deletion: {qty_remaining}. "
                  f"Reason: {deletion_reason}")
        
        flash(f'Patient medication record deleted. Reason logged in audit trail.', 'success')
        return redirect(url_for('patient_inventory'))
    
    # Get administration/waste logs for this medication
    logs = PatientMedicationLog.query.filter_by(patient_medication_id=id).order_by(
        PatientMedicationLog.administration_date.desc()
    ).all()
    
    return render_template('delete_patient_medication.html',
                          patient_med=patient_med,
                          logs=logs)


# ==================== DISPENSING ROUTES ====================

@app.route('/dispense', methods=['GET', 'POST'])
@login_required
def dispense():
    if request.method == 'POST':
        inventory_item_id = int(request.form['inventory_id'])
        quantity = float(request.form['quantity'])
        
        item = InventoryItem.query.get_or_404(inventory_item_id)
        
        if quantity > item.current_quantity:
            flash('Insufficient quantity available.', 'danger')
            return redirect(url_for('dispense'))
        
        balance_before = item.current_quantity
        item.current_quantity -= quantity
        balance_after = item.current_quantity
        
        # Check if patient_id was provided (from patient database)
        patient_id = request.form.get('patient_id')
        patient_name = request.form.get('patient_name', '').strip()
        patient_dob = None
        patient_mrn = request.form.get('patient_mrn', '').strip() or None
        
        if patient_id:
            # Link to patient database
            patient = Patient.query.get(int(patient_id))
            if patient:
                patient_name = patient.full_name
                patient_dob = patient.date_of_birth
                patient_mrn = patient.mrn
        elif patient_name and request.form.get('patient_dob'):
            patient_dob = datetime.strptime(request.form['patient_dob'], '%Y-%m-%d').date()
            
            # Create patient record if doesn't exist
            # Parse name - expect "Last, First" format
            name_parts = patient_name.split(',', 1)
            if len(name_parts) == 2:
                last_name = name_parts[0].strip()
                first_name = name_parts[1].strip()
            else:
                last_name = patient_name
                first_name = ''
            
            # Check for existing patient with same name and DOB
            existing_patient = Patient.query.filter(
                Patient.last_name.ilike(last_name),
                Patient.first_name.ilike(first_name),
                Patient.date_of_birth == patient_dob
            ).first()
            
            if existing_patient:
                patient_id = existing_patient.id
            else:
                # Create new patient
                new_patient = Patient(
                    first_name=first_name or last_name,
                    last_name=last_name if first_name else '',
                    date_of_birth=patient_dob,
                    mrn=patient_mrn,
                    created_by=session['user_id']
                )
                db.session.add(new_patient)
                db.session.flush()
                patient_id = new_patient.id
                
                log_audit('add_patient', 'patient', new_patient.id, 
                         f"Auto-created patient from dispensing: {new_patient.full_name}")
        
        transaction = Transaction(
            inventory_item_id=inventory_item_id,
            transaction_type='dispense',
            quantity=quantity,
            balance_before=balance_before,
            balance_after=balance_after,
            patient_id=int(patient_id) if patient_id else None,
            patient_name=patient_name,
            patient_dob=patient_dob,
            patient_mrn=patient_mrn,
            prescription_number=request.form.get('prescription_number'),
            prescriber_id=request.form.get('prescriber_id') or None,
            performed_by=session['user_id'],
            notes=request.form.get('notes')
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        log_audit('dispense', 'transaction', transaction.id,
                 f'Dispensed {quantity} units of {item.medication.name} to {patient_name or "Unknown"}')
        
        flash(f'Successfully dispensed {quantity} units. New balance: {balance_after}', 'success')
        return redirect(url_for('inventory'))
    
    # Get available inventory items
    inventory_items = InventoryItem.query.join(Medication).filter(
        InventoryItem.is_active == True,
        InventoryItem.current_quantity > 0
    ).order_by(Medication.schedule, Medication.name).all()
    
    providers = User.query.filter(
        User.is_active == True,
        User.role.in_(['admin', 'provider'])
    ).all()
    
    # Get patients for autocomplete
    patients = Patient.query.filter_by(is_active=True).order_by(Patient.last_name, Patient.first_name).all()
    
    return render_template('dispense.html', inventory_items=inventory_items, providers=providers, patients=patients)


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
    today = get_current_date()
    
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


@app.route('/daily-count/verify-all', methods=['POST'])
@login_required
def verify_all_counts():
    """Verify all pending counts at once"""
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
    
    # Get all unverified counts for today
    today = get_current_date()
    unverified_counts = DailyCount.query.filter(
        DailyCount.count_date == today,
        DailyCount.verified_by == None
    ).all()
    
    verified_count = 0
    skipped_count = 0
    
    for count in unverified_counts:
        # Can't verify own counts
        if verifier.id == count.counted_by:
            skipped_count += 1
            continue
        
        count.verified_by = verifier.id
        count.verified_at = datetime.utcnow()
        verified_count += 1
    
    db.session.commit()
    
    if verified_count > 0:
        log_audit('verify_all_counts', 'daily_count', None, 
                  f'Bulk verified {verified_count} daily counts by {verifier.full_name}')
    
    if skipped_count > 0:
        flash(f'Verified {verified_count} counts. Skipped {skipped_count} (cannot verify own counts).', 'warning')
    else:
        flash(f'Successfully verified {verified_count} counts.', 'success')
    
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
    
    # Get all current inventory items to display
    inventory_items = InventoryItem.query.join(Medication).filter(
        InventoryItem.is_active == True,
        InventoryItem.current_quantity > 0
    ).order_by(Medication.schedule, Medication.name).all()
    
    # Get users who can be witnesses
    witnesses = User.query.filter_by(is_active=True).all()
    
    return render_template('new_biennial_inventory.html',
                          dea_reg=dea_reg,
                          nc_reg=nc_reg,
                          inventory_items=inventory_items,
                          witnesses=witnesses)


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
    type_filter = request.args.get('type')
    schedule_filter = request.args.get('schedule')
    
    # Parse dates
    start = None
    end = None
    if start_date and start_date.strip():
        try:
            start = datetime.strptime(start_date, '%Y-%m-%d')
        except ValueError:
            start = None
    if end_date and end_date.strip():
        try:
            end = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
        except ValueError:
            end = None
    
    # Build query for regular transactions
    query = db.session.query(Transaction).join(
        InventoryItem, Transaction.inventory_item_id == InventoryItem.id
    ).join(
        Medication, InventoryItem.medication_id == Medication.id
    )
    
    if start:
        query = query.filter(Transaction.performed_at >= start)
    
    if end:
        query = query.filter(Transaction.performed_at < end)
    
    if medication_id:
        query = query.filter(Medication.id == int(medication_id))
    
    if type_filter and type_filter != 'patient_receive':
        query = query.filter(Transaction.transaction_type == type_filter)
    
    if schedule_filter:
        query = query.filter(Medication.schedule == schedule_filter)
    
    transactions = query.order_by(Transaction.performed_at.desc()).limit(500).all()
    
    # Get patient-specific medication receipts if showing all types or specifically patient_receive
    patient_receipts = []
    if not type_filter or type_filter == 'patient_receive':
        pm_query = PatientMedication.query.join(Medication)
        
        if start:
            pm_query = pm_query.filter(PatientMedication.created_at >= start)
        if end:
            pm_query = pm_query.filter(PatientMedication.created_at < end)
        if medication_id:
            pm_query = pm_query.filter(PatientMedication.medication_id == int(medication_id))
        if schedule_filter:
            pm_query = pm_query.filter(Medication.schedule == schedule_filter)
        
        patient_receipts = pm_query.order_by(PatientMedication.created_at.desc()).limit(500).all()
    
    # If filtering specifically for patient_receive, clear regular transactions
    if type_filter == 'patient_receive':
        transactions = []
    
    medications = Medication.query.filter_by(is_active=True).order_by(Medication.name).all()
    
    return render_template('usage_report.html',
                          transactions=transactions,
                          patient_receipts=patient_receipts,
                          medications=medications,
                          start_date=start_date or '',
                          end_date=end_date or '',
                          medication_id=medication_id,
                          type_filter=type_filter,
                          schedule_filter=schedule_filter)


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


# ==================== PATIENT MANAGEMENT ====================

@app.route('/patients')
@login_required
def patients():
    search = request.args.get('search', '')
    
    query = Patient.query.filter_by(is_active=True)
    
    if search:
        query = query.filter(or_(
            Patient.first_name.ilike(f'%{search}%'),
            Patient.last_name.ilike(f'%{search}%'),
            Patient.mrn.ilike(f'%{search}%'),
            Patient.phone.ilike(f'%{search}%')
        ))
    
    patients = query.order_by(Patient.last_name, Patient.first_name).all()
    
    return render_template('patients.html', patients=patients, search=search)


@app.route('/patients/add', methods=['GET', 'POST'])
@login_required
def add_patient():
    if request.method == 'POST':
        # Check for duplicate MRN
        mrn = request.form.get('mrn', '').strip()
        if mrn:
            existing = Patient.query.filter_by(mrn=mrn).first()
            if existing:
                flash('A patient with this MRN already exists.', 'danger')
                return redirect(url_for('add_patient'))
        
        patient = Patient(
            first_name=request.form['first_name'].strip(),
            last_name=request.form['last_name'].strip(),
            date_of_birth=datetime.strptime(request.form['date_of_birth'], '%Y-%m-%d').date(),
            mrn=mrn or None,
            phone=request.form.get('phone', '').strip() or None,
            email=request.form.get('email', '').strip() or None,
            address=request.form.get('address', '').strip() or None,
            city=request.form.get('city', '').strip() or None,
            state=request.form.get('state', '').strip() or None,
            zip_code=request.form.get('zip_code', '').strip() or None,
            insurance_id=request.form.get('insurance_id', '').strip() or None,
            notes=request.form.get('notes', '').strip() or None,
            created_by=session['user_id']
        )
        
        db.session.add(patient)
        db.session.commit()
        
        log_audit('add_patient', 'patient', patient.id, f"Added patient: {patient.full_name}")
        flash(f'Patient {patient.full_name} added successfully.', 'success')
        return redirect(url_for('patients'))
    
    return render_template('patient_form.html', patient=None)


@app.route('/patients/<int:id>')
@login_required
def patient_detail(id):
    patient = Patient.query.get_or_404(id)
    
    # Get transactions for this patient
    transactions = Transaction.query.filter_by(patient_id=id).order_by(
        Transaction.performed_at.desc()
    ).limit(50).all()
    
    # Get patient-specific medications
    patient_meds = PatientMedication.query.filter_by(patient_id=id).order_by(
        PatientMedication.created_at.desc()
    ).all()
    
    return render_template('patient_detail.html', 
                          patient=patient, 
                          transactions=transactions,
                          patient_meds=patient_meds)


@app.route('/patients/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_patient(id):
    patient = Patient.query.get_or_404(id)
    
    if request.method == 'POST':
        # Check for duplicate MRN
        mrn = request.form.get('mrn', '').strip()
        if mrn:
            existing = Patient.query.filter(Patient.mrn == mrn, Patient.id != id).first()
            if existing:
                flash('A patient with this MRN already exists.', 'danger')
                return redirect(url_for('edit_patient', id=id))
        
        patient.first_name = request.form['first_name'].strip()
        patient.last_name = request.form['last_name'].strip()
        patient.date_of_birth = datetime.strptime(request.form['date_of_birth'], '%Y-%m-%d').date()
        patient.mrn = mrn or None
        patient.phone = request.form.get('phone', '').strip() or None
        patient.email = request.form.get('email', '').strip() or None
        patient.address = request.form.get('address', '').strip() or None
        patient.city = request.form.get('city', '').strip() or None
        patient.state = request.form.get('state', '').strip() or None
        patient.zip_code = request.form.get('zip_code', '').strip() or None
        patient.insurance_id = request.form.get('insurance_id', '').strip() or None
        patient.notes = request.form.get('notes', '').strip() or None
        
        db.session.commit()
        
        log_audit('edit_patient', 'patient', patient.id, f"Updated patient: {patient.full_name}")
        flash(f'Patient {patient.full_name} updated successfully.', 'success')
        return redirect(url_for('patient_detail', id=id))
    
    return render_template('patient_form.html', patient=patient)


@app.route('/patients/search')
@login_required
def search_patients():
    """API endpoint for patient search autocomplete"""
    q = request.args.get('q', '')
    if len(q) < 2:
        return jsonify([])
    
    patients = Patient.query.filter(
        Patient.is_active == True,
        or_(
            Patient.first_name.ilike(f'%{q}%'),
            Patient.last_name.ilike(f'%{q}%'),
            Patient.mrn.ilike(f'%{q}%')
        )
    ).limit(10).all()
    
    return jsonify([{
        'id': p.id,
        'name': p.full_name,
        'dob': p.date_of_birth.strftime('%m/%d/%Y'),
        'mrn': p.mrn or '',
        'phone': p.phone or ''
    } for p in patients])


# ==================== SUPPLIER MANAGEMENT ====================

@app.route('/suppliers')
@login_required
def suppliers():
    suppliers = Supplier.query.filter_by(is_active=True).order_by(Supplier.name).all()
    inactive_suppliers = Supplier.query.filter_by(is_active=False).order_by(Supplier.name).all()
    return render_template('suppliers.html', suppliers=suppliers, inactive_suppliers=inactive_suppliers)


@app.route('/suppliers/add', methods=['GET', 'POST'])
@admin_required
def add_supplier():
    if request.method == 'POST':
        dea_number = request.form.get('dea_number', '').upper().strip() or None
        
        # Validate DEA number if provided
        if dea_number and not Supplier.validate_dea_number(dea_number):
            flash('Invalid DEA number format. Please check and try again.', 'danger')
            return redirect(url_for('add_supplier'))
        
        # Check for duplicate DEA if provided
        if dea_number:
            existing = Supplier.query.filter_by(dea_number=dea_number).first()
            if existing:
                flash(f'A supplier with DEA number {dea_number} already exists.', 'danger')
                return redirect(url_for('add_supplier'))
        
        supplier = Supplier(
            name=request.form['name'],
            dea_number=dea_number,
            address=request.form.get('address'),
            city=request.form.get('city'),
            state=request.form.get('state'),
            zip_code=request.form.get('zip_code'),
            phone=request.form.get('phone'),
            fax=request.form.get('fax'),
            email=request.form.get('email'),
            contact_name=request.form.get('contact_name'),
            account_number=request.form.get('account_number'),
            notes=request.form.get('notes'),
            created_by=session['user_id']
        )
        
        db.session.add(supplier)
        db.session.commit()
        
        log_audit('add_supplier', 'supplier', supplier.id, f'Added supplier: {supplier.name}' + (f' (DEA: {supplier.dea_number})' if supplier.dea_number else ''))
        
        flash(f'Supplier "{supplier.name}" added successfully.', 'success')
        return redirect(url_for('suppliers'))
    
    return render_template('supplier_form.html', supplier=None)


@app.route('/suppliers/<int:id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_supplier(id):
    supplier = Supplier.query.get_or_404(id)
    
    if request.method == 'POST':
        dea_number = request.form.get('dea_number', '').upper().strip() or None
        
        # Validate DEA number if provided
        if dea_number and not Supplier.validate_dea_number(dea_number):
            flash('Invalid DEA number format.', 'danger')
            return redirect(url_for('edit_supplier', id=id))
        
        # Check for duplicate (excluding this supplier) if DEA provided
        if dea_number:
            existing = Supplier.query.filter(Supplier.dea_number == dea_number, Supplier.id != id).first()
            if existing:
                flash(f'Another supplier with DEA number {dea_number} already exists.', 'danger')
                return redirect(url_for('edit_supplier', id=id))
        
        supplier.name = request.form['name']
        supplier.dea_number = dea_number
        supplier.address = request.form.get('address')
        supplier.city = request.form.get('city')
        supplier.state = request.form.get('state')
        supplier.zip_code = request.form.get('zip_code')
        supplier.phone = request.form.get('phone')
        supplier.fax = request.form.get('fax')
        supplier.email = request.form.get('email')
        supplier.contact_name = request.form.get('contact_name')
        supplier.account_number = request.form.get('account_number')
        supplier.notes = request.form.get('notes')
        supplier.is_active = request.form.get('is_active') == 'yes'
        
        db.session.commit()
        
        log_audit('edit_supplier', 'supplier', supplier.id, f'Updated supplier: {supplier.name}')
        
        flash(f'Supplier "{supplier.name}" updated successfully.', 'success')
        return redirect(url_for('suppliers'))
    
    return render_template('supplier_form.html', supplier=supplier)


@app.route('/suppliers/<int:id>')
@login_required
def supplier_detail(id):
    supplier = Supplier.query.get_or_404(id)
    
    # Get inventory items from this supplier
    inventory_items = InventoryItem.query.filter_by(supplier_id=id).order_by(InventoryItem.date_received.desc()).limit(50).all()
    
    # Get Form 222s from this supplier
    form222s = Form222.query.filter_by(supplier_id=id).order_by(Form222.order_date.desc()).limit(20).all()
    
    return render_template('supplier_detail.html', supplier=supplier, inventory_items=inventory_items, form222s=form222s)


# ==================== DEA FORM 222 TRACKING ====================

@app.route('/form222')
@login_required
def form222_list():
    status_filter = request.args.get('status', 'all')
    
    query = Form222.query
    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    
    forms = query.order_by(Form222.order_date.desc()).all()
    
    return render_template('form222_list.html', forms=forms, status_filter=status_filter)


@app.route('/form222/add', methods=['GET', 'POST'])
@provider_required
def add_form222():
    if request.method == 'POST':
        form_number = request.form['form_number'].strip().upper()
        
        # Check for duplicate
        existing = Form222.query.filter_by(form_number=form_number).first()
        if existing:
            flash(f'Form 222 #{form_number} already exists.', 'danger')
            return redirect(url_for('add_form222'))
        
        form222 = Form222(
            form_number=form_number,
            supplier_id=int(request.form['supplier_id']) if request.form.get('supplier_id') else None,
            order_date=datetime.strptime(request.form['order_date'], '%Y-%m-%d').date(),
            notes=request.form.get('notes'),
            created_by=session['user_id']
        )
        
        db.session.add(form222)
        db.session.flush()
        
        # Add line items
        line_num = 1
        while f'medication_id_{line_num}' in request.form:
            med_id = request.form.get(f'medication_id_{line_num}')
            qty = request.form.get(f'quantity_{line_num}')
            
            if med_id and qty:
                line_item = Form222LineItem(
                    form222_id=form222.id,
                    line_number=line_num,
                    medication_id=int(med_id),
                    quantity_ordered=float(qty)
                )
                db.session.add(line_item)
            
            line_num += 1
        
        db.session.commit()
        
        log_audit('add_form222', 'form222', form222.id, f'Created Form 222 #{form_number}')
        
        flash(f'Form 222 #{form_number} created successfully.', 'success')
        return redirect(url_for('form222_list'))
    
    suppliers = Supplier.query.filter_by(is_active=True).order_by(Supplier.name).all()
    medications = Medication.query.filter_by(is_active=True, schedule='II').order_by(Medication.name).all()
    
    return render_template('form222_form.html', form222=None, suppliers=suppliers, medications=medications)


@app.route('/form222/<int:id>')
@login_required
def form222_detail(id):
    form222 = Form222.query.get_or_404(id)
    return render_template('form222_detail.html', form222=form222)


@app.route('/form222/<int:id>/receive', methods=['GET', 'POST'])
@provider_required
def receive_form222(id):
    form222 = Form222.query.get_or_404(id)
    
    if form222.status == 'complete':
        flash('This form has already been fully received.', 'warning')
        return redirect(url_for('form222_detail', id=id))
    
    if request.method == 'POST':
        received_date = datetime.strptime(request.form['received_date'], '%Y-%m-%d').date()
        form222.received_date = received_date
        
        all_received = True
        
        for line_item in form222.line_items:
            qty_received = request.form.get(f'qty_received_{line_item.id}')
            lot_number = request.form.get(f'lot_number_{line_item.id}')
            expiration = request.form.get(f'expiration_{line_item.id}')
            
            if qty_received:
                qty = float(qty_received)
                if qty > 0:
                    line_item.quantity_received = qty
                    
                    # Create inventory item
                    inv_item = InventoryItem(
                        medication_id=line_item.medication_id,
                        lot_number=lot_number,
                        expiration_date=datetime.strptime(expiration, '%Y-%m-%d').date() if expiration else None,
                        quantity_received=qty,
                        current_quantity=qty,
                        received_date=received_date,
                        received_by=session['user_id'],
                        supplier_id=form222.supplier_id,
                        form222_id=form222.id,
                        notes=f'Received via Form 222 #{form222.form_number}'
                    )
                    db.session.add(inv_item)
                    db.session.flush()
                    
                    line_item.inventory_item_id = inv_item.id
                    
                    # Log the receipt
                    log_audit('receive_form222', 'inventory_item', inv_item.id,
                             f'Received {qty} of {line_item.medication.name} via Form 222 #{form222.form_number}')
                
                if line_item.quantity_received < line_item.quantity_ordered:
                    all_received = False
            else:
                all_received = False
        
        form222.status = 'complete' if all_received else 'partial'
        db.session.commit()
        
        flash('Form 222 receipt recorded successfully.', 'success')
        return redirect(url_for('form222_detail', id=id))
    
    return render_template('form222_receive.html', form222=form222)


@app.route('/form222/<int:id>/void', methods=['POST'])
@admin_required
def void_form222(id):
    form222 = Form222.query.get_or_404(id)
    
    reason = request.form.get('void_reason', '').strip()
    if not reason:
        flash('A reason is required to void a Form 222.', 'danger')
        return redirect(url_for('form222_detail', id=id))
    
    form222.status = 'void'
    form222.voided_reason = reason
    db.session.commit()
    
    log_audit('void_form222', 'form222', form222.id, f'Voided Form 222 #{form222.form_number}. Reason: {reason}')
    
    flash(f'Form 222 #{form222.form_number} has been voided.', 'warning')
    return redirect(url_for('form222_list'))


# ==================== PHYSICAL INVENTORY ====================

@app.route('/physical-inventory')
@login_required
def physical_inventory_list():
    inventories = PhysicalInventory.query.order_by(PhysicalInventory.inventory_date.desc()).all()
    return render_template('physical_inventory_list.html', inventories=inventories)


@app.route('/physical-inventory/new', methods=['GET', 'POST'])
@provider_required
def new_physical_inventory():
    if request.method == 'POST':
        inventory_type = request.form['inventory_type']
        
        inventory = PhysicalInventory(
            inventory_date=get_current_date(),
            inventory_type=inventory_type,
            started_by=session['user_id'],
            notes=request.form.get('notes')
        )
        
        db.session.add(inventory)
        db.session.flush()
        
        # Add items based on type
        if inventory_type == 'full':
            items = InventoryItem.query.filter(
                InventoryItem.is_active == True,
                InventoryItem.current_quantity > 0
            ).all()
        elif inventory_type == 'schedule2':
            items = InventoryItem.query.join(Medication).filter(
                InventoryItem.is_active == True,
                InventoryItem.current_quantity > 0,
                Medication.schedule == 'II'
            ).all()
        else:  # spot_check
            # For spot check, items are added manually
            items = []
        
        for item in items:
            count_item = PhysicalInventoryItem(
                physical_inventory_id=inventory.id,
                inventory_item_id=item.id,
                expected_quantity=item.current_quantity
            )
            db.session.add(count_item)
        
        db.session.commit()
        
        log_audit('start_physical_inventory', 'physical_inventory', inventory.id,
                 f'Started {inventory_type} physical inventory')
        
        flash(f'Physical inventory started with {len(items)} items.', 'success')
        return redirect(url_for('perform_physical_inventory', id=inventory.id))
    
    return render_template('new_physical_inventory.html')


@app.route('/physical-inventory/<int:id>')
@login_required
def perform_physical_inventory(id):
    inventory = PhysicalInventory.query.get_or_404(id)
    return render_template('perform_physical_inventory.html', inventory=inventory)


@app.route('/physical-inventory/<int:id>/count', methods=['POST'])
@login_required
def submit_physical_count(id):
    inventory = PhysicalInventory.query.get_or_404(id)
    
    for item in inventory.count_items:
        qty = request.form.get(f'qty_{item.id}')
        if qty is not None and qty != '':
            item.actual_quantity = float(qty)
            item.counted_by = session['user_id']
            item.counted_at = get_current_time()
            
            notes = request.form.get(f'notes_{item.id}')
            if notes:
                item.discrepancy_notes = notes
    
    db.session.commit()
    
    flash('Counts saved successfully.', 'success')
    return redirect(url_for('perform_physical_inventory', id=id))


@app.route('/physical-inventory/<int:id>/complete', methods=['POST'])
@provider_required
def complete_physical_inventory(id):
    inventory = PhysicalInventory.query.get_or_404(id)
    
    # Check all items counted
    uncounted = [i for i in inventory.count_items if i.actual_quantity is None]
    if uncounted:
        flash(f'{len(uncounted)} items have not been counted yet.', 'danger')
        return redirect(url_for('perform_physical_inventory', id=id))
    
    inventory.status = 'completed'
    inventory.completed_by = session['user_id']
    inventory.completed_at = get_current_time()
    
    db.session.commit()
    
    log_audit('complete_physical_inventory', 'physical_inventory', inventory.id,
             f'Completed physical inventory. {inventory.discrepancy_count} discrepancies found.')
    
    flash('Physical inventory completed.', 'success')
    return redirect(url_for('physical_inventory_report', id=id))


@app.route('/physical-inventory/<int:id>/report')
@login_required
def physical_inventory_report(id):
    inventory = PhysicalInventory.query.get_or_404(id)
    return render_template('physical_inventory_report.html', inventory=inventory)


@app.route('/physical-inventory/<int:id>/adjust', methods=['POST'])
@admin_required
def adjust_from_physical_inventory(id):
    inventory = PhysicalInventory.query.get_or_404(id)
    
    item_id = int(request.form['item_id'])
    count_item = PhysicalInventoryItem.query.get_or_404(item_id)
    
    if count_item.physical_inventory_id != id:
        abort(403)
    
    inv_item = count_item.inventory_item
    old_qty = inv_item.current_quantity
    new_qty = count_item.actual_quantity
    
    # Create adjustment transaction
    transaction = Transaction(
        inventory_item_id=inv_item.id,
        transaction_type='adjust',
        quantity=new_qty - old_qty,
        balance_before=old_qty,
        balance_after=new_qty,
        adjustment_reason=f'Physical inventory adjustment. {request.form.get("reason", "")}',
        performed_by=session['user_id']
    )
    
    inv_item.current_quantity = new_qty
    
    count_item.discrepancy_resolved = True
    count_item.resolution_notes = request.form.get('reason', 'Adjusted to match physical count')
    
    db.session.add(transaction)
    db.session.commit()
    
    log_audit('physical_inventory_adjust', 'inventory_item', inv_item.id,
             f'Adjusted quantity from {old_qty} to {new_qty} based on physical inventory')
    
    flash(f'Inventory adjusted from {old_qty} to {new_qty}.', 'success')
    return redirect(url_for('physical_inventory_report', id=id))


# ==================== REORDER MANAGEMENT ====================

@app.route('/reorder')
@login_required
def reorder_list():
    # Get medications that need reorder
    medications = Medication.query.filter_by(is_active=True).all()
    
    needs_reorder = []
    for med in medications:
        if med.reorder_point and med.total_quantity <= med.reorder_point:
            needs_reorder.append({
                'medication': med,
                'current_qty': med.total_quantity,
                'reorder_point': med.reorder_point,
                'suggested_qty': med.reorder_quantity or (med.reorder_point * 2)
            })
    
    # Sort by urgency (lowest stock first)
    needs_reorder.sort(key=lambda x: x['current_qty'])
    
    return render_template('reorder_list.html', needs_reorder=needs_reorder)


@app.route('/reorder/settings', methods=['GET', 'POST'])
@admin_required
def reorder_settings():
    if request.method == 'POST':
        med_id = int(request.form['medication_id'])
        medication = Medication.query.get_or_404(med_id)
        
        medication.reorder_point = int(request.form['reorder_point']) if request.form.get('reorder_point') else None
        medication.reorder_quantity = int(request.form['reorder_quantity']) if request.form.get('reorder_quantity') else None
        
        db.session.commit()
        
        log_audit('update_reorder_settings', 'medication', med_id,
                 f'Updated reorder settings: point={medication.reorder_point}, qty={medication.reorder_quantity}')
        
        flash(f'Reorder settings updated for {medication.name}.', 'success')
        return redirect(url_for('reorder_settings'))
    
    medications = Medication.query.filter_by(is_active=True).order_by(Medication.schedule, Medication.name).all()
    suppliers = Supplier.query.filter_by(is_active=True).order_by(Supplier.name).all()
    
    return render_template('reorder_settings.html', medications=medications, suppliers=suppliers)


# ==================== EXPIRATION MANAGEMENT ====================

@app.route('/expiration')
@login_required
def expiration_management():
    today = get_current_date()
    
    # Expired items
    expired = InventoryItem.query.filter(
        InventoryItem.is_active == True,
        InventoryItem.current_quantity > 0,
        InventoryItem.expiration_date < today
    ).order_by(InventoryItem.expiration_date).all()
    
    # Expiring within 30 days
    thirty_days = today + timedelta(days=30)
    expiring_30 = InventoryItem.query.filter(
        InventoryItem.is_active == True,
        InventoryItem.current_quantity > 0,
        InventoryItem.expiration_date >= today,
        InventoryItem.expiration_date <= thirty_days
    ).order_by(InventoryItem.expiration_date).all()
    
    # Expiring within 90 days
    ninety_days = today + timedelta(days=90)
    expiring_90 = InventoryItem.query.filter(
        InventoryItem.is_active == True,
        InventoryItem.current_quantity > 0,
        InventoryItem.expiration_date > thirty_days,
        InventoryItem.expiration_date <= ninety_days
    ).order_by(InventoryItem.expiration_date).all()
    
    # Quarantined items
    quarantined = InventoryItem.query.filter(
        InventoryItem.is_quarantined == True
    ).order_by(InventoryItem.expiration_date).all()
    
    return render_template('expiration_management.html',
                          expired=expired,
                          expiring_30=expiring_30,
                          expiring_90=expiring_90,
                          quarantined=quarantined)


@app.route('/inventory/<int:id>/quarantine', methods=['POST'])
@provider_required
def quarantine_item(id):
    item = InventoryItem.query.get_or_404(id)
    
    reason = request.form.get('reason', 'Expired').strip()
    
    item.is_quarantined = True
    item.quarantine_reason = reason
    
    db.session.commit()
    
    log_audit('quarantine_item', 'inventory_item', item.id,
             f'Quarantined {item.medication.name} (Lot: {item.lot_number}). Reason: {reason}')
    
    flash(f'{item.medication.name} has been quarantined.', 'warning')
    return redirect(url_for('expiration_management'))


@app.route('/inventory/<int:id>/unquarantine', methods=['POST'])
@admin_required
def unquarantine_item(id):
    item = InventoryItem.query.get_or_404(id)
    
    item.is_quarantined = False
    reason = item.quarantine_reason
    item.quarantine_reason = None
    
    db.session.commit()
    
    log_audit('unquarantine_item', 'inventory_item', item.id,
             f'Removed {item.medication.name} from quarantine. Was quarantined for: {reason}')
    
    flash(f'{item.medication.name} has been removed from quarantine.', 'success')
    return redirect(url_for('expiration_management'))


# ==================== ANALYTICS DASHBOARD ====================

@app.route('/analytics')
@login_required
def analytics():
    today = get_current_date()
    thirty_days_ago = today - timedelta(days=30)
    
    dispensing_30 = []
    top_dispensed = []
    waste_30 = 0
    total_items = 0
    schedule_breakdown = []
    
    try:
        # Usage trends - last 30 days
        dispensing_30 = db.session.query(
            func.date(Transaction.performed_at).label('date'),
            func.sum(Transaction.quantity).label('total')
        ).filter(
            Transaction.transaction_type == 'dispense',
            Transaction.performed_at >= thirty_days_ago
        ).group_by(func.date(Transaction.performed_at)).order_by(func.date(Transaction.performed_at)).all()
        
        # Convert to list of dicts for JSON serialization in template
        dispensing_30 = [{'date': str(d.date), 'total': float(d.total)} for d in dispensing_30]
        
        # Top dispensed medications - last 30 days
        top_dispensed = db.session.query(
            Medication.name,
            Medication.schedule,
            func.sum(Transaction.quantity).label('total')
        ).select_from(Transaction).join(
            InventoryItem, Transaction.inventory_item_id == InventoryItem.id
        ).join(
            Medication, InventoryItem.medication_id == Medication.id
        ).filter(
            Transaction.transaction_type == 'dispense',
            Transaction.performed_at >= thirty_days_ago
        ).group_by(Medication.id, Medication.name, Medication.schedule).order_by(func.sum(Transaction.quantity).desc()).limit(10).all()
        
        # Waste summary - last 30 days
        waste_30 = db.session.query(
            func.sum(Transaction.quantity)
        ).filter(
            Transaction.transaction_type == 'waste',
            Transaction.performed_at >= thirty_days_ago
        ).scalar() or 0
        
        # Total active inventory items
        total_items = InventoryItem.query.filter(
            InventoryItem.is_active == True,
            InventoryItem.current_quantity > 0
        ).count()
        
        # Schedule breakdown
        schedule_breakdown = db.session.query(
            Medication.schedule,
            func.count(InventoryItem.id).label('items'),
            func.sum(InventoryItem.current_quantity).label('quantity')
        ).select_from(InventoryItem).join(
            Medication, InventoryItem.medication_id == Medication.id
        ).filter(
            InventoryItem.is_active == True,
            InventoryItem.current_quantity > 0
        ).group_by(Medication.schedule).all()
        
    except Exception as e:
        print(f"Analytics error: {e}")
        flash('Error loading some analytics data.', 'warning')
    
    return render_template('analytics.html',
                          dispensing_30=dispensing_30,
                          top_dispensed=top_dispensed,
                          waste_30=waste_30,
                          total_items=total_items,
                          schedule_breakdown=schedule_breakdown)


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


@app.route('/settings/reset-data', methods=['POST'])
@admin_required
def reset_data():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    witness_id = request.form.get('witness_id')
    witness_password = request.form.get('witness_password', '')
    reason = request.form.get('reason', '').strip()
    
    # Validate current user credentials
    admin_user = User.query.get(session['user_id'])
    if not admin_user or admin_user.username != username:
        flash('Invalid username. Please enter your own username.', 'danger')
        return redirect(url_for('settings'))
    
    if not admin_user.check_password(password):
        flash('Invalid password.', 'danger')
        return redirect(url_for('settings'))
    
    # Validate witness
    if not witness_id:
        flash('A witness is required for data reset.', 'danger')
        return redirect(url_for('settings'))
    
    witness = User.query.get(int(witness_id))
    if not witness or not witness.is_active:
        flash('Invalid witness selected.', 'danger')
        return redirect(url_for('settings'))
    
    if witness.id == admin_user.id:
        flash('You cannot be your own witness.', 'danger')
        return redirect(url_for('settings'))
    
    if not witness.check_password(witness_password):
        flash('Invalid witness password.', 'danger')
        return redirect(url_for('settings'))
    
    if not reason:
        flash('A reason for the data reset is required.', 'danger')
        return redirect(url_for('settings'))
    
    # All validations passed - perform the reset
    Transaction.query.delete()
    DailyCount.query.delete()
    BiennialInventoryItem.query.delete()
    BiennialInventory.query.delete()
    Document.query.delete()
    TheftLossReport.query.delete()
    
    # Reset inventory quantities to 0
    InventoryItem.query.update({'current_quantity': 0})
    
    db.session.commit()
    
    # Log the action with details
    log_audit('data_reset', 'system', None, 
              f'Data reset performed. Witness: {witness.full_name}. Reason: {reason}')
    
    flash(f'All transactions, counts, and documents have been cleared. Witnessed by {witness.full_name}.', 'warning')
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
        if start_date and start_date.strip():
            query = query.filter(Transaction.performed_at >= datetime.strptime(start_date, '%Y-%m-%d'))
        if end_date and end_date.strip():
            query = query.filter(Transaction.performed_at < datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1))
        
        headers = ['Date', 'Type', 'Medication', 'Schedule', 'Lot #', 'Quantity', 'Balance', 'Patient', 'User', 'Witness']
        data = []
        for t in query.order_by(Transaction.performed_at.desc()).all():
            data.append([
                t.performed_at.strftime('%Y-%m-%d %H:%M'),
                t.transaction_type.title(),
                t.inventory_item.medication.name,
                t.inventory_item.medication.schedule,
                t.inventory_item.lot_number or 'N/A',
                str(t.quantity),
                str(t.balance_after),
                t.patient_name or '-',
                t.performer.full_name if t.performer else 'Unknown',
                t.witness.full_name if t.witness else '-'
            ])
        title = 'Transaction History Report'
        
    elif report_type == 'inventory':
        headers = ['Medication', 'Schedule', 'Lot #', 'Quantity', 'Unit', 'Expiration', 'Storage Location']
        data = []
        for i in InventoryItem.query.filter(InventoryItem.current_quantity > 0, InventoryItem.is_active == True).join(Medication).order_by(Medication.schedule, Medication.name).all():
            data.append([
                i.medication.name,
                i.medication.schedule,
                i.lot_number or 'N/A',
                str(i.current_quantity),
                i.unit_count or 'units',
                i.expiration_date.strftime('%Y-%m-%d') if i.expiration_date else 'N/A',
                i.storage_location or '-'
            ])
        title = 'Current Inventory Report'
        
    elif report_type == 'dispensing':
        query = Transaction.query.filter_by(transaction_type='dispense').join(InventoryItem).join(Medication)
        if start_date and start_date.strip():
            query = query.filter(Transaction.performed_at >= datetime.strptime(start_date, '%Y-%m-%d'))
        if end_date and end_date.strip():
            query = query.filter(Transaction.performed_at < datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1))
        
        headers = ['Date', 'Medication', 'Schedule', 'Quantity', 'Patient', 'Prescriber', 'Dispensed By']
        data = []
        for t in query.order_by(Transaction.performed_at.desc()).all():
            data.append([
                t.performed_at.strftime('%Y-%m-%d %H:%M'),
                t.inventory_item.medication.name,
                t.inventory_item.medication.schedule,
                str(t.quantity),
                t.patient_name or '-',
                t.prescriber.full_name if t.prescriber else '-',
                t.performer.full_name if t.performer else 'Unknown'
            ])
        title = 'Dispensing Report'
        
    elif report_type == 'waste':
        query = Transaction.query.filter_by(transaction_type='waste').join(InventoryItem).join(Medication)
        if start_date and start_date.strip():
            query = query.filter(Transaction.performed_at >= datetime.strptime(start_date, '%Y-%m-%d'))
        if end_date and end_date.strip():
            query = query.filter(Transaction.performed_at < datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1))
        
        headers = ['Date', 'Medication', 'Schedule', 'Quantity', 'Reason', 'Wasted By', 'Witness']
        data = []
        for t in query.order_by(Transaction.performed_at.desc()).all():
            data.append([
                t.performed_at.strftime('%Y-%m-%d %H:%M'),
                t.inventory_item.medication.name,
                t.inventory_item.medication.schedule,
                str(t.quantity),
                t.waste_reason or '-',
                t.performer.full_name if t.performer else 'Unknown',
                t.witness.full_name if t.witness else '-'
            ])
        title = 'Waste Report'
        
    elif report_type == 'schedule2':
        headers = ['Medication', 'Lot #', 'Received', 'Current Qty', 'Expiration', 'Storage']
        data = []
        for i in InventoryItem.query.join(Medication).filter(
            Medication.schedule == 'II',
            InventoryItem.is_active == True
        ).order_by(Medication.name).all():
            data.append([
                i.medication.name,
                i.lot_number or 'N/A',
                str(i.quantity_received),
                str(i.current_quantity),
                i.expiration_date.strftime('%Y-%m-%d') if i.expiration_date else 'N/A',
                i.storage_location or '-'
            ])
        title = 'Schedule II Inventory Report'
        
    else:
        headers = ['No data']
        data = []
        title = 'Report'
    
    # Generate output based on format
    if format_type == 'pdf':
        # Generate PDF using reportlab
        from io import BytesIO
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        
        buffer = BytesIO()
        
        # Use landscape for reports with many columns
        page_size = landscape(letter) if len(headers) > 6 else letter
        doc = SimpleDocTemplate(buffer, pagesize=page_size, 
                               leftMargin=0.5*inch, rightMargin=0.5*inch,
                               topMargin=0.5*inch, bottomMargin=0.5*inch)
        
        elements = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=16, spaceAfter=6)
        elements.append(Paragraph(title, title_style))
        
        # Meta info
        meta_text = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        if start_date and end_date:
            meta_text += f" | Date Range: {start_date} to {end_date}"
        meta_style = ParagraphStyle('Meta', parent=styles['Normal'], fontSize=8, textColor=colors.grey)
        elements.append(Paragraph(meta_text, meta_style))
        elements.append(Spacer(1, 12))
        
        # Build table data with headers
        table_data = [headers] + data
        
        # Calculate column widths based on content
        available_width = page_size[0] - 1*inch
        col_width = available_width / len(headers)
        col_widths = [col_width] * len(headers)
        
        # Create table
        table = Table(table_data, colWidths=col_widths, repeatRows=1)
        
        # Style the table
        table_style = TableStyle([
            # Header styling
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2d3748')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            
            # Body styling
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
            ('TOPPADDING', (0, 1), (-1, -1), 4),
            
            # Grid
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('LINEBELOW', (0, 0), (-1, 0), 1, colors.HexColor('#2d3748')),
            
            # Alignment
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ])
        
        # Add alternating row colors
        for i in range(1, len(table_data)):
            if i % 2 == 0:
                table_style.add('BACKGROUND', (0, i), (-1, i), colors.HexColor('#f7fafc'))
        
        table.setStyle(table_style)
        elements.append(table)
        
        # Footer
        elements.append(Spacer(1, 12))
        footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey, alignment=1)
        elements.append(Paragraph(f"Total Records: {len(data)} | Controlled Substances Inventory System", footer_style))
        
        # Build PDF
        doc.build(elements)
        buffer.seek(0)
        
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename={report_type}_report.pdf'}
        )
    
    else:
        # Generate CSV
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
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
    try:
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
    except Exception as e:
        print(f"Database initialization error: {e}")


# Initialize database when running with gunicorn or directly
# This runs once when the module is first imported
with app.app_context():
    try:
        db.create_all()
        
        # Handle schema migrations for new columns
        # SQLite doesn't support ALTER TABLE ADD COLUMN with foreign keys well
        # So we need to check and add columns manually if they don't exist
        from sqlalchemy import inspect, text
        inspector = inspect(db.engine)
        
        existing_tables = inspector.get_table_names()
        
        # Check if patient_id column exists in transaction table
        if 'transaction' in existing_tables:
            transaction_columns = [c['name'] for c in inspector.get_columns('transaction')]
            if 'patient_id' not in transaction_columns:
                try:
                    db.session.execute(text('ALTER TABLE "transaction" ADD COLUMN patient_id INTEGER'))
                    db.session.commit()
                    print("Added patient_id column to transaction table")
                except Exception as e:
                    print(f"Could not add patient_id to transaction: {e}")
                    db.session.rollback()
        
        # Check if patient table exists, if not create it
        if 'patient' not in existing_tables:
            db.create_all()
            print("Created patient table")
        
        # Check if patient_id column exists in patient_medication table
        if 'patient_medication' in existing_tables:
            pm_columns = [c['name'] for c in inspector.get_columns('patient_medication')]
            if 'patient_id' not in pm_columns:
                try:
                    db.session.execute(text('ALTER TABLE patient_medication ADD COLUMN patient_id INTEGER'))
                    db.session.commit()
                    print("Added patient_id column to patient_medication table")
                except Exception as e:
                    print(f"Could not add patient_id to patient_medication: {e}")
                    db.session.rollback()
        
        # Check if low_stock_threshold column exists in medication table
        if 'medication' in existing_tables:
            med_columns = [c['name'] for c in inspector.get_columns('medication')]
            if 'low_stock_threshold' not in med_columns:
                try:
                    db.session.execute(text('ALTER TABLE medication ADD COLUMN low_stock_threshold INTEGER DEFAULT 10'))
                    db.session.commit()
                    print("Added low_stock_threshold column to medication table")
                except Exception as e:
                    print(f"Could not add low_stock_threshold to medication: {e}")
                    db.session.rollback()
            
            # Add reorder columns to medication
            if 'reorder_point' not in med_columns:
                try:
                    db.session.execute(text('ALTER TABLE medication ADD COLUMN reorder_point INTEGER'))
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
            if 'reorder_quantity' not in med_columns:
                try:
                    db.session.execute(text('ALTER TABLE medication ADD COLUMN reorder_quantity INTEGER'))
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
        
        # Add new columns to user table (quote "user" for PostgreSQL)
        if 'user' in existing_tables:
            user_columns = [c['name'] for c in inspector.get_columns('user')]
            new_user_cols = [
                ('dea_expiration', 'DATE'),
                ('can_prescribe_schedule_2', 'BOOLEAN DEFAULT FALSE'),
                ('state_license', 'VARCHAR(30)')
            ]
            for col_name, col_type in new_user_cols:
                if col_name not in user_columns:
                    try:
                        db.session.execute(text(f'ALTER TABLE "user" ADD COLUMN {col_name} {col_type}'))
                        db.session.commit()
                        print(f"Added {col_name} column to user table")
                    except Exception as e:
                        print(f"Could not add {col_name} to user: {e}")
                        db.session.rollback()
        
        # Add new columns to inventory_item table
        if 'inventory_item' in existing_tables:
            inv_columns = [c['name'] for c in inspector.get_columns('inventory_item')]
            new_inv_cols = [
                ('supplier_id', 'INTEGER'),
                ('form222_id', 'INTEGER'),
                ('is_quarantined', 'BOOLEAN DEFAULT FALSE'),
                ('quarantine_reason', 'VARCHAR(200)')
            ]
            for col_name, col_type in new_inv_cols:
                if col_name not in inv_columns:
                    try:
                        db.session.execute(text(f'ALTER TABLE inventory_item ADD COLUMN {col_name} {col_type}'))
                        db.session.commit()
                        print(f"Added {col_name} column to inventory_item table")
                    except Exception as e:
                        print(f"Could not add {col_name} to inventory_item: {e}")
                        db.session.rollback()
        
        # Create new tables if they don't exist
        db.create_all()
        
        # Check if admin exists (need to handle potential missing columns gracefully)
        try:
            admin = db.session.execute(text('SELECT id FROM "user" WHERE username = :u'), {'u': 'admin'}).first()
            if not admin:
                admin = User(
                    username='admin',
                    full_name='System Administrator',
                    role='admin'
                )
                admin.set_password('changeme123')
                db.session.add(admin)
                db.session.commit()
                print("Default admin user created. Username: admin, Password: changeme123")
        except Exception as e:
            print(f"Admin check error: {e}")
    except Exception as e:
        print(f"Database initialization: {e}")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
