import os
import hashlib
import smtplib
import secrets  # For cryptographically secure random numbers
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import gc
from functools import wraps # NEW: For creating custom security decorators
from datetime import datetime, timedelta

# IMPORTS FOR 2FA
import pyotp
import qrcode
import io
import base64
import re
import random


# IMPORTS FOR ENCRYPTION & ASYNC DB
from cryptography.fernet import Fernet
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi.responses import StreamingResponse
from PIL import Image, UnidentifiedImageError
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, abort # Added abort
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import SQLAlchemyError
from dotenv import load_dotenv
from datetime import timedelta
from flask import request, jsonify

# RATE LIMITING IMPORTS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# AUTH IMPORTS
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature  
from flask_wtf.csrf import CSRFProtect  

# DB AND VALIDATOR IMPORTS
from models import db, RecoveryEntry, User, save_to_nosql_vault
from validators import anonymize_filename, is_authorized_upload

# FASTAPI INTEGRATION IMPORTS 
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Request, Depends
from fastapi.middleware.wsgi import WSGIMiddleware
from crypto import secure_chunked_ingestion 
import uvicorn 
from typing import Optional

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
csrf = CSRFProtect(app) 

# --- Rate Limiter Setup ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    # This disables the rate limiter automatically when pytest is running!
    default_limits_exempt_when=lambda: app.config.get('TESTING', False)
)

# --- Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault_core.db'
app.config['UPLOAD_FOLDER'] = 'static/img'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise RuntimeError("SECRET_KEY not set in environment variables. Please set it in your .env file.")

# --- Strict Encryption Setup ---
# --- Strict Encryption Setup ---
app.config['ENCRYPTION_KEY'] = os.environ.get('ENCRYPTION_KEY')
if not app.config['ENCRYPTION_KEY']:
    raise RuntimeError("CRITICAL ERROR: ENCRYPTION_KEY not set in .env file! Please generate one and add it.")
cipher_suite = Fernet(app.config['ENCRYPTION_KEY'])

# --- MongoDB GridFS Setup ---
import gridfs
from pymongo import MongoClient
from bson.objectid import ObjectId # Added to fix ObjectId error in download route

mongo_client = MongoClient(os.environ.get("MONGO_URI", "mongodb://localhost:27017/"))
mongo_db = mongo_client["bhv_database"] # Matched the DB name used in your ingest_record route
fs = gridfs.GridFS(mongo_db, collection="vaulted_narratives") # Matched your collection name

db.init_app(app)

# --- Auth & Session Setup ---
login_manager = LoginManager()
login_manager.login_view = 'login_page'
login_manager.login_message_category = 'error'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- GLOBAL SECURITY HEADERS ---
@app.after_request
def add_security_headers(response):
    """
    Adds critical HTTP security headers to every response sent by the server.
    """
    # Prevents attackers from embedding your site in an iframe (Clickjacking protection)
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Forces the browser to strictly follow the declared content type (MIME-sniffing protection)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Tells browsers to ONLY connect via HTTPS for the next year (HSTS)
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
# ==========================================
#          CUSTOM ROLE DECORATORS (RBAC)
# ==========================================
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role not in ['admin', 'owner']:
            abort(403) # Returns a 403 Forbidden error
        return f(*args, **kwargs)
    return decorated_function

def owner_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'owner':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# --- Google OAuth Setup ---
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# --- Email Token Setup ---
token_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def send_otp_email(user_email, otp):
    sender = os.environ.get('MAIL_USERNAME')
    password = os.environ.get('MAIL_PASSWORD')
    
    if not sender or not password:
        print("WARNING: Email credentials missing. OTP not sent.")
        return

    msg = MIMEMultipart()
    msg['From'] = f"Recovery Vault <{sender}>"
    msg['To'] = user_email
    msg['Subject'] = "Password Reset OTP"
    
    body = f"Your One-Time Password (OTP) for resetting your password is: {otp}\n\nIf you did not request this, please secure your account immediately."
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender, password)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print(f"Failed to send OTP email: {e}")

def send_verification_email(user_email, token):
    sender = os.environ.get('MAIL_USERNAME')
    password = os.environ.get('MAIL_PASSWORD')
    
    if not sender or not password:
        print("WARNING: Email credentials missing in .env. Email not sent.")
        return

    link = url_for('verify_email', token=token, _external=True)
    
    msg = MIMEMultipart()
    msg['From'] = f"Recovery Vault <{sender}>"
    msg['To'] = user_email
    msg['Subject'] = "Verify your Recovery Vault Account"
    
    body = f"Welcome!\n\nPlease click the link below to verify your account:\n{link}\n\nThis link expires in 1 hour."
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender, password)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print(f"Failed to send email: {e}")

IMAGE_EXTENSIONS = ('.png', '.jpg', '.jpeg', '.gif', '.webp')

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    flash("Error: File is too large. Maximum size is 100MB.", "error")
    return redirect(url_for('upload_page'))

# ==========================================
#              PUBLIC ROUTES
# ==========================================

@app.route('/')
def welcome():
    return render_template('welcome.html')

# ==========================================
#          AUTHENTICATION ROUTES
# ==========================================

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", exempt_when=lambda: app.config.get('TESTING', False))
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('welcome'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.password_hash and check_password_hash(user.password_hash, password):
            if not user.is_verified:
                flash("Please verify your email address first.", "error")
                return redirect(url_for('login_page'))
            
            if user.is_2fa_enabled:
                session['pending_2fa_user_id'] = user.id
                return redirect(url_for('login_2fa_prompt'))
                
            login_user(user, remember=True)
            flash(f"Welcome back, {user.name}!", "success")
            return redirect(url_for('welcome'))
        else:
            flash("Invalid email or password.", "error")
            
    return render_template('login.html')

@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa_prompt():
    if 'pending_2fa_user_id' not in session:
        return redirect(url_for('login_page'))

    if request.method == 'POST':
        code = request.form.get('code')
        user = db.session.get(User, session['pending_2fa_user_id'])
        
        if not user:
            return redirect(url_for('login_page'))

        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(code):
            login_user(user, remember=True)
            session.pop('pending_2fa_user_id', None)
            flash("Authentication successful.", "success")
            return redirect(url_for('welcome'))
        else:
            flash("Invalid 2FA code.", "error")
            
    return render_template('login_2fa.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # --- NEW: If they refresh the page, just show them the form ---
    if request.method == 'GET':
        return render_template('login.html')
    # -------------------------------------------------------------

    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')

    # --- Password Strength Check ---
    # Regex checks for: 8+ chars, 1 uppercase, 1 lowercase, 1 number, 1 special char
    password_pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
    
    if not password_pattern.match(password):
        flash('Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number, and a special character.', 'error')
        return redirect(url_for('login_page'))
    # ------------------------------------

    if User.query.filter_by(email=email).first():
        flash("Email already registered. Try logging in.", "error")
        return redirect(url_for('login_page'))

    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(name=name, email=email, password_hash=hashed_pw, is_verified=False)
    
    db.session.add(new_user)
    db.session.commit()

    token = token_serializer.dumps(email, salt='email-verify')
    send_verification_email(email, token)

    flash("Account created! Please check your email to verify your account.", "success")
    return redirect(url_for('login_page'))

@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = token_serializer.loads(token, salt='email-verify', max_age=3600)
    except (SignatureExpired, BadTimeSignature): 
        flash("The verification link is invalid or has expired.", "error")
        return redirect(url_for('login_page'))

    user = User.query.filter_by(email=email).first()
    if user:
        if user.is_verified:
            flash("Account already verified. Please log in.", "success")
        else:
            user.is_verified = True
            db.session.commit()
            flash("Email verified successfully! You can now log in.", "success")
    
    return redirect(url_for('login_page'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for('welcome'))

@app.route('/send-otp', methods=['POST'])
@csrf.exempt  
def send_otp():
    """Generates an OTP and emails it to the user."""
    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({"success": False, "message": "Email is required."})
        
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": True, "message": "If the email is registered, an OTP has been sent."})
        
    otp = str(secrets.randbelow(900000) + 100000)
    session['reset_otp'] = otp
    session['reset_email'] = email
    
    send_otp_email(email, otp)
    return jsonify({"success": True, "message": "OTP sent to your email!"})

@app.route('/reset-password', methods=['POST'])
def reset_password():
    """Verifies the OTP and updates the password."""
    email = request.form.get('email')
    otp = request.form.get('otp')
    new_password = request.form.get('password') 
    
    if not email or not otp or not new_password:
        flash("All fields are required.", "error")
        return redirect(url_for('login_page'))

    if session.get('reset_email') != email or session.get('reset_otp') != otp:
        flash("Invalid or expired OTP.", "error")
        return redirect(url_for('login_page'))
    
    user = User.query.filter_by(email=email).first()
    if user:
        user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()
        flash("Password reset successfully! You can now log in.", "success")
        
        session.pop('reset_otp', None)
        session.pop('reset_email', None)
    
    return redirect(url_for('login_page'))

@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/google')
def google_authorize():
    token = google.authorize_access_token()
    user_info = google.parse_id_token(token, nonce=None)
    
    email = user_info.get('email')
    name = user_info.get('name')

    user = User.query.filter_by(email=email).first()

    if not user:
        user = User(name=name, email=email, is_verified=True)
        db.session.add(user)
        db.session.commit()

    login_user(user, remember=True)
    flash(f"Logged in via Google as {name}", "success")
    return redirect(url_for('welcome'))

# ==========================================
#          PROTECTED APP ROUTES
# ==========================================

# --- ADMIN DASHBOARD ---
# --- REAL-TIME GROWTH DATA HELPER ---
def get_user_growth_data():
    """Calculates real registrations over the last 7 days."""
    today = datetime.utcnow().date()
    dates = [(today - timedelta(days=i)) for i in range(6, -1, -1)]
    labels = [d.strftime('%b %d') for d in dates]
    
    admin_data = [0] * 7
    user_data = [0] * 7
    
    all_users = User.query.all()
    for u in all_users:
        if u.created_at:
            u_date = u.created_at.date()
            if u_date in dates:
                idx = dates.index(u_date)
                if u.role == 'admin':
                    admin_data[idx] += 1
                elif u.role == 'user':
                    user_data[idx] += 1
                    
    return {"labels": labels, "admin_data": admin_data, "user_data": user_data}

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    # 1. Real Stats
    patients_count = User.query.filter_by(role='user').count()
    records_count = RecoveryEntry.query.count()
    recent_activity = RecoveryEntry.query.order_by(RecoveryEntry.created_at.desc()).limit(5).all()
    
    # 2. Fetch the actual list of patients for the directory table
    all_patients = User.query.filter_by(role='user').all()
    
    # 3. Bundle specifically for the template
    stats = {"total_patients": patients_count, "total_records": records_count}
    graph_data = get_user_growth_data()
    
    return render_template(
        'admin_dashboard.html', 
        user=current_user, 
        stats=stats, 
        recent_activity=recent_activity,
        graph_data=graph_data,
        patients=all_patients 
    )

@app.route('/admin/download-record/<int:record_id>')
@login_required
@admin_required
def admin_download_record(record_id):
    # 1. Fetch the metadata from SQLite
    record = RecoveryEntry.query.get_or_404(record_id)
    
    # 2. Security Check: Ensure the file belongs to a standard patient
    target_user = User.query.get(record.user_id)
    if target_user.role in ['admin', 'owner']:
        flash("Unauthorized: Cannot download staff vault records.", "error")
        return redirect(url_for('admin_dashboard'))

    try:
        # 3. Fetch the file directly from MongoDB using the filename
        # Based on your serve_file route, you save them with the 'stored_filename'
        client = MongoClient(os.environ.get("MONGO_URI", "mongodb://localhost:27017/"))
        vault_collection = client.bhv_database.vaulted_narratives
        nosql_record = vault_collection.find_one({"filename": record.stored_filename, "user_id": target_user.id})
        client.close()

        if not nosql_record:
            flash("System Error: Record metadata exists, but file is missing from Vault.", "error")
            return redirect(url_for('admin_view_user_vault', target_user_id=target_user.id))

        # 4. Decrypt the payload
        encrypted_data = nosql_record['payload']
        decrypted_bytes = cipher_suite.decrypt(encrypted_data)
        
        # 5. Serve the decrypted file directly to the admin's browser
        buffer = io.BytesIO(decrypted_bytes)
        buffer.seek(0)
        
        mimetype = 'application/octet-stream'
        if record.stored_filename.lower().endswith(IMAGE_EXTENSIONS):
            mimetype = f'image/{record.stored_filename.split(".")[-1].replace("jpg", "jpeg")}'
            
        return send_file(
            buffer,
            as_attachment=True,
            download_name=record.display_name,
            mimetype=mimetype
        )
        
    except Exception as e:
        print(f"Decryption Error: {e}")
        flash("System Error: Could not decrypt this file. The encryption key may be invalid or missing.", "error")
        return redirect(url_for('admin_view_user_vault', target_user_id=record.user_id))


@app.route('/admin/user-vault/<int:target_user_id>')
@login_required
@admin_required
def admin_view_user_vault(target_user_id):
    # Get the requested user
    target_user = User.query.get_or_404(target_user_id)
    
    # Security check: Admins should only view patients ('user' role)
    if target_user.role in ['admin', 'owner']:
        flash("Unauthorized: You cannot view the vaults of other staff members.", "error")
        return redirect(url_for('admin_dashboard'))
        
    # Fetch all records belonging to this specific patient
    user_records = RecoveryEntry.query.filter_by(user_id=target_user.id).order_by(RecoveryEntry.created_at.desc()).all()
    
    return render_template('admin_view_vault.html', target_user=target_user, records=user_records)


# --- OWNER DASHBOARD ---
@app.route('/owner/dashboard')
@login_required
@owner_required
def owner_dashboard():
    all_users = User.query.all()
    active_admins = sum(1 for u in all_users if u.role == 'admin')
    
    system_health = {"db_status": "Online", "active_admins": active_admins}
    graph_data = get_user_growth_data()
    
    return render_template(
        'owner_dashboard.html', 
        user=current_user, 
        health=system_health,
        all_users=all_users,
        graph_data=graph_data
    )

# --- UPDATE USER ROLE ROUTE ---
@app.route('/owner/update-role/<int:target_user_id>', methods=['POST'])
@login_required
@owner_required
def update_user_role(target_user_id):
    target_user = User.query.get_or_404(target_user_id)
    new_role = request.form.get('role')

    # Security: Prevent self-demotion or owner modification
    if target_user.role == 'owner':
        flash("System Owner privileges are immutable.", "error")
    elif new_role in ['user', 'admin']:
        target_user.role = new_role
        db.session.commit()
        flash(f"Access level for {target_user.name} changed to {new_role}.", "success")
    else:
        flash("Invalid role assignment.", "error")

    return redirect(url_for('owner_dashboard'))

# ==========================================
#          PROTECTED APP ROUTES
# ==========================================

@app.route('/profile')
@login_required
def profile_page():
    record_count = len(current_user.entries)
    return render_template('profile.html', record_count=record_count)

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    new_name = request.form.get('name')
    # We ignore the email field here completely because it is 
    # securely handled by the OTP API routes now!

    # 1. Update Name
    if new_name and new_name != current_user.name:
        current_user.name = new_name

    # 2. Update Profile Picture
    file = request.files.get('profile_pic')
    if file and file.filename != '':
        if file.filename.lower().endswith(IMAGE_EXTENSIONS):
            filename = secure_filename(file.filename)
            unique_filename = f"user_{current_user.id}_{filename}"
            
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            
            current_user.profile_image = unique_filename
        else:
            flash("Invalid file type. Please upload a valid image.", "error")
            return redirect(url_for('profile_page'))

    # 3. Save Changes
    try:
        db.session.commit()
        flash("Profile updated successfully.", "success")
    except Exception as e:
        app.logger.error(f"Profile Update Error: {e}")
        db.session.rollback()
        flash("A system error occurred while saving your changes.", "error")

    return redirect(url_for('profile_page'))

# --- SECURE EMAIL UPDATE PIPELINE ---

@app.route('/request-email-update', methods=['POST'])
@login_required
def request_email_update():
    new_email = request.form.get('new_email')
    
    # 1. Validation
    if not new_email or new_email == current_user.email:
        return jsonify({"error": "Invalid or identical email."}), 400
        
    if User.query.filter_by(email=new_email).first():
        return jsonify({"error": "Email already in use."}), 400

    # 2. Generate the 6-digit OTP
    otp = str(random.randint(100000, 999999))
    
    # 3. USE YOUR EXISTING EMAIL FUNCTION!
    # (If your existing function requires a subject and body, just format them here)
    try:
        send_otp_email(new_email, otp) 
    except Exception as e:
        print(f"Failed to send email: {e}")
        return jsonify({"error": "Failed to send email. Please try again later."}), 500
    
    # 4. Save to database only IF the email successfully sent
    current_user.pending_email = new_email
    current_user.update_otp = otp 
    current_user.update_otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    db.session.commit()
    
    return jsonify({"success": "OTP sent to your new email."}), 200

@app.route('/verify-email-update', methods=['POST'])
@login_required
def verify_email_update():
    user_otp = request.form.get('otp')
    
    if not current_user.pending_email or not current_user.update_otp:
        return jsonify({"error": "No email update pending."}), 400
        
    if datetime.utcnow() > current_user.update_otp_expiry:
        return jsonify({"error": "OTP has expired."}), 400
        
    if user_otp != current_user.update_otp:
        return jsonify({"error": "Invalid OTP. Please try again."}), 400
        
    current_user.email = current_user.pending_email
    current_user.pending_email = None
    current_user.update_otp = None
    current_user.update_otp_expiry = None
    db.session.commit()
    
    return jsonify({"success": "Email updated successfully!"}), 200

@app.route('/profile/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    
    if not current_user.password_hash:
        flash("Accounts created via Google cannot change passwords here.", "error")
        return redirect(url_for('profile_page'))

    if not check_password_hash(current_user.password_hash, current_password):
        flash("Incorrect current password.", "error")
        return redirect(url_for('profile_page'))

    current_user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
    db.session.commit()
    flash("Password updated successfully.", "success")
    return redirect(url_for('profile_page'))

@app.route('/profile/setup-2fa')
@login_required
def setup_2fa():
    if current_user.is_2fa_enabled:
        flash("2FA is already enabled on your account.", "success")
        return redirect(url_for('profile_page'))

    if 'totp_secret' not in session:
        session['totp_secret'] = pyotp.random_base32()
    
    secret = session['totp_secret']
    totp = pyotp.TOTP(secret)
    
    provisioning_uri = totp.provisioning_uri(name=current_user.email, issuer_name="Recovery Vault")
    
    qr = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return render_template('setup_2fa.html', secret=secret, qr_base64=qr_base64)

@app.route('/profile/verify-2fa', methods=['POST'])
@login_required
def verify_2fa_setup():
    code = request.form.get('code')
    secret = session.get('totp_secret')

    if not secret:
        return redirect(url_for('setup_2fa'))

    totp = pyotp.TOTP(secret)
    if totp.verify(code):
        current_user.totp_secret = secret
        current_user.is_2fa_enabled = True
        db.session.commit()
        session.pop('totp_secret', None)
        flash("Two-Factor Authentication successfully enabled! 🛡️", "success")
        return redirect(url_for('profile_page'))
    else:
        flash("Invalid authentication code. Please try again.", "error")
        return redirect(url_for('setup_2fa'))

@app.route('/upload')
@login_required
def upload_page():
    return render_template('upload.html')

@app.route('/gallery')
@login_required
def gallery_page():
    entries = RecoveryEntry.query.filter_by(user_id=current_user.id).order_by(RecoveryEntry.created_at.desc()).all()
    return render_template('gallery.html', entries=entries, image_extensions=IMAGE_EXTENSIONS)

@app.route('/ingest', methods=['POST'])
@login_required
async def ingest_record():
    file = request.files.get('file')
    narrative = request.form.get('narrative')
    
    if not file or file.filename == '':
        flash("No file selected.", "error")
        return redirect(url_for('upload_page'))

    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)

    if not is_authorized_upload(file.filename, file_size):
        flash("Error: Invalid file type or size.", "error")
        return redirect(url_for('upload_page'))

    secure_name = anonymize_filename(file.filename)
    safe_display_name = secure_filename(file.filename)
    is_image = file.filename.lower().endswith(IMAGE_EXTENSIONS)
    
    try:
        file_stream = None
        if is_image:
            try:
                img = Image.open(file)
                img.verify() 
                file.seek(0)
                
                img = Image.open(file)
                data = img.getdata()
                clean_image = Image.new(img.mode, img.size)
                clean_image.putdata(data)
                
                clean_buffer = io.BytesIO()
                fmt = img.format if img.format else 'PNG'
                clean_image.save(clean_buffer, format=fmt)
                
                clean_buffer.seek(0)
                file_stream = clean_buffer
            except Exception:
                file.seek(0)
                file_stream = file
        else:
            file.seek(0)
            file_stream = file

        sha256_hash = hashlib.sha256()
        current_pos = file_stream.tell()
        for byte_block in iter(lambda: file_stream.read(4096), b""):
            sha256_hash.update(byte_block)
        
        file_stream.seek(current_pos)
        digital_fingerprint = sha256_hash.hexdigest()

        file_bytes = file_stream.getvalue() if hasattr(file_stream, 'getvalue') else file_stream.read()
        encrypted_data = cipher_suite.encrypt(file_bytes)
        
        await save_to_nosql_vault(
            user_id=current_user.id,
            filename=secure_name,
            encrypted_payload=encrypted_data,
            metadata={'narrative': narrative, 'file_hash': digital_fingerprint}
        )
        
        entry = RecoveryEntry(
            stored_filename=secure_name, 
            display_name=safe_display_name, 
            narrative_text=narrative,
            file_hash=digital_fingerprint,
            user_id=current_user.id 
        )
        db.session.add(entry)
        db.session.commit()
        
        flash("Record secured successfully.", "success")
        return redirect(url_for('gallery_page'))
    
    except (OSError, SQLAlchemyError) as e:
        app.logger.error(f"Error: {e}")
        flash("System error saving the record.", "error")
        return redirect(url_for('upload_page'))

@app.route('/delete/<int:entry_id>', methods=['POST'])
@login_required
async def delete_record(entry_id: int):
    entry = RecoveryEntry.query.get_or_404(entry_id)
    
    if entry.user_id != current_user.id:
        flash("Unauthorized action.", "error")
        return redirect(url_for('gallery_page'))
        
    try:
        db.session.delete(entry)
        db.session.commit()
        
        client = AsyncIOMotorClient(os.getenv("MONGO_URI", "mongodb://localhost:27017"))
        vault_collection = client.bhv_database.vaulted_narratives
        await vault_collection.delete_one({"filename": entry.stored_filename, "user_id": current_user.id})
        client.close()
        
        flash("Record deleted permanently.", "success")
    except Exception as e:
        app.logger.error(f"Deletion Error: {e}")
        flash("Error deleting record.", "error")
    
    return redirect(url_for('gallery_page'))

@app.route('/vault/file/<filename>')
@login_required
async def serve_file(filename):
    entry = RecoveryEntry.query.filter_by(stored_filename=filename).first_or_404()
    
    if entry.user_id != current_user.id:
        flash("Unauthorized access.", "error")
        return redirect(url_for('gallery_page'))
        
    try:
        client = AsyncIOMotorClient(os.getenv("MONGO_URI", "mongodb://localhost:27017"))
        vault_collection = client.bhv_database.vaulted_narratives
        nosql_record = await vault_collection.find_one({"filename": filename, "user_id": current_user.id})
        client.close()
        
        if not nosql_record:
            flash("Record not found in Vault.", "error")
            return redirect(url_for('gallery_page'))

        encrypted_data = nosql_record['payload']
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        
        buffer = io.BytesIO(decrypted_data)
        buffer.seek(0)
        
        mimetype = 'application/octet-stream'
        if filename.lower().endswith(IMAGE_EXTENSIONS):
            mimetype = f'image/{filename.split(".")[-1].replace("jpg", "jpeg")}'
        
        return send_file(buffer, download_name=entry.display_name, mimetype=mimetype)
        
    except Exception as e:
        app.logger.error(f"Decryption error: {e}")
        return "Error decrypting file. It may be corrupted.", 500


# ==========================================
#          FASTAPI (API & STREAMING) ROUTES
# ==========================================
fastapi_app = FastAPI(title="BHV Fast Vault Gateway")

@fastapi_app.post("/api/vault/upload")
async def upload_visual_narrative(
    patient_id: str = Form(...),
    file: UploadFile = File(...)
):
    try:
        from crypto import stream_security
        from models import stream_to_nosql_vault
        
        # 1. Setup the streamable cipher
        iv, encryptor = stream_security.get_encryptor()
        sha256_hash = hashlib.sha256()

        # 2. The Generator: This is the core of Radical Minimalism.
        # It never holds more than 64KB in RAM at any given millisecond.
        async def encrypting_generator():
            while chunk := await file.read(65536):  # 64KB increments
                sha256_hash.update(chunk)
                # Yield encrypted data immediately
                yield encryptor.update(chunk)       
            yield encryptor.finalize()

        # 3. Metadata for searchability
        metadata = {
            "patient_id": patient_id,
            "sync_status": "pending_sync",
            "file_extension": file.filename.split(".")[-1] if file.filename else "unknown"
        }

        # 4. Execute the stream (User -> Generator -> Encryptor -> GridFS)
        file_id = await stream_to_nosql_vault(
            user_id=patient_id,
            filename=file.filename,
            iv=iv,
            metadata=metadata,
            async_chunk_generator=encrypting_generator()
        )

        return {
            "status": "success",
            "vault_id": file_id,
            "integrity_hash": sha256_hash.hexdigest(),
            "sync_status": metadata["sync_status"]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Streaming failed: {str(e)}")
    

@fastapi_app.get("/api/vault/download/{file_id}")
async def download_visual_narrative(
    file_id: str,
    patient_id: str # We pass this to verify ownership
):
    from crypto import stream_security
    from models import get_nosql_download_stream
    
    try:
        # 1. Retrieve the DB stream and the Decryption IV
        grid_out, iv, db_client, filename = await get_nosql_download_stream(file_id, int(patient_id))
    except Exception as e:
        raise HTTPException(status_code=403, detail=str(e))
        
    # 2. Initialize the decryptor using the file's unique IV
    decryptor = stream_security.get_decryptor(iv)
    
    # 3. The Generator (The Decryption Nozzle)
    async def decrypting_generator():
        try:
            # GridFS naturally chunks data (usually 255KB). We read one chunk at a time.
            while chunk := await grid_out.readchunk(): 
                decrypted_chunk = decryptor.update(chunk)
                
                # Yield to the browser immediately
                yield decrypted_chunk
                
            # Finalize the cipher stream
            yield decryptor.finalize()
            
        finally:
            # CLEANUP: This block runs even if the user cancels the download halfway through.
            # It ensures we never leak database connections or memory.
            db_client.close()
            gc.collect()
            
    # 4. Stream the response directly to the client
    return StreamingResponse(
        decrypting_generator(), 
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="decrypted_{filename}"'}
    )


@fastapi_app.get("/api/vault/search")
async def search_vault(
    patient_id: Optional[str] = Query(None, description="Filter by patient ID"),
    sync_status: Optional[str] = Query(None, description="Filter by sync state (e.g., pending_sync)"),
    file_extension: Optional[str] = Query(None, description="Filter by extension (e.g., enc, bin)"),
    skip: int = Query(0, ge=0, description="Number of records to skip for pagination"),
    limit: int = Query(10, ge=1, le=100, description="Max records to return per page")
):
    """
    Search and filter vault metadata using memory-safe database pagination.
    """
    # 1. Initialize MongoDB client inside the function to prevent asyncio conflicts
    MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
    client = AsyncIOMotorClient(MONGO_URI)
    mongo_db = client.bhv_database
    
    # GridFS stores file metadata in the ".files" collection
    files_collection = mongo_db["vaulted_narratives.files"] 
    
    try:
        # 2. Build the dynamic MongoDB query
        query = {}
        
        if patient_id:
            query["metadata.patient_id"] = patient_id 
            
        if sync_status:
            query["metadata.sync_status"] = sync_status
            
        if file_extension:
            # FIX: Added 'r' for raw string to prevent the SyntaxWarning
            query["filename"] = {"$regex": rf"\.{file_extension}$", "$options": "i"}

        # 3. Get the total count for frontend pagination math
        total_records = await files_collection.count_documents(query)

        # 4. Fetch ONLY the requested page of data (The Radical Minimalism approach)
        cursor = files_collection.find(query).skip(skip).limit(limit)
        
        results = []
        async for document in cursor:
            results.append({
                "vault_id": str(document["_id"]),
                "filename": document.get("filename"),
                "patient_id": document.get("metadata", {}).get("patient_id") or document.get("metadata", {}).get("user_id"),
                "sync_status": document.get("metadata", {}).get("sync_status"),
                "size_bytes": document.get("length"),
                "upload_date": document.get("uploadDate").isoformat() if document.get("uploadDate") else None
            })

        return {
            "status": "success",
            "pagination": {
                "total_records": total_records,
                "skip": skip,
                "limit": limit,
                "has_more": (skip + limit) < total_records
            },
            "data": results
        }
    finally:
        # Always close the DB connection to prevent memory leaks!
        client.close()

fastapi_app.mount("/", WSGIMiddleware(app))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # --- NEW: AUTO-BOOTSTRAP THE OWNER ACCOUNT ---
        owner_email = os.environ.get("OWNER_EMAIL")
        owner_pass = os.environ.get("OWNER_PASSWORD")
        
        if owner_email and owner_pass:
            owner_user = User.query.filter_by(email=owner_email).first()
            if not owner_user:
                hashed_pw = generate_password_hash(owner_pass, method='pbkdf2:sha256')
                # Create the owner, skipping email verification so you can log in instantly
                new_owner = User(
                    name="System Architect", 
                    email=owner_email, 
                    password_hash=hashed_pw, 
                    role="owner", 
                    is_verified=True 
                )
                db.session.add(new_owner)
                db.session.commit()
                print(f"👑 Owner account ({owner_email}) securely bootstrapped from .env!")

    uvicorn.run(fastapi_app, host="127.0.0.1", port=8000)