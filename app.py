import os
import hashlib
import smtplib
import random
import secrets  # ADDED: For cryptographically secure random numbers
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from PIL import Image, UnidentifiedImageError
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import SQLAlchemyError
from dotenv import load_dotenv

# AUTH IMPORTS
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature  # CHANGED: Added specific exceptions
from flask_wtf.csrf import CSRFProtect  # ADDED: CSRF Protection

from models import db, RecoveryEntry, User
from validators import anonymize_filename, is_authorized_upload

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
csrf = CSRFProtect(app)  # ADDED: Initialize CSRF protection globally

# --- Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault_core.db'
app.config['UPLOAD_FOLDER'] = 'static/img'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# CHANGED: Removed hardcoded fallback to secure session management
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise RuntimeError("SECRET_KEY not set in environment variables. Please set it in your .env file.")

db.init_app(app)

# --- Auth & Session Setup ---
login_manager = LoginManager()
login_manager.login_view = 'login_page'
login_manager.login_message_category = 'error'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    # FIXED: Replaced legacy Query.get() to remove the SQLAlchemy warning
    return db.session.get(User, int(user_id))

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
def login_page():
    if current_user.is_authenticated:
        # CHANGED: Redirects to home (welcome) if already logged in
        return redirect(url_for('welcome'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.password_hash and check_password_hash(user.password_hash, password):
            if not user.is_verified:
                flash("Please verify your email address first.", "error")
                return redirect(url_for('login_page'))
                
            login_user(user, remember=True)
            flash(f"Welcome back, {user.name}!", "success")
            # CHANGED: Redirects to home (welcome) after successful login
            return redirect(url_for('welcome'))
        else:
            flash("Invalid email or password.", "error")
            
    return render_template('login.html')

@app.route('/signup', methods=['POST'])
def signup():
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')

    if User.query.filter_by(email=email).first():
        flash("Email already registered. Try logging in.", "error")
        return redirect(url_for('login_page'))

    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(name=name, email=email, password_hash=hashed_pw, is_verified=False)
    
    db.session.add(new_user)
    db.session.commit()

    # Generate and send verification email
    token = token_serializer.dumps(email, salt='email-verify')
    send_verification_email(email, token)

    flash("Account created! Please check your email to verify your account.", "success")
    return redirect(url_for('login_page'))

@app.route('/verify/<token>')
def verify_email(token):
    try:
        # Token expires in 3600 seconds (1 hour)
        email = token_serializer.loads(token, salt='email-verify', max_age=3600)
    except (SignatureExpired, BadTimeSignature):  # CHANGED: Specific exception handling
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

# --- OTP and Password Reset Routes ---
# Exempt the send_otp route from CSRF if you are calling it via fetch/AJAX without sending the CSRF token in headers. 
# Alternatively, pass the CSRF token in your frontend fetch request.
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
        # We pretend it succeeded to prevent hackers from guessing emails
        return jsonify({"success": True, "message": "If the email is registered, an OTP has been sent."})
        
    # CHANGED: Generate 6 digit OTP securely using secrets module
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

    # Verify the OTP matches the one we saved in the session
    if session.get('reset_email') != email or session.get('reset_otp') != otp:
        flash("Invalid or expired OTP.", "error")
        return redirect(url_for('login_page'))
    
    user = User.query.filter_by(email=email).first()
    if user:
        # Hash the new password and save it
        user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()
        flash("Password reset successfully! You can now log in.", "success")
        
        # Clear the OTP from session so it can't be reused
        session.pop('reset_otp', None)
        session.pop('reset_email', None)
    
    return redirect(url_for('login_page'))

# --- Google OAuth Routes ---
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
        # Create user automatically, mark as verified since Google vouches for them
        user = User(name=name, email=email, is_verified=True)
        db.session.add(user)
        db.session.commit()

    login_user(user, remember=True)
    flash(f"Logged in via Google as {name}", "success")
    # CHANGED: Redirects to home (welcome) after Google login
    return redirect(url_for('welcome'))


# ==========================================
#          PROTECTED APP ROUTES
# ==========================================

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
def ingest_record():
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
                
                import io
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

        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        destination_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_name)
        
        with open(destination_path, 'wb') as f:
            f.write(file_stream.getbuffer() if hasattr(file_stream, 'getbuffer') else file_stream.read())
        
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
def delete_record(entry_id: int):
    entry = RecoveryEntry.query.get_or_404(entry_id)
    
    if entry.user_id != current_user.id:
        flash("Unauthorized action.", "error")
        return redirect(url_for('gallery_page'))
        
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], entry.stored_filename)
    
    try:
        db.session.delete(entry)
        db.session.commit()
        if os.path.exists(file_path):
            os.remove(file_path)
        flash("Record deleted permanently.", "success")
    except Exception as e:
        app.logger.error(f"Deletion Error: {e}")
        flash("Error deleting record.", "error")
    
    return redirect(url_for('gallery_page'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    app.run(port=8000)