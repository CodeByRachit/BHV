import os
import hashlib
from PIL import Image, UnidentifiedImageError
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
from sqlalchemy.exc import SQLAlchemyError
from models import db, RecoveryEntry
from validators import anonymize_filename

app = Flask(__name__)

# --- Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault_core.db'
app.config['UPLOAD_FOLDER'] = 'static/img'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB Limit
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-for-local-testing')

db.init_app(app)

# Extensions that will be treated as images for preview/processing
IMAGE_EXTENSIONS = ('.png', '.jpg', '.jpeg', '.gif', '.webp')

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    flash("Error: File is too large. Maximum size is 100MB.", "error")
    return redirect(url_for('upload_page'))

# --- ROUTES ---

@app.route('/')
def welcome():
    """Renders the landing page."""
    return render_template('welcome.html')

@app.route('/upload')
def upload_page():
    """Renders the dedicated upload workspace."""
    return render_template('upload.html')

@app.route('/gallery')
def gallery_page():
    """Renders the evidence gallery feed."""
    entries = RecoveryEntry.query.order_by(RecoveryEntry.created_at.desc()).all()
    # Pass image_extensions so the template knows what to render as an <img>
    return render_template('gallery.html', entries=entries, image_extensions=IMAGE_EXTENSIONS)

@app.route('/ingest', methods=['POST'])
def ingest_record():
    file = request.files.get('image')
    narrative = request.form.get('narrative')
    
    if not file or file.filename == '':
        flash("No file selected.", "error")
        return redirect(url_for('upload_page'))

    # 1. Filename & Hashing Preparation
    secure_name = anonymize_filename(file.filename)
    safe_display_name = secure_filename(file.filename)
    
    # Check if we should attempt image processing
    is_image = file.filename.lower().endswith(IMAGE_EXTENSIONS)
    
    try:
        # 2. Processing Stream
        file_stream = None
        
        if is_image:
            try:
                # Attempt to strip metadata if it's an image
                img = Image.open(file)
                img.verify() 
                file.seek(0)
                
                img = Image.open(file)
                data = list(img.getdata())
                clean_image = Image.new(img.mode, img.size)
                clean_image.putdata(data)
                
                import io
                clean_buffer = io.BytesIO()
                # Default to PNG if format is missing, or keep original
                fmt = img.format if img.format else 'PNG'
                clean_image.save(clean_buffer, format=fmt)
                
                clean_buffer.seek(0)
                file_stream = clean_buffer
            except Exception:
                # If image processing fails, fall back to raw file
                file.seek(0)
                file_stream = file
        else:
            # Not an image? Just use the raw file
            file.seek(0)
            file_stream = file

        # 3. Calculate Hash
        sha256_hash = hashlib.sha256()
        # Read stream in blocks
        current_pos = file_stream.tell()
        for byte_block in iter(lambda: file_stream.read(4096), b""):
            sha256_hash.update(byte_block)
        
        file_stream.seek(current_pos) # Reset to where we were
        digital_fingerprint = sha256_hash.hexdigest()

        # 4. Save to Disk
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        destination_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_name)
        
        with open(destination_path, 'wb') as f:
            f.write(file_stream.getbuffer() if hasattr(file_stream, 'getbuffer') else file_stream.read())
        
        # 5. Save to Database
        entry = RecoveryEntry(
            stored_filename=secure_name, 
            display_name=safe_display_name, 
            narrative_text=narrative,
            file_hash=digital_fingerprint
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
def delete_record(entry_id: int):
    entry = RecoveryEntry.query.get_or_404(entry_id)
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
    
    if not os.environ.get('FLASK_DEBUG'):
        os.environ['FLASK_DEBUG'] = 'true'
    
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode, port=8000)