import os
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
from sqlalchemy.exc import SQLAlchemyError
from models import db, RecoveryEntry
from validators import is_authorized_upload, anonymize_filename

app = Flask(__name__)

# --- Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault_core.db'
app.config['UPLOAD_FOLDER'] = 'static/img'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 

# SECURITY: Get key from environment (Production safe).
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

db.init_app(app)

# Constants for Template
IMAGE_EXTENSIONS = ('.png', '.jpg', '.jpeg', '.gif', '.webp')

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    flash("Error: File is too large. Maximum size is 100MB.", "error")
    return redirect(url_for('index'))

@app.route('/')
def index():
    entries = RecoveryEntry.query.order_by(RecoveryEntry.created_at.desc()).all()
    return render_template('dashboard.html', entries=entries, image_extensions=IMAGE_EXTENSIONS)

@app.route('/ingest', methods=['POST'])
def ingest_record():
    """Handles file uploads with specific error handling."""
    file = request.files.get('image')
    narrative = request.form.get('narrative')
    
    if not file or file.filename == '':
        flash("No file selected.", "error")
        return redirect(url_for('index'))

    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)

    if is_authorized_upload(file.filename, size):
        try:
            secure_name = anonymize_filename(file.filename)
            safe_display_name = secure_filename(file.filename)
            
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_name))
            
            entry = RecoveryEntry(
                stored_filename=secure_name, 
                display_name=safe_display_name, 
                narrative_text=narrative
            )
            db.session.add(entry)
            db.session.commit()
            
            flash("Record successfully vaulted.", "success")
        
        # Bot Fix: Catch specific File System errors
        except OSError as e:
            app.logger.error(f"File Error: {e}")
            flash("System error saving the file.", "error")
        
        # Bot Fix: Catch specific Database errors
        except SQLAlchemyError as e:
            app.logger.error(f"Database Error: {e}")
            flash("Database error saving the record.", "error")
            
    else:
        flash("Security Error: Invalid file type or size.", "error")
    
    return redirect(url_for('index'))

@app.route('/delete/<int:entry_id>', methods=['POST'])
def delete_record(entry_id: int):
    entry = RecoveryEntry.query.get_or_404(entry_id)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], entry.stored_filename)
    
    # 1. Delete DB record first (Atomic strategy)
    try:
        db.session.delete(entry)
        db.session.commit()
    except SQLAlchemyError as e:
        app.logger.error(f"Database Error: {e}")
        flash("Error deleting database record.", "error")
        return redirect(url_for('index'))

    # 2. Then delete physical file
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except OSError as e:
            app.logger.error(f"File Deletion Error: {e}")
            flash("Record deleted, but the associated file could not be removed.", "warning")
            return redirect(url_for('index'))
    
    flash("Record deleted permanently.", "success")
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    if not app.config['SECRET_KEY']:
        app.config['SECRET_KEY'] = 'dev-secret-key-for-local-testing'
    
    app.run(debug=True, port=8000)