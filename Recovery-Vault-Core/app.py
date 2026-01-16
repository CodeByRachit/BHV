import os
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.exceptions import RequestEntityTooLarge
from models import db, RecoveryEntry
from validators import is_authorized_upload, anonymize_filename

app = Flask(__name__)

# --- Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault_core.db'
app.config['UPLOAD_FOLDER'] = 'static/img'
# Security: Use environment variable or fallback for dev
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'production-grade-secret')
# Security: Block requests larger than 100MB immediately
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 

# Initialize extensions
db.init_app(app)

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    """Global error handler for files exceeding the size limit."""
    flash("Error: File is too large. Maximum size is 100MB.", "error")
    return redirect(url_for('index'))

@app.route('/')
def index():
    """Renders the dashboard with all recovery records."""
    entries = RecoveryEntry.query.order_by(RecoveryEntry.created_at.desc()).all()
    return render_template('dashboard.html', entries=entries)

@app.route('/ingest', methods=['POST'])
def ingest_record():
    """
    Handles file uploads and database entry creation.
    Performs security checks on extension and file size.
    """
    file = request.files.get('image')
    narrative = request.form.get('narrative')
    
    if not file or file.filename == '':
        flash("No file selected.", "error")
        return redirect(url_for('index'))

    # Check file size manually for validator logic (double-check)
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)

    if is_authorized_upload(file.filename, size):
        try:
            secure_name = anonymize_filename(file.filename)
            
            # Ensure upload directory exists
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            # Save the file
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_name))
            
            # Save to Database
            entry = RecoveryEntry(
                stored_filename=secure_name, 
                display_name=file.filename, 
                narrative_text=narrative
            )
            db.session.add(entry)
            db.session.commit()
            
            flash("Record successfully vaulted.", "success")
        except Exception as e:
            # Catch file permission or OS errors
            flash(f"System Error: {str(e)}", "error")
    else:
        flash("Security Error: Invalid file type or size.", "error")
    
    return redirect(url_for('index'))

@app.route('/delete/<int:entry_id>', methods=['POST'])
def delete_record(entry_id: int):
    """
    Deletes a record from the database and removes the associated file.
    """
    entry = RecoveryEntry.query.get_or_404(entry_id)
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], entry.stored_filename)
    
    # Attempt to delete actual file
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except OSError as e:
            flash(f"Error deleting physical file: {e}", "error")
    
    # Delete DB record
    db.session.delete(entry)
    db.session.commit()
    
    flash("Record deleted permanently.", "success")
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create upload folder on startup to prevent errors
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # debug=True is fine for local dev, but bots might flag it for production code.
    # We keep it for now as this is an MVP.
    app.run(debug=True, port=8000)