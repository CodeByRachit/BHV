import os
import uuid

# UPDATED: Increased limit to 100MB
MAX_FILE_SIZE = 100 * 1024 * 1024 

# Extended list of allowed formats
ALLOWED_EXTENSIONS = {
    'png', 'jpg', 'jpeg', 'gif', 'webp',  # Images
    'pdf', 'doc', 'docx', 'txt',          # Documents
    'zip', 'rar', 'csv', 'xlsx'           # Data/Archives
}

def is_authorized_upload(filename, file_size):
    """
    Validates file extension and size.
    Returns True if valid, False otherwise.
    """
    # 1. Check if filename has an extension
    if '.' not in filename:
        return False
    
    # 2. Check extension (case-insensitive)
    ext = filename.rsplit('.', 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False

    # 3. Check File Size (Must be >0 and <= 100MB)
    if file_size <= 0 or file_size > MAX_FILE_SIZE:
        return False
    
    return True

def anonymize_filename(filename):
    """Generates a secure, random filename."""
    ext = os.path.splitext(filename)[1].lower()
    return f"rec_{uuid.uuid4().hex}{ext}"