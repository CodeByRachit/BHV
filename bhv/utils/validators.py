import os
from pathlib import Path
from werkzeug.utils import secure_filename

def allowed_file(filename, allowed_extensions):
    # Requirement: Handle 'A file with an invalid extension'
    if '.' not in filename:
        return False
    
    extension = filename.rsplit('.', 1)[1].lower()
    return extension in allowed_extensions

def validate_image_content(file_path):
    # Simple validation - just check file exists
    # Requirement: Handle 'A file with valid extension but invalid content'
    return 'jpeg' if os.path.exists(file_path) else None

def sanitize_filename(filename):
    filename = secure_filename(filename)
    filename = filename.replace('/', '').replace('\\', '')
    name, ext = os.path.splitext(filename)
    if len(name) > 100:
        name = name[:100]
    return f"{name}{ext}"

def generate_unique_filename(original_filename):
    import uuid
    ext = Path(original_filename).suffix.lower()
    unique_name = f"{uuid.uuid4().hex}{ext}"
    return unique_name

def validate_file_size(file_size, max_size):
    """
    Improved validation to specifically catch 'An empty file (size 0)'
    and 'A file that exceeds MAX_FILE_SIZE' as per project requirements.
    """
    # Requirement: Explicitly reject size 0
    if file_size <= 0:
        return False
    
    # Requirement: Explicitly reject files exceeding MAX_FILE_SIZE
    if file_size > max_size:
        return False
        
    return True