import os
from PIL import Image, UnidentifiedImageError  # Added specific error import

def get_image_metadata(file_path):
    """
    Extracts metadata from an image. 
    Refactored to catch specific PIL and IO exceptions as per review feedback.
    """
    try:
        with Image.open(file_path) as img:
            return {
                'width': img.width,
                'height': img.height,
                'format': img.format,
                'mode': img.mode
            }
    # SECURITY & CODE QUALITY FIX: Catching specific exceptions
    except (IOError, UnidentifiedImageError) as e:
        print(f"Error processing image metadata for {file_path}: {e}")
        return None

def get_file_size(file_path):
    """Returns file size in bytes. Returns 0 if file is inaccessible."""
    try:
        return os.path.getsize(file_path)
    # Refined to catch OSError (file missing/permission) specifically
    except OSError:
        return 0