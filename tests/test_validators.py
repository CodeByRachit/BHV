import unittest
import sys
import os

# ==========================================
# 1. PATH SETUP & IMPORTS
# ==========================================
# This line helps Python find your bhv folder from the root
sys.path.append(os.getcwd())

# Import your actual functions from the project structure
from bhv.utils.validators import validate_file_size, allowed_file

# ==========================================
# 2. THE ROBUST TEST SUITE
# ==========================================
class TestValidators(unittest.TestCase):

    def setUp(self):
        """
        Runs before every test. Sets up common variables.
        """
        self.MAX_SIZE = 5 * 1024 * 1024  # 5 MB
        self.ALLOWED_EXTS = {'jpg', 'jpeg', 'png', 'gif'}

    # ---------------------------------------------------------------
    # Part A: Tests for validate_file_size
    # ---------------------------------------------------------------
    
    def test_size_valid_average(self):
        """Test a standard valid file size (2MB)."""
        # Requirement: Handle valid files
        is_valid = validate_file_size(2 * 1024 * 1024, self.MAX_SIZE)
        self.assertTrue(is_valid, "Should accept a file within the limit")

    def test_size_boundary_exact_max(self):
        """Boundary Test: Exactly the max size allowed."""
        is_valid = validate_file_size(self.MAX_SIZE, self.MAX_SIZE)
        self.assertTrue(is_valid, "Should accept file that is exactly the max size")

    def test_size_boundary_exceeded_by_one_byte(self):
        """Boundary Test: Max size + 1 byte."""
        # Requirement: Handle 'A file that exceeds MAX_FILE_SIZE'
        is_valid = validate_file_size(self.MAX_SIZE + 1, self.MAX_SIZE)
        self.assertFalse(is_valid, "Should reject file that is 1 byte over limit")

    def test_size_empty_file(self):
        """Edge Case: File size is 0."""
        # Requirement: Handle 'An empty file (size 0)'
        is_valid = validate_file_size(0, self.MAX_SIZE)
        self.assertFalse(is_valid, "Should reject 0-byte files")

    def test_size_negative(self):
        """Sanity Check: Negative size."""
        is_valid = validate_file_size(-100, self.MAX_SIZE)
        self.assertFalse(is_valid, "Should reject negative file sizes")

    # ---------------------------------------------------------------
    # Part B: Tests for allowed_file
    # ---------------------------------------------------------------

    def test_ext_valid_standard(self):
        """Test standard lowercase extensions."""
        self.assertTrue(allowed_file("photo.jpg", self.ALLOWED_EXTS))
        self.assertTrue(allowed_file("image.png", self.ALLOWED_EXTS))

    def test_ext_case_insensitivity(self):
        """Crucial: Users often upload uppercase extensions (JPG, Png)."""
        self.assertTrue(allowed_file("photo.JPG", self.ALLOWED_EXTS), "Should handle Uppercase extensions")
        self.assertTrue(allowed_file("image.PnG", self.ALLOWED_EXTS), "Should handle Mixed-case extensions")

    def test_ext_invalid_type(self):
        """Test forbidden extensions."""
        self.assertFalse(allowed_file("malware.exe", self.ALLOWED_EXTS))
        self.assertFalse(allowed_file("document.pdf", self.ALLOWED_EXTS))

    def test_ext_no_extension(self):
        """Edge Case: Filename with no extension."""
        self.assertFalse(allowed_file("README", self.ALLOWED_EXTS))
        self.assertFalse(allowed_file("justfile", self.ALLOWED_EXTS))

    def test_ext_multiple_dots(self):
        """Edge Case: Filenames with multiple dots (e.g., my.photo.jpg)."""
        # Should look at the *last* extension
        self.assertTrue(allowed_file("my.vacation.photo.jpg", self.ALLOWED_EXTS))
        # If .gz is not allowed, this should fail even if .tar is valid
        self.assertFalse(allowed_file("archive.tar.gz", self.ALLOWED_EXTS))

    def test_ext_hidden_file(self):
        """Edge Case: Unix hidden files (starts with dot)."""
        self.assertFalse(allowed_file(".gitignore", self.ALLOWED_EXTS))

if __name__ == '__main__':
    # verbosity=2 ensures you see the full "ok" report for every test
    unittest.main(verbosity=2)