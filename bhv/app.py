import os
import sys
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, Optional

# SECURITY & REFACTOR FIX: Import from centralized utilities
from bhv.utils.validators import (
    allowed_file, 
    sanitize_filename, 
    generate_unique_filename, 
    validate_file_size
)

# Database setup
db = SQLAlchemy()

# Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    images = db.relationship('Image', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Image(db.Model):
    __tablename__ = 'images'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    file_size = db.Column(db.Integer)
    mime_type = db.Column(db.String(50))
    width = db.Column(db.Integer)
    height = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

# Forms
class ImageUploadForm(FlaskForm):
    image = FileField('Image', validators=[
        FileRequired(message='Please select an image'),
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')
    ])
    title = StringField('Title', validators=[
        DataRequired(message='Title is required'),
        Length(min=3, max=200, message='Title must be between 3 and 200 characters')
    ])
    description = TextAreaField('Description (Your Story)', validators=[
        Optional(),
        Length(max=5000, message='Description must be less than 5000 characters')
    ])
    submit = SubmitField('Upload Image')

# App factory
def create_app():
    BASE_DIR = Path(__file__).parent.parent
    
    app = Flask(__name__, 
                static_folder=str(BASE_DIR / 'static'),
                static_url_path='/static')
    
    # SECURITY FIX: Load SECRET_KEY from environment variable
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{BASE_DIR / "bhv.db"}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = BASE_DIR / 'static' / 'uploads'
    app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
    app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
    
    db.init_app(app)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    with app.app_context():
        db.create_all()
        # Note: Default user logic for initial setup
        if User.query.count() == 0:
            default_user = User(username='default', email='default@bhv.org')
            default_user.set_password('changeme123')
            db.session.add(default_user)
            db.session.commit()
    
    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/upload', methods=['GET', 'POST'])
    def upload():
        form = ImageUploadForm()
        
        if form.validate_on_submit():
            file = form.image.data
            
            # SECURITY FIX: In-memory size validation BEFORE disk save (DoS protection)
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)
            
            if not validate_file_size(file_size, app.config['MAX_CONTENT_LENGTH']):
                flash('File is empty or exceeds the 5MB limit.', 'error')
                return redirect(request.url)
            
            if not allowed_file(file.filename, app.config['ALLOWED_EXTENSIONS']):
                flash('Invalid file type. Only PNG, JPG, JPEG, and GIF are allowed.', 'error')
                return redirect(request.url)
            
            original_filename = sanitize_filename(file.filename)
            unique_filename = generate_unique_filename(original_filename)
            file_path = Path(app.config['UPLOAD_FOLDER']) / unique_filename
            
            # Save validated file
            file.save(file_path)
            
            # DATA FIX: Use actual file.mimetype instead of hardcoded strings
            image = Image(
                filename=unique_filename,
                original_filename=original_filename,
                title=form.title.data,
                description=form.description.data,
                file_size=file_size,
                mime_type=file.mimetype, 
                width=0,
                height=0,
                user_id=1
            )
            
            db.session.add(image)
            db.session.commit()
            
            flash('Image uploaded successfully!', 'success')
            return redirect(url_for('gallery'))
        
        return render_template('upload.html', form=form)
    
    @app.route('/gallery')
    def gallery():
        images = Image.query.order_by(Image.uploaded_at.desc()).all()
        return render_template('gallery.html', images=images)
    
    # SECURITY FIX: Prevent Path Traversal with send_from_directory
    @app.route('/uploads/<path:filename>')
    def serve_upload(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    
    @app.route('/health')
    def health():
        return jsonify({'status': 'ok', 'service': 'BHV'}), 200
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)