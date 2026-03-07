from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()

# NEW: User Table
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True) # Nullable because Google users don't have passwords
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # NEW: Link User to their uploaded entries
    entries = db.relationship('RecoveryEntry', backref='owner', lazy=True)

# EXISTING: Your Recovery Entry Table
class RecoveryEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stored_filename = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    narrative_text = db.Column(db.Text, nullable=True)
    file_hash = db.Column(db.String(64), nullable=False)
    
    # NEW: Store which user uploaded this file
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)