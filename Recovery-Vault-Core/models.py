from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class RecoveryEntry(db.Model):
    """Database index linking recovery images with textual narratives."""
    id = db.Column(db.Integer, primary_key=True)
    stored_filename = db.Column(db.String(100), nullable=False)
    display_name = db.Column(db.String(100))
    # Requirement: Associated textual narratives
    narrative_text = db.Column(db.Text, nullable=True) 
    created_at = db.Column(db.DateTime, default=datetime.utcnow)