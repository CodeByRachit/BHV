from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class RecoveryEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stored_filename = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    narrative_text = db.Column(db.Text, nullable=True)
    # FIXED: Changed nullable to False as requested
    file_hash = db.Column(db.String(64), nullable=False)