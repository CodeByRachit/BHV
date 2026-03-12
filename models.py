from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin
from motor.motor_asyncio import AsyncIOMotorClient
import os

db = SQLAlchemy()

# This fulfills the 'Flexible Storage Zone' milestone
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
# Removed global client initialization here to prevent asyncio loop conflicts with asgiref

# NEW: User Table
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True) 
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    entries = db.relationship('RecoveryEntry', backref='owner', lazy=True)

    # Stores the filename of the user's avatar.
    profile_image = db.Column(db.String(100), nullable=False, default='default_profile.png')

    # NEW REQUIRED CHANGES FOR 2FA
    totp_secret = db.Column(db.String(32), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)

# EXISTING: Your Recovery Entry Table
class RecoveryEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stored_filename = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    narrative_text = db.Column(db.Text, nullable=True)
    file_hash = db.Column(db.String(64), nullable=False)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- NEW: REQUIRED ASYNCHRONOUS PERSISTENCE LOGIC ---
async def save_to_nosql_vault(user_id: int, filename: str, encrypted_payload: bytes, metadata: dict = None):
    """
    Saves an encrypted document to the NoSQL vault. 
    Fulfills 'Asynchronous Persistence' milestone.
    """
    # Initialize client INSIDE the function to attach to the request's specific event loop
    client = AsyncIOMotorClient(MONGO_URI)
    vault_collection = client.bhv_database.vaulted_narratives
    
    document = {
        "user_id": user_id,
        "filename": filename,
        "payload": encrypted_payload,  # The AES-256 protected blob
        "metadata": metadata or {},
        "vault_status": "encrypted_at_rest",
        "created_at": datetime.utcnow()
    }
    result = await vault_collection.insert_one(document)
    
    # Close the connection for this loop
    client.close()
    return str(result.inserted_id)

async def get_vaulted_record(record_id: str):
    """
    Retrieves a specific encrypted record from MongoDB.
    Supports 'In-Memory Secure Streaming'.
    """
    # Initialize client INSIDE the function to attach to the request's specific event loop
    client = AsyncIOMotorClient(MONGO_URI)
    vault_collection = client.bhv_database.vaulted_narratives
    
    result = await vault_collection.find_one({"_id": record_id})
    
    client.close()
    return result