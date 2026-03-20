from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from bson import ObjectId
from flask_login import UserMixin
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorGridFSBucket # NEW: Added GridFS import
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
    
    # NEW: Role-Based Access Control (RBAC)
    role = db.Column(db.String(20), nullable=False, default="user")
    
    entries = db.relationship('RecoveryEntry', backref='owner', lazy=True)

    # Stores the filename of the user's avatar.
    profile_image = db.Column(db.String(100), nullable=False, default='default_profile.png')

    # NEW REQUIRED CHANGES FOR 2FA
    totp_secret = db.Column(db.String(32), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)

    # --- NEW: Secure Email Update Pipeline (ATO Protection) ---
    pending_email = db.Column(db.String(150), unique=True, nullable=True)
    update_otp = db.Column(db.String(6), nullable=True)
    update_otp_expiry = db.Column(db.DateTime, nullable=True)

# EXISTING: Your Recovery Entry Table
class RecoveryEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stored_filename = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    narrative_text = db.Column(db.Text, nullable=True)
    file_hash = db.Column(db.String(64), nullable=False)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- NEW: RADICAL MINIMALISM STREAMING LOGIC ---
async def stream_to_nosql_vault(user_id: int, filename: str, iv: bytes, metadata: dict, async_chunk_generator):
    """
    Radical Minimalism: Streams encrypted chunks straight into MongoDB GridFS.
    Bypasses the 16MB document limit and keeps RAM usage near zero.
    """
    client = AsyncIOMotorClient(MONGO_URI)
    db = client.bhv_database
    
    # GridFS automatically breaks large files into chunks in the database
    fs = AsyncIOMotorGridFSBucket(db, bucket_name='vaulted_narratives')
    
    # We MUST save the IV in the metadata to decrypt this specific file later
    full_metadata = {"user_id": user_id, "iv": iv.hex(), **(metadata or {})}
    
    # Open an upload stream to MongoDB
    grid_in = fs.open_upload_stream(filename, metadata=full_metadata)
    
    # The Nozzle: Pull from the generator, push directly to the DB
    async for encrypted_chunk in async_chunk_generator:
        await grid_in.write(encrypted_chunk)
        
    await grid_in.close()
    client.close()
    
    return str(grid_in._id)

# --- EXISTING: REQUIRED ASYNCHRONOUS PERSISTENCE LOGIC ---
# (Kept intact so your older Flask /ingest routes do not break)
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



# --- RADICAL MINIMALISM: DOWNLOAD STREAM ---
async def get_nosql_download_stream(file_id: str, user_id: int):
    """
    Opens a GridFS download stream and retrieves the decryption IV.
    """
    client = AsyncIOMotorClient(MONGO_URI)
    db = client.bhv_database
    fs = AsyncIOMotorGridFSBucket(db, bucket_name='vaulted_narratives')
    
    try:
        # 1. Open the stream by its MongoDB ObjectId
        grid_out = await fs.open_download_stream(ObjectId(file_id))
    except Exception:
        client.close()
        raise ValueError("File not found in Vault.")
        
    # 2. Zero-Trust Verification: Ensure this user owns the file
    metadata = grid_out.metadata or {}
    if str(metadata.get("user_id")) != str(user_id):  # FIX: Convert both to strings to ensure they match!
        client.close()
        raise PermissionError("Unauthorized access to this vault record.")
        
    # 3. Extract the IV required for decryption
    iv_hex = metadata.get("iv")
    if not iv_hex:
        client.close()
        raise ValueError("Decryption IV missing from file metadata.")
        
    iv = bytes.fromhex(iv_hex)
    
    # We return the client so the FastAPI generator can close it when the download finishes
    return grid_out, iv, client, grid_out.filename