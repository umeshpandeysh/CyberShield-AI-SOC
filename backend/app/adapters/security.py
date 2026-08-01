import uuid
from datetime import datetime, timedelta
from typing import Optional, dict
from jose import jwt, JWTError
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from app.infra.config import settings

# Password hashing context using Bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain text password against the stored bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Generates a bcrypt hash for the provided password."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Generates an OAuth2 compatible JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "jti": str(uuid.uuid4())  # Unique identifier for revocation checks
    })
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

def decode_access_token(token: str) -> dict:
    """Decodes a JWT access token and verifies its signatures/expiry.
    Raises JWTError if invalid or expired.
    """
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    return payload

# Database encryption tools (for sensitive configuration fields/API tokens)
# We generate a Fernet key derived from settings.SECRET_KEY
import hashlib
import base64

def get_encryption_key() -> bytes:
    """Derives a stable 32-byte base64 key from settings.SECRET_KEY for Fernet."""
    digest = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return base64.urlsafe_b64encode(digest)

def encrypt_value(value: str) -> str:
    """Encrypts a string value using AES-128/256 Fernet block encryption."""
    if not value:
        return value
    f = Fernet(get_encryption_key())
    return f.encrypt(value.encode()).decode()

def decrypt_value(encrypted_value: str) -> str:
    """Decrypts a Fernet encrypted string back to plain text."""
    if not encrypted_value:
        return encrypted_value
    f = Fernet(get_encryption_key())
    return f.decrypt(encrypted_value.encode()).decode()
