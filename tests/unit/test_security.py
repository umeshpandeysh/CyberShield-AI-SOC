import pytest
from datetime import timedelta
from jose import jwt
from backend.app.adapters.security import (
    get_password_hash,
    verify_password,
    create_access_token,
    decode_access_token,
    encrypt_value,
    decrypt_value
)

def test_password_hashing():
    password = "SuperSecretPassword123!"
    hashed = get_password_hash(password)
    
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("wrong_password", hashed) is False

def test_jwt_token_generation_and_decoding():
    user_data = {"sub": "user_id_123", "role": "Analyst_L1"}
    token = create_access_token(user_data, expires_delta=timedelta(minutes=10))
    
    assert isinstance(token, str)
    
    decoded = decode_access_token(token)
    assert decoded["sub"] == "user_id_123"
    assert decoded["role"] == "Analyst_L1"
    assert "exp" in decoded
    assert "jti" in decoded

def test_encryption_decryption():
    secret_message = "This is a sensitive threat indicator API key"
    encrypted = encrypt_value(secret_message)
    
    assert encrypted != secret_message
    
    decrypted = decrypt_value(encrypted)
    assert decrypted == secret_message
