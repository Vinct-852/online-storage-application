import hmac
import hashlib
import secrets
import base64

def generate_salt(length=32):
    """Generate a random salt using PRNG"""
    return secrets.token_bytes(length)

def generate_password_hash(password, salt=None):
    """Generate a secure password hash using HMAC-SHA256"""
    if not salt:
        salt = generate_salt()
    
    # Convert password to bytes if it's not already
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Create HMAC using SHA256 and the salt
    hmac_obj = hmac.new(salt, password, hashlib.sha256)
    password_hash = hmac_obj.digest()
    
    # Combine salt and hash, then base64 encode
    combined = salt + password_hash
    return base64.b64encode(combined).decode('utf-8')

def check_password_hash(stored_hash, password):
    """Verify a password against its hash"""
    try:
        # Decode the stored hash
        decoded = base64.b64decode(stored_hash.encode('utf-8'))
        
        # Split into salt and hash (salt is first 32 bytes)
        salt = decoded[:32]
        stored_password_hash = decoded[32:]
        
        # Generate hash of provided password
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Create HMAC using same salt and check
        hmac_obj = hmac.new(salt, password, hashlib.sha256)
        password_hash = hmac_obj.digest()
        
        # Compare in constant time to prevent timing attacks
        return hmac.compare_digest(stored_password_hash, password_hash)
    except Exception:
        return False
