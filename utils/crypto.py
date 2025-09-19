
import hashlib
import hmac
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

class CryptoUtils:
    """Cryptographic utility functions"""
    
    @staticmethod
    def generate_secure_random(size: int) -> bytes:
        """Generate cryptographically secure random bytes"""
        return secrets.token_bytes(size)
    
    @staticmethod
    def hash_data(data: bytes, algorithm: str = 'sha256') -> str:
        """Hash data using specified algorithm"""
        if algorithm == 'sha256':
            return hashlib.sha256(data).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(data).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    @staticmethod
    def generate_key_pair():
        """Generate RSA key pair for certificate signing"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        
        return private_key, public_key