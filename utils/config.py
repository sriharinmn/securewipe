
import os
from pathlib import Path

class Config:
    """Application configuration"""
    
    # Application info
    APP_NAME = "Secure Data Wiper"
    APP_VERSION = "1.0.0"
    
    # Directories
    BASE_DIR = Path(__file__).parent.parent
    CERT_DIR = BASE_DIR / "certificates"
    LOG_DIR = BASE_DIR / "logs"
    
    # Wiping configuration
    DEFAULT_BLOCK_SIZE = 64 * 1024  # 64KB
    MAX_DEVICE_SIZE = 10 * 1024 * 1024 * 1024 * 1024  # 10TB
    
    # Security
    HASH_ALGORITHM = 'sha256'
    
    @classmethod
    def ensure_directories(cls):
        """Ensure required directories exist"""
        cls.CERT_DIR.mkdir(exist_ok=True)
        cls.LOG_DIR.mkdir(exist_ok=True)