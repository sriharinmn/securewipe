
# =============================================================================
# utils/config.py - Configuration
# =============================================================================

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
    
    # HPA and DCO configuration
    ENABLE_HPA_DETECTION = True
    ENABLE_DCO_DETECTION = True
    AUTO_REMOVE_HPA = True
    AUTO_REMOVE_DCO = True
    HPA_DCO_TIMEOUT = 30  # seconds
    
    # Security
    HASH_ALGORITHM = 'sha256'
    
    # CRITICAL SAFETY SETTINGS
    ENABLE_SAFETY_CHECKS = True
    REQUIRE_CONFIRMATION = True
    
    # Protected device patterns (NEVER allow wiping these)
    PROTECTED_DEVICE_PATTERNS = [
        '/dev/disk0',      # macOS main disk
        '/dev/sda',        # Linux main disk (common)
        '/dev/nvme0n1',    # NVMe main disk (common)
        r'\\.\PHYSICALDRIVE0',  # Windows main disk
        '/System/',        # macOS system paths
        '/Users/',         # macOS user paths
        '/Applications/',  # macOS applications
        'C:\\',           # Windows C drive
        '/home/',         # Linux home directories
        '/root/',         # Linux root directory
        '/boot/',         # Linux boot directory
        '/usr/',          # Linux system directory
        '/var/',          # Linux variable directory
        '/etc/',          # Linux configuration directory
    ]
    
    # Only allow these safe patterns for testing
    ALLOWED_TEST_PATTERNS = [
        '/tmp/test_drive',      # Test files in temp
        '/var/tmp/test_drive',  # Alternative temp location
        r'C:\temp\test_drive',  # Windows temp test files
        r'C:\tmp\test_drive',   # Windows alternative temp
    ]
    
    # Mounted filesystem detection
    FORBIDDEN_MOUNT_POINTS = [
        '/',              # Root filesystem
        '/System',        # macOS System
        '/Applications',  # macOS Applications
        '/Users',         # macOS Users
        'C:\\',           # Windows C drive
        '/home',          # Linux home
        '/usr',           # Linux usr
        '/var',           # Linux var
        '/boot',          # Linux boot
    ]
    
    @classmethod
    def ensure_directories(cls):
        """Ensure required directories exist"""
        cls.CERT_DIR.mkdir(exist_ok=True)
        cls.LOG_DIR.mkdir(exist_ok=True)
