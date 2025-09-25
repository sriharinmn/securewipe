# =============================================================================
# utils/safety.py - Critical Safety Checks
# =============================================================================

import os
import sys
import subprocess
import logging
import re
from pathlib import Path
from typing import List, Dict, Tuple
from .config import Config

class SafetyChecker:
    """Critical safety checks to prevent accidental data loss"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
    
    def is_device_safe_to_wipe(self, device_path: str) -> Tuple[bool, str]:
        """
        Comprehensive safety check for device wiping
        
        Args:
            device_path: Path to the device to check
            
        Returns:
            Tuple of (is_safe: bool, reason: str)
        """
        
        # Check if safety is enabled
        if not Config.ENABLE_SAFETY_CHECKS:
            self.logger.warning("SAFETY CHECKS DISABLED - DANGEROUS!")
            return True, "Safety checks disabled"
        
        # Check against protected patterns
        is_protected, reason = self._check_protected_patterns(device_path)
        if is_protected:
            return False, reason
        
        # Check if device is mounted
        is_mounted, mount_reason = self._check_mount_status(device_path)
        if is_mounted:
            return False, mount_reason
        
        # Check if device contains system files
        has_system, system_reason = self._check_system_files(device_path)
        if has_system:
            return False, system_reason
        
        # Check device size (prevent accidental large disk wipes)
        is_large, size_reason = self._check_device_size(device_path)
        if is_large:
            return False, size_reason
        
        # Only allow test files or explicitly safe patterns
        is_test_file = self._is_test_file(device_path)
        if not is_test_file:
            return False, "Only test files are allowed for wiping. Use /tmp/test_drive*.img files."
        
        return True, "Device appears safe for wiping"
    
    def _check_protected_patterns(self, device_path: str) -> Tuple[bool, str]:
        """Check if device matches protected patterns"""
        device_path_lower = device_path.lower()
        
        for pattern in Config.PROTECTED_DEVICE_PATTERNS:
            if pattern.lower() in device_path_lower:
                return True, f"Device matches protected pattern: {pattern}"
        
        return False, "No protected patterns matched"
    
    def _check_mount_status(self, device_path: str) -> Tuple[bool, str]:
        """Check if device or its partitions are mounted"""
        try:
            if sys.platform.startswith('darwin'):  # macOS
                result = subprocess.run(['mount'], capture_output=True, text=True)
                if device_path in result.stdout:
                    return True, f"Device {device_path} is currently mounted"
                    
                # Check for partition mounts
                base_device = device_path.replace('/dev/', '')
                if base_device in result.stdout:
                    return True, f"Device {device_path} has mounted partitions"
                    
            elif sys.platform.startswith('linux'):
                # Check /proc/mounts
                with open('/proc/mounts', 'r') as f:
                    mounts = f.read()
                    if device_path in mounts:
                        return True, f"Device {device_path} is currently mounted"
                        
            elif sys.platform.startswith('win'):
                # Windows check - be extra cautious
                if 'PHYSICALDRIVE0' in device_path:
                    return True, "PHYSICALDRIVE0 is the system drive - NEVER wipe this!"
                    
        except Exception as e:
            self.logger.error(f"Error checking mount status: {e}")
            return True, f"Could not verify mount status (assuming mounted for safety): {e}"
        
        return False, "Device not mounted"
    
    def _check_system_files(self, device_path: str) -> Tuple[bool, str]:
        """Check if device contains critical system files"""
        
        # Don't try to read from actual block devices - too dangerous
        if not device_path.startswith('/tmp/') and not device_path.startswith('/var/tmp/'):
            if sys.platform.startswith(('linux', 'darwin')):
                if device_path.startswith('/dev/'):
                    return True, "Block devices are not safe - use test files only"
            elif sys.platform.startswith('win'):
                if 'PHYSICALDRIVE' in device_path:
                    return True, "Physical drives are not safe - use test files only"
        
        return False, "No system files detected"
    
    def _check_device_size(self, device_path: str) -> Tuple[bool, str]:
        """Check if device is suspiciously large (likely a real drive)"""
        try:
            if os.path.exists(device_path):
                size = os.path.getsize(device_path)
                
                # If it's larger than 1GB, be suspicious
                if size > 1024 * 1024 * 1024:  # 1GB
                    return True, f"Device is very large ({size} bytes) - likely a real drive"
                    
        except Exception as e:
            self.logger.error(f"Error checking device size: {e}")
            return True, f"Could not verify device size (assuming large for safety): {e}"
        
        return False, "Device size acceptable"
    
    def _is_test_file(self, device_path: str) -> bool:
        """Check if device is an allowed test file"""
        device_path_lower = device_path.lower()
        
        for pattern in Config.ALLOWED_TEST_PATTERNS:
            if pattern.lower() in device_path_lower:
                return True
        
        # Additional check for test file naming convention
        if 'test_drive' in device_path_lower and ('.img' in device_path_lower or '.dat' in device_path_lower):
            return True
            
        return False
    
    def create_test_file(self, size_mb: int = 10, filename: str = None) -> str:
        """
        Create a safe test file for wiping demonstrations
        
        Args:
            size_mb: Size of test file in MB (default: 10MB)
            filename: Optional custom filename
            
        Returns:
            Path to created test file
        """
        if filename is None:
            import time
            timestamp = int(time.time())
            filename = f"test_drive_{timestamp}.img"
        
        test_file_path = f"/tmp/{filename}"
        
        try:
            # Create test file with random data
            with open(test_file_path, 'wb') as f:
                chunk_size = 1024 * 1024  # 1MB chunks
                for _ in range(size_mb):
                    f.write(os.urandom(chunk_size))
            
            self.logger.info(f"Created test file: {test_file_path} ({size_mb}MB)")
            return test_file_path
            
        except Exception as e:
            self.logger.error(f"Failed to create test file: {e}")
            raise
    
    def get_safety_warnings(self, device_path: str) -> List[str]:
        """Get all safety warnings for a device"""
        warnings = []
        
        if not Config.ENABLE_SAFETY_CHECKS:
            warnings.append("⚠️  CRITICAL: Safety checks are disabled!")
        
        is_safe, reason = self.is_device_safe_to_wipe(device_path)
        if not is_safe:
            warnings.append(f"🚫 UNSAFE: {reason}")
        
        if not self._is_test_file(device_path):
            warnings.append("⚠️  This is not a recognized test file")
        
        # Check if it looks like a real device
        if '/dev/' in device_path or 'PHYSICALDRIVE' in device_path:
            warnings.append("🚨 DANGER: This appears to be a real storage device!")
        
        return warnings