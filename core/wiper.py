
import os
import sys
import random
import hashlib
import time
import logging
from typing import Optional, Callable
from datetime import datetime

class DataWiper:
    """Core data wiping engine with NIST SP 800-88 compliance"""
    
    # NIST SP 800-88 Rev. 1 compliant patterns
    NIST_PATTERNS = [
        b'\x00',  # All zeros
        b'\xFF',  # All ones  
        b'\xAA',  # 10101010
        b'\x55',  # 01010101
    ]
    
    # DoD 5220.22-M patterns
    DOD_PATTERNS = [
        b'\x00',  # Pass 1: All zeros
        b'\xFF',  # Pass 2: All ones
        None,     # Pass 3: Random data
    ]
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.block_size = 64 * 1024  # 64KB blocks for performance
        
    def wipe_device(self, device_path: str, method: str = 'nist', 
                   progress_callback: Optional[Callable] = None) -> str:
        """
        Wipe device using specified method
        Returns: Certificate ID for the wipe operation
        """
        start_time = datetime.now()
        
        # Validate device
        if not os.path.exists(device_path):
            raise ValueError(f"Device {device_path} does not exist")
        
        # Get device size
        device_size = self._get_device_size(device_path)
        if device_size == 0:
            raise ValueError("Could not determine device size")
        
        self.logger.info(f"Starting {method.upper()} wipe of {device_path} ({device_size} bytes)")
        
        patterns = self.NIST_PATTERNS if method == 'nist' else self.DOD_PATTERNS
        total_passes = len(patterns)
        
        verification_hashes = []
        
        try:
            with open(device_path, 'r+b', buffering=0) as device:
                for pass_num, pattern in enumerate(patterns, 1):
                    self.logger.info(f"Starting pass {pass_num}/{total_passes}")
                    
                    if pattern is None:
                        # Random pattern
                        pass_hash = self._write_random_pattern(device, device_size, progress_callback, pass_num, total_passes)
                    else:
                        # Fixed pattern
                        pass_hash = self._write_fixed_pattern(device, device_size, pattern, progress_callback, pass_num, total_passes)
                    
                    verification_hashes.append({
                        'pass': pass_num,
                        'pattern': pattern.hex() if pattern else 'random',
                        'hash': pass_hash
                    })
                    
                    # Force sync to disk
                    device.flush()
                    os.fsync(device.fileno())
        
        except Exception as e:
            self.logger.error(f"Wipe operation failed: {e}")
            raise
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Generate certificate
        from core.certificate import CertificateGenerator
        cert_gen = CertificateGenerator()
        
        cert_id = cert_gen.generate_certificate({
            'device_path': device_path,
            'device_size': device_size,
            'method': method.upper(),
            'start_time': start_time,
            'end_time': end_time,
            'duration': duration,
            'verification_hashes': verification_hashes,
            'passes': total_passes
        })
        
        self.logger.info(f"Wipe completed successfully. Certificate ID: {cert_id}")
        return cert_id
    
    def _get_device_size(self, device_path: str) -> int:
        """Get device size in bytes"""
        try:
            with open(device_path, 'rb') as device:
                # Seek to end and get position
                device.seek(0, os.SEEK_END)
                return device.tell()
        except Exception as e:
            self.logger.error(f"Failed to get device size: {e}")
            return 0
    
    def _write_fixed_pattern(self, device, device_size: int, pattern: bytes,
                           progress_callback: Optional[Callable], pass_num: int, total_passes: int) -> str:
        """Write fixed pattern to device"""
        device.seek(0)
        hasher = hashlib.sha256()
        bytes_written = 0
        
        # Create pattern block
        pattern_block = pattern * self.block_size
        
        while bytes_written < device_size:
            remaining = device_size - bytes_written
            write_size = min(self.block_size, remaining)
            
            data = pattern_block[:write_size]
            device.write(data)
            hasher.update(data)
            
            bytes_written += write_size
            
            # Update progress
            if progress_callback:
                overall_progress = ((pass_num - 1) * 100 + (bytes_written * 100 // device_size)) // total_passes
                progress_callback(overall_progress, f"Pass {pass_num}/{total_passes}: Writing pattern")
        
        return hasher.hexdigest()
    
    def _write_random_pattern(self, device, device_size: int, 
                            progress_callback: Optional[Callable], pass_num: int, total_passes: int) -> str:
        """Write random pattern to device"""
        device.seek(0)
        hasher = hashlib.sha256()
        bytes_written = 0
        
        while bytes_written < device_size:
            remaining = device_size - bytes_written
            write_size = min(self.block_size, remaining)
            
            # Generate random data
            random_data = os.urandom(write_size)
            device.write(random_data)
            hasher.update(random_data)
            
            bytes_written += write_size
            
            # Update progress
            if progress_callback:
                overall_progress = ((pass_num - 1) * 100 + (bytes_written * 100 // device_size)) // total_passes
                progress_callback(overall_progress, f"Pass {pass_num}/{total_passes}: Writing random data")
        
        return hasher.hexdigest()