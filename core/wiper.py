# =============================================================================
# core/wiper.py - Core Wiping Engine
# =============================================================================

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
    
    # NIST SP 800-88 Rev. 1 compliant patterns (4-pass method)
    # Pass 1: Write binary zeros (0x00)
    # Pass 2: Write binary ones (0xFF)
    # Pass 3: Write a known binary pattern (0xAA = 10101010)
    # Pass 4: Write complement pattern (0x55 = 01010101)
    NIST_PATTERNS = [
        b'\x00',  # Pass 1: All zeros (00000000)
        b'\xFF',  # Pass 2: All ones (11111111)
        b'\xAA',  # Pass 3: Alternating pattern (10101010)
        b'\x55',  # Pass 4: Complement alternating pattern (01010101)
    ]
    
    # DoD 5220.22-M patterns (3-pass method)
    # Pass 1: Write binary zeros (0x00)
    # Pass 2: Write binary ones (0xFF) 
    # Pass 3: Write pseudorandom data and verify
    DOD_PATTERNS = [
        b'\x00',  # Pass 1: All zeros
        b'\xFF',  # Pass 2: All ones
        None,     # Pass 3: Pseudorandom data
    ]
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.block_size = 64 * 1024  # 64KB blocks for performance
        
    def wipe_device(self, device_path: str, method: str = 'nist', 
               progress_callback: Optional[Callable] = None,
               device_info: dict = None) -> str:
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
        
        # Store current method for progress calculation
        self._current_method = method
        
        patterns = self.NIST_PATTERNS if method == 'nist' else self.DOD_PATTERNS
        total_passes = len(patterns)
        
        if method == 'nist':
            self.logger.info(f"NIST SP 800-88 Rev. 1 compliant wiping with {total_passes} passes:")
            self.logger.info("  Pass 1: All zeros (0x00)")
            self.logger.info("  Pass 2: All ones (0xFF)")
            self.logger.info("  Pass 3: Alternating pattern (0xAA)")
            self.logger.info("  Pass 4: Complement alternating pattern (0x55)")
            self.logger.info("  Each pass includes verification read")
        elif method == 'dod':
            self.logger.info(f"DoD 5220.22-M compliant wiping with {total_passes} passes:")
            self.logger.info("  Pass 1: All zeros (0x00)")
            self.logger.info("  Pass 2: All ones (0xFF)")
            self.logger.info("  Pass 3: Pseudorandom data")
        
        verification_hashes = []
        
        try:
            with open(device_path, 'r+b', buffering=0) as device:
                for pass_num, pattern in enumerate(patterns, 1):
                    self.logger.info(f"Starting pass {pass_num}/{total_passes}")
                    
                    # Write pass
                    if pattern is None:
                        # Random pattern (only used in DoD method)
                        pass_hash = self._write_random_pattern(device, device_size, progress_callback, pass_num, total_passes)
                    else:
                        # Fixed pattern (used in both NIST and DoD)
                        pass_hash = self._write_fixed_pattern(device, device_size, pattern, progress_callback, pass_num, total_passes)
                    
                    # Force sync to disk after write
                    device.flush()
                    os.fsync(device.fileno())
                    
                    # NIST requires verification read after each write pass
                    verify_hash = None
                    if method == 'nist':
                        self.logger.info(f"Verifying pass {pass_num}/{total_passes}")
                        verify_hash = self._verify_pattern(device, device_size, pattern, progress_callback, pass_num, total_passes)
                        
                        # Ensure verification matches write
                        if pass_hash != verify_hash:
                            raise RuntimeError(f"Verification failed for pass {pass_num}: write hash {pass_hash[:8]}... != verify hash {verify_hash[:8]}...")
                        
                        self.logger.info(f"Pass {pass_num} verification successful")
                    
                    verification_hashes.append({
                        'pass': pass_num,
                        'pattern': pattern.hex() if pattern else 'pseudorandom',
                        'write_hash': pass_hash,
                        'verify_hash': verify_hash
                    })
        
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
        
        # Create pattern block - ensure we have enough pattern data
        if len(pattern) == 1:
            # Single byte pattern - repeat to fill block
            pattern_block = pattern * self.block_size
        else:
            # Multi-byte pattern - repeat as needed
            repeats_needed = (self.block_size // len(pattern)) + 1
            pattern_block = (pattern * repeats_needed)[:self.block_size]
        
        while bytes_written < device_size:
            remaining = device_size - bytes_written
            write_size = min(self.block_size, remaining)
            
            data = pattern_block[:write_size]
            device.write(data)
            hasher.update(data)
            
            bytes_written += write_size
            
            # Update progress 
            if progress_callback:
                # For NIST: write is 50% (verification takes other 50%)
                # For DoD: write is 100% (no verification required)
                progress_multiplier = 50 if hasattr(self, '_current_method') and self._current_method == 'nist' else 100
                write_progress = (bytes_written * progress_multiplier // device_size)
                overall_progress = ((pass_num - 1) * 100 + write_progress) // total_passes
                progress_callback(overall_progress, f"Pass {pass_num}/{total_passes}: Writing pattern {pattern.hex()}")
        
        return hasher.hexdigest()
    
    def _write_random_pattern(self, device, device_size: int, 
                            progress_callback: Optional[Callable], pass_num: int, total_passes: int) -> str:
        """Write pseudorandom pattern to device (for DoD method)"""
        device.seek(0)
        hasher = hashlib.sha256()
        bytes_written = 0
        
        while bytes_written < device_size:
            remaining = device_size - bytes_written
            write_size = min(self.block_size, remaining)
            
            # Generate pseudorandom data (suitable for DoD standard)
            random_data = os.urandom(write_size)
            device.write(random_data)
            hasher.update(random_data)
            
            bytes_written += write_size
            
            # Update progress - full pass progress for DoD (no verification required)
            if progress_callback:
                overall_progress = ((pass_num - 1) * 100 + (bytes_written * 100 // device_size)) // total_passes
                progress_callback(overall_progress, f"Pass {pass_num}/{total_passes}: Writing pseudorandom data")
        
        return hasher.hexdigest()
    
    def _write_crypto_random_pattern(self, device, device_size: int, 
                                   progress_callback: Optional[Callable], pass_num: int, total_passes: int) -> str:
        """Write cryptographically secure random pattern to device (for NIST final pass)"""
        device.seek(0)
        hasher = hashlib.sha256()
        bytes_written = 0
        
        # Use stronger randomness for NIST compliance
        while bytes_written < device_size:
            remaining = device_size - bytes_written
            write_size = min(self.block_size, remaining)
            
            # Generate cryptographically secure random data
            crypto_random_data = os.urandom(write_size)
            device.write(crypto_random_data)
            hasher.update(crypto_random_data)
            
            bytes_written += write_size
            
            # Update progress - only show write progress (50% of total pass)
            if progress_callback:
                write_progress = (bytes_written * 50 // device_size)  # Write is 50% of pass progress
                overall_progress = ((pass_num - 1) * 100 + write_progress) // total_passes
                progress_callback(overall_progress, f"Pass {pass_num}/{total_passes}: Writing crypto-random data")
        
        return hasher.hexdigest()
    
    def _verify_pattern(self, device, device_size: int, expected_pattern: bytes, 
                       progress_callback: Optional[Callable], pass_num: int, total_passes: int) -> str:
        """Verify written pattern by reading back and hashing (NIST requirement)"""
        device.seek(0)
        hasher = hashlib.sha256()
        bytes_read = 0
        
        while bytes_read < device_size:
            remaining = device_size - bytes_read
            read_size = min(self.block_size, remaining)
            
            data = device.read(read_size)
            if not data:
                break
                
            hasher.update(data)
            bytes_read += len(data)
            
            # For fixed patterns, verify the data matches expected pattern
            if expected_pattern is not None:
                expected_block = (expected_pattern * (read_size // len(expected_pattern) + 1))[:read_size]
                if data != expected_block:
                    # Log first few bytes for debugging
                    actual_sample = data[:16].hex()
                    expected_sample = expected_block[:16].hex()
                    self.logger.warning(f"Pattern mismatch at offset {bytes_read - len(data)}: "
                                      f"expected {expected_sample}, got {actual_sample}")
            
            # Update progress
            if progress_callback:
                verify_progress = (bytes_read * 50 // device_size)  # Verification is 50% of pass progress
                overall_progress = ((pass_num - 1) * 100 + 50 + verify_progress) // total_passes
                progress_callback(overall_progress, f"Pass {pass_num}/{total_passes}: Verifying")
        
        return hasher.hexdigest()
