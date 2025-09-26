# =============================================================================
# core/wiper.py - Enhanced Core Wiping Engine with HPA/DCO Support
# =============================================================================

import os
import sys
import random
import hashlib
import time
import logging
from typing import Optional, Callable
from datetime import datetime
from .hpa_dco_manager import HPADCOManager
from .mount_manager import MountManager
import logging

class DataWiper:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    """Enhanced core data wiping engine with HPA/DCO and mounting support"""
    
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
    
    def _init_(self):
        self.logger = logging.getLogger(_name_)
        self.block_size = 64 * 1024  # 64KB blocks for performance
        self.hpa_dco_manager = HPADCOManager()
        self.mount_manager = MountManager()
        
    def wipe_device(self, device_path: str, method: str = 'nist', 
               progress_callback: Optional[Callable] = None,
               device_info: dict = None) -> str:
        """
        Enhanced wipe device with HPA/DCO detection and unmounting
        Returns: Certificate ID for the wipe operation
        """
        start_time = datetime.now()
        hidden_partition_info = None
        mount_info = None
        
        # Validate device
        if not os.path.exists(device_path):
            raise ValueError(f"Device {device_path} does not exist")
        
        try:
            # Step 1: Detect and unlock HPA/DCO hidden areas for HDDs
            if progress_callback:
                progress_callback(5, "Detecting hidden partitions (HPA/DCO)...")
            
            hidden_partition_info = self.hpa_dco_manager.detect_and_unlock_hidden_areas(device_path)
            
            if hidden_partition_info['hpa_detected'] or hidden_partition_info['dco_detected']:
                hidden_mb = (hidden_partition_info['hidden_sectors'] * 512) // (1024 * 1024)
                self.logger.info(f"Hidden partitions detected: {hidden_mb} MB")
                if progress_callback:
                    progress_callback(8, f"Found {hidden_mb} MB hidden partitions - unlocked for wiping")
            
            # Step 2: Unmount any mounted partitions
            if progress_callback:
                progress_callback(10, "Unmounting external drives...")
            
            mount_info = self.mount_manager.unmount_device_safely(device_path)
            
            if mount_info['unmounted_partitions']:
                self.logger.info(f"Unmounted partitions: {mount_info['unmounted_partitions']}")
                if progress_callback:
                    progress_callback(15, f"Unmounted {len(mount_info['unmounted_partitions'])} partitions")
            
            if not mount_info['safe_to_wipe']:
                raise ValueError(f"Device cannot be safely wiped: {'; '.join(mount_info['errors'])}")
            
            # Step 3: Get device size (now including unlocked areas)
            if progress_callback:
                progress_callback(18, "Determining device size...")
            
            device_size = self._get_device_size(device_path)
            if device_size == 0:
                raise ValueError("Could not determine device size")
            
            # Check if size increased due to unlocked areas
            if hidden_partition_info and hidden_partition_info['accessible_size'] > 0:
                original_size = hidden_partition_info['original_size']
                if original_size > device_size:
                    self.logger.info(f"Device size increased from {device_size} to {original_size} bytes after unlocking hidden areas")
                    device_size = original_size
            
            self.logger.info(f"Starting {method.upper()} wipe of {device_path} ({device_size} bytes)")
            
            if progress_callback:
                progress_callback(20, f"Starting {method.upper()} wipe ({device_size // (1024*1024)} MB)...")
            
            # Step 4: Perform actual wiping
            patterns = self.NIST_PATTERNS if method == 'nist' else self.DOD_PATTERNS
            total_passes = len(patterns)
            
            verification_hashes = []
            
            with open(device_path, 'r+b', buffering=0) as device:
                for pass_num, pattern in enumerate(patterns, 1):
                    self.logger.info(f"Starting pass {pass_num}/{total_passes}")
                    
                    if pattern is None:
                        # Random pattern
                        pass_hash = self._write_random_pattern(
                            device, device_size, progress_callback, 
                            pass_num, total_passes, base_progress=20
                        )
                    else:
                        # Fixed pattern
                        pass_hash = self._write_fixed_pattern(
                            device, device_size, pattern, progress_callback, 
                            pass_num, total_passes, base_progress=20
                        )
                    
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
            
            # Cleanup on failure
            try:
                if progress_callback:
                    progress_callback(95, "Cleaning up after error...")
                self.hpa_dco_manager.restore_original_state()
                self.mount_manager.remount_drives()
            except:
                pass
            
            raise
        
        finally:
            # Step 5: Cleanup - restore HPA/DCO state and remount drives
            try:
                if progress_callback:
                    progress_callback(95, "Restoring drive state...")
                
                # Restore original HPA/DCO state
                self.hpa_dco_manager.restore_original_state()
                
                # Remount drives
                self.mount_manager.remount_drives()
                
            except Exception as e:
                self.logger.warning(f"Cleanup warning: {e}")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        if progress_callback:
            progress_callback(98, "Generating certificate...")
        
        # Generate certificate with hidden partition information
        from core.certificate import CertificateGenerator
        cert_gen = CertificateGenerator()
        
        cert_data = {
            'device_path': device_path,
            'device_size': device_size,
            'method': method.upper(),
            'start_time': start_time,
            'end_time': end_time,
            'duration': duration,
            'verification_hashes': verification_hashes,
            'passes': total_passes,
            'hidden_partition_info': hidden_partition_info,
            'mount_info': mount_info
        }
        
        cert_id = cert_gen.generate_certificate(cert_data)
        
        if progress_callback:
            progress_callback(100, "Wipe completed successfully!")
        
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
                           progress_callback: Optional[Callable], pass_num: int, 
                           total_passes: int, base_progress: int = 0) -> str:
        """Write fixed pattern to device with enhanced progress tracking"""
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
            
            # Update progress with base offset
            if progress_callback:
                pass_progress = (bytes_written * 100) // device_size
                overall_progress = base_progress + ((pass_num - 1) * (80 // total_passes)) + (pass_progress * (80 // total_passes) // 100)
                mb_written = bytes_written // (1024 * 1024)
                mb_total = device_size // (1024 * 1024)
                progress_callback(overall_progress, f"Pass {pass_num}/{total_passes}: Writing pattern ({mb_written}/{mb_total} MB)")
        
        return hasher.hexdigest()
    
    def _write_random_pattern(self, device, device_size: int, 
                            progress_callback: Optional[Callable], pass_num: int, 
                            total_passes: int, base_progress: int = 0) -> str:
        """Write random pattern to device with enhanced progress tracking"""
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
            
            # Update progress with base offset
            if progress_callback:
                pass_progress = (bytes_written * 100) // device_size
                overall_progress = base_progress + ((pass_num - 1) * (80 // total_passes)) + (pass_progress * (80 // total_passes) // 100)
                mb_written = bytes_written // (1024 * 1024)
                mb_total = device_size // (1024 * 1024)
                progress_callback(overall_progress, f"Pass {pass_num}/{total_passes}: Writing random data ({mb_written}/{mb_total} MB)")
        
        return hasher.hexdigest()