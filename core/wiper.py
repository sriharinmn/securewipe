# =============================================================================
# core/wiper.py - Core Wiping Engine
# =============================================================================

import os
import sys
import random
import hashlib
import time
import logging
from typing import Optional, Callable, Tuple
from datetime import datetime
from utils.device_manager import DeviceManager

class DataWiper:
    """Core data wiping engine with NIST SP 800-88 compliance and automatic unmounting"""
    
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
        self.device_manager = DeviceManager()
        
    def wipe_device(self, device_path: str, method: str = 'nist', 
               progress_callback: Optional[Callable] = None,
               device_info: dict = None, auto_unmount: bool = True) -> str:
        """
        Wipe device using specified method with automatic unmounting
        
        Args:
            device_path: Path to the device to wipe
            method: Wiping method ('nist', 'dod', etc.)
            progress_callback: Optional callback for progress updates
            device_info: Optional device information
            auto_unmount: If True, automatically unmount device before wiping
            
        Returns: Certificate ID for the wipe operation
        """
        start_time = datetime.now()
        unmount_info = None
        
        # Validate device
        if not os.path.exists(device_path):
            raise ValueError(f"Device {device_path} does not exist")
        
        # Handle automatic unmounting
        if auto_unmount and not ('test_drive' in os.path.basename(device_path)):
            unmount_info = self._handle_device_unmounting(device_path, progress_callback)
        
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
            
            # If we unmounted the device and wipe failed, attempt to remount
            if unmount_info and unmount_info.get('unmounted_partitions'):
                self.logger.info("Wipe failed, attempting to remount device...")
                try:
                    success, message = self.device_manager.remount_device(device_path)
                    if success:
                        self.logger.info(f"Device remounted successfully: {message}")
                    else:
                        self.logger.error(f"Failed to remount device: {message}")
                except Exception as remount_error:
                    self.logger.error(f"Error during remount attempt: {remount_error}")
            
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
    
    def _handle_device_unmounting(self, device_path: str, progress_callback: Optional[Callable] = None) -> dict:
        """
        Handle automatic unmounting of the device before wiping
        
        Args:
            device_path: Path to the device
            progress_callback: Optional callback for progress updates
            
        Returns:
            Dictionary with unmounting information
        """
        unmount_info = {
            'was_mounted': False,
            'unmounted_partitions': [],
            'unmount_successful': False,
            'unmount_message': ''
        }
        
        try:
            # Check if device is mounted
            mounted_partitions = self.device_manager.get_mounted_partitions(device_path)
            
            if not mounted_partitions:
                unmount_info['unmount_message'] = "Device has no mounted partitions"
                unmount_info['unmount_successful'] = True
                return unmount_info
            
            unmount_info['was_mounted'] = True
            
            # Update progress
            if progress_callback:
                progress_callback(0, f"Unmounting {len(mounted_partitions)} partitions...")
            
            self.logger.info(f"Found {len(mounted_partitions)} mounted partitions, attempting unmount...")
            
            # Check for critical partitions
            if self.device_manager._has_critical_partitions(mounted_partitions):
                raise ValueError("Device contains system critical partitions and cannot be safely unmounted")
            
            # Attempt unmounting
            success, message, unmounted_partitions = self.device_manager.unmount_device(device_path, force=False)
            
            unmount_info['unmounted_partitions'] = unmounted_partitions
            unmount_info['unmount_successful'] = success
            unmount_info['unmount_message'] = message
            
            if success:
                self.logger.info(f"Successfully unmounted {len(unmounted_partitions)} partitions")
                if progress_callback:
                    progress_callback(5, f"Successfully unmounted {len(unmounted_partitions)} partitions")
            else:
                self.logger.error(f"Failed to unmount device: {message}")
                raise ValueError(f"Cannot unmount device: {message}")
            
        except Exception as e:
            self.logger.error(f"Error during unmounting: {e}")
            raise ValueError(f"Unmounting failed: {e}")
        
        return unmount_info
