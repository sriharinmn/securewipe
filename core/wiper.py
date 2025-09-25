# =============================================================================
# core/wiper.py - Core Wiping Engine
# =============================================================================

import os
import sys
import random
import hashlib
import time
import logging
import subprocess
import struct
from typing import Optional, Callable, Dict, List
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
        self.hpa_detected = False
        self.dco_detected = False
        self.original_hpa_size = 0
        self.original_dco_size = 0
        
    def _is_safe_to_wipe(self, device_path: str) -> bool:
        """
        Critical safety check to prevent wiping system drives
        Returns: True if safe to wipe, False otherwise
        """
        # Never allow wiping these critical paths
        unsafe_paths = [
            '/',           # Root filesystem
            '/dev/disk0',  # Primary macOS drive
            '/dev/sda',    # Primary Linux drive
            '/dev/sda1',   # Primary Linux partition
            'C:',          # Windows C drive
            'C:\\',        # Windows C drive
            '\\\\.\\C:',   # Windows physical C drive
            '\\\\.\\PHYSICALDRIVE0',  # Windows primary physical drive
        ]
        
        # Check if path is in unsafe list
        for unsafe in unsafe_paths:
            if device_path.startswith(unsafe) or device_path == unsafe:
                self.logger.error(f"SAFETY VIOLATION: Attempted to wipe critical system path: {device_path}")
                return False
        
        # Only allow test files and specific safe patterns
        safe_patterns = [
            '/tmp/',
            '/temp/',
            'test_drive',
            'test_file',
            '.img',
            '.test'
        ]
        
        # Check if path contains safe patterns
        is_safe = any(pattern in device_path.lower() for pattern in safe_patterns)
        
        if not is_safe:
            self.logger.error(f"SAFETY VIOLATION: Path does not match safe patterns: {device_path}")
            return False
        
        return True

    def wipe_device(self, device_path: str, method: str = 'nist', 
               progress_callback: Optional[Callable] = None,
               device_info: dict = None,
               remove_hpa: bool = True,
               remove_dco: bool = True) -> str:
        """
        Wipe device using specified method with HPA and DCO support
        
        Args:
            device_path: Path to the device to wipe
            method: Wiping method ('nist' or 'dod')
            progress_callback: Optional callback for progress updates
            device_info: Additional device information
            remove_hpa: Whether to detect and remove HPA areas (default: True)
            remove_dco: Whether to detect and remove DCO areas (default: True)
        
        Returns: Certificate ID for the wipe operation
        """
        start_time = datetime.now()
        
        # CRITICAL SAFETY CHECK
        if not self._is_safe_to_wipe(device_path):
            raise ValueError(f"SAFETY VIOLATION: Cannot wipe {device_path} - this appears to be a system drive!")
        
        # Validate device
        if not os.path.exists(device_path):
            raise ValueError(f"Device {device_path} does not exist")
        
        # Get device size
        device_size = self._get_device_size(device_path)
        if device_size == 0:
            raise ValueError("Could not determine device size")
        
        self.logger.info(f"Starting {method.upper()} wipe of {device_path} ({device_size} bytes)")
        
        # Detect and handle HPA and DCO areas
        hpa_info = {}
        dco_info = {}
        
        if remove_hpa:
            if progress_callback:
                progress_callback(1, "Detecting HPA areas...")
            hpa_info = self.detect_hpa(device_path)
            if hpa_info['present']:
                self.logger.warning(f"HPA detected with {hpa_info['protected_sectors']} protected sectors")
                if self.remove_hpa(device_path):
                    # Recalculate device size after HPA removal
                    new_size = self._get_device_size(device_path)
                    if new_size > device_size:
                        device_size = new_size
                        self.logger.info(f"Device size updated after HPA removal: {device_size} bytes")
        
        if remove_dco:
            if progress_callback:
                progress_callback(2, "Detecting DCO areas...")
            dco_info = self.detect_dco(device_path)
            if dco_info['present']:
                self.logger.warning("DCO detected on device")
                if self.remove_dco(device_path):
                    # Recalculate device size after DCO removal
                    new_size = self._get_device_size(device_path)
                    if new_size > device_size:
                        device_size = new_size
                        self.logger.info(f"Device size updated after DCO removal: {device_size} bytes")
        
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
            'passes': total_passes,
            'hpa_info': hpa_info,
            'dco_info': dco_info,
            'hpa_removed': hpa_info.get('present', False) and remove_hpa,
            'dco_removed': dco_info.get('present', False) and remove_dco
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
    
    def detect_hpa(self, device_path: str) -> Dict[str, any]:
        """
        Detect Host Protected Access (HPA) on ATA/SATA drives
        Returns: Dictionary with HPA status and information
        """
        hpa_info = {
            'present': False,
            'max_native_lba': 0,
            'current_max_lba': 0,
            'protected_sectors': 0,
            'protected_size_bytes': 0
        }
        
        # Only attempt HPA detection on real drives, not test files
        if '/tmp/' in device_path or 'test' in device_path.lower():
            self.logger.info("Skipping HPA detection for test file")
            return hpa_info
        
        try:
            # Use hdparm to check for HPA on Linux/macOS systems
            if sys.platform.startswith(('linux', 'darwin')):
                result = subprocess.run(['hdparm', '-N', device_path], 
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    output = result.stdout
                    for line in output.split('\n'):
                        if 'max sectors' in line.lower():
                            # Parse max sectors information
                            parts = line.split()
                            if len(parts) >= 4:
                                try:
                                    current_max = int(parts[0].replace(',', ''))
                                    max_native = int(parts[3].replace(',', ''))
                                    
                                    if max_native > current_max:
                                        hpa_info['present'] = True
                                        hpa_info['max_native_lba'] = max_native
                                        hpa_info['current_max_lba'] = current_max
                                        hpa_info['protected_sectors'] = max_native - current_max
                                        hpa_info['protected_size_bytes'] = (max_native - current_max) * 512
                                        
                                        self.hpa_detected = True
                                        self.logger.info(f"HPA detected: {hpa_info['protected_sectors']} protected sectors")
                                except ValueError:
                                    pass
            
            elif sys.platform.startswith('win'):
                # Use Windows-specific approach
                self._detect_hpa_windows(device_path, hpa_info)
                
        except subprocess.TimeoutExpired:
            self.logger.warning("HPA detection timed out")
        except FileNotFoundError:
            self.logger.warning("hdparm not found - HPA detection unavailable")
        except Exception as e:
            self.logger.error(f"Error detecting HPA: {e}")
        
        return hpa_info
    
    def detect_dco(self, device_path: str) -> Dict[str, any]:
        """
        Detect Device Configuration Overlay (DCO) on ATA/SATA drives
        Returns: Dictionary with DCO status and information
        """
        dco_info = {
            'present': False,
            'dco_sectors': 0,
            'dco_size_bytes': 0,
            'features_enabled': []
        }
        
        # Only attempt DCO detection on real drives, not test files
        if '/tmp/' in device_path or 'test' in device_path.lower():
            self.logger.info("Skipping DCO detection for test file")
            return dco_info
        
        try:
            if sys.platform.startswith(('linux', 'darwin')):
                # Use hdparm to check for DCO
                result = subprocess.run(['hdparm', '--dco-identify', device_path], 
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    output = result.stdout
                    if 'DCO' in output and 'enabled' in output.lower():
                        dco_info['present'] = True
                        self.dco_detected = True
                        self.logger.info("DCO detected on device")
                        
                        # Parse DCO information
                        for line in output.split('\n'):
                            if 'sectors' in line.lower() and 'dco' in line.lower():
                                try:
                                    sectors = int([x for x in line.split() if x.isdigit()][0])
                                    dco_info['dco_sectors'] = sectors
                                    dco_info['dco_size_bytes'] = sectors * 512
                                except:
                                    pass
            elif sys.platform.startswith('win'):
                # Windows DCO detection would require specialized tools
                self.logger.info("DCO detection on Windows requires specialized tools")
                
        except subprocess.TimeoutExpired:
            self.logger.warning("DCO detection timed out")
        except FileNotFoundError:
            self.logger.warning("hdparm not found - DCO detection unavailable")
        except Exception as e:
            self.logger.error(f"Error detecting DCO: {e}")
        
        return dco_info
    
    def remove_hpa(self, device_path: str) -> bool:
        """
        Remove Host Protected Access (HPA) to access full device capacity
        Returns: True if successful, False otherwise
        """
        try:
            if not self.hpa_detected:
                self.logger.info("No HPA detected, skipping removal")
                return True
            
            # Safety check
            if not self._is_safe_to_wipe(device_path):
                self.logger.error("Safety check failed - cannot remove HPA from system drive")
                return False
            
            if sys.platform.startswith(('linux', 'darwin')):
                # Disable HPA using hdparm
                result = subprocess.run(['hdparm', '-N', 'p', device_path], 
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    self.logger.info("HPA successfully disabled")
                    return True
                else:
                    self.logger.error(f"Failed to disable HPA: {result.stderr}")
                    return False
                    
            elif sys.platform.startswith('win'):
                return self._remove_hpa_windows(device_path)
                
        except subprocess.TimeoutExpired:
            self.logger.error("HPA removal timed out")
            return False
        except FileNotFoundError:
            self.logger.warning("hdparm not found - HPA removal unavailable")
            return False
        except Exception as e:
            self.logger.error(f"Error removing HPA: {e}")
            return False
        
        return False
    
    def remove_dco(self, device_path: str) -> bool:
        """
        Remove Device Configuration Overlay (DCO) to restore original device settings
        Returns: True if successful, False otherwise
        """
        try:
            if not self.dco_detected:
                self.logger.info("No DCO detected, skipping removal")
                return True
            
            # Safety check
            if not self._is_safe_to_wipe(device_path):
                self.logger.error("Safety check failed - cannot remove DCO from system drive")
                return False
                
            if sys.platform.startswith(('linux', 'darwin')):
                # Remove DCO using hdparm
                result = subprocess.run(['hdparm', '--dco-restore', device_path], 
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    self.logger.info("DCO successfully removed")
                    return True
                else:
                    self.logger.error(f"Failed to remove DCO: {result.stderr}")
                    return False
                    
            elif sys.platform.startswith('win'):
                self.logger.warning("DCO removal on Windows requires specialized tools")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("DCO removal timed out")
            return False
        except FileNotFoundError:
            self.logger.warning("hdparm not found - DCO removal unavailable")
            return False
        except Exception as e:
            self.logger.error(f"Error removing DCO: {e}")
            return False
        
        return False
    
    def _detect_hpa_windows(self, device_path: str, hpa_info: Dict) -> None:
        """Windows-specific HPA detection"""
        try:
            # Extract physical drive number from path
            if 'PHYSICALDRIVE' in device_path:
                drive_num = device_path.split('PHYSICALDRIVE')[1]
                
                # Use PowerShell to get disk information
                ps_script = f"""
                try {{
                    $disk = Get-Disk -Number {drive_num} -ErrorAction SilentlyContinue
                    if ($disk) {{
                        $disk | Select-Object Size, AllocatedSize | ConvertTo-Json
                    }}
                }} catch {{
                    Write-Error "Failed to get disk information"
                }}
                """
                
                result = subprocess.run(['powershell', '-Command', ps_script], 
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0 and result.stdout.strip():
                    import json
                    disk_info = json.loads(result.stdout)
                    
                    # Compare allocated vs total size to detect potential HPA
                    if disk_info.get('Size') and disk_info.get('AllocatedSize'):
                        size_diff = disk_info['Size'] - disk_info['AllocatedSize']
                        if size_diff > 0:
                            hpa_info['present'] = True
                            hpa_info['protected_size_bytes'] = size_diff
                            hpa_info['protected_sectors'] = size_diff // 512
                            self.hpa_detected = True
                            
        except Exception as e:
            self.logger.error(f"Windows HPA detection error: {e}")
    
    def _remove_hpa_windows(self, device_path: str) -> bool:
        """Windows-specific HPA removal"""
        try:
            # Windows HPA removal would typically require diskpart or specialized tools
            self.logger.warning("HPA removal on Windows requires administrative privileges and specialized tools")
            return False
        except Exception as e:
            self.logger.error(f"Windows HPA removal error: {e}")
            return False
