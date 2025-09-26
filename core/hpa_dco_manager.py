# =============================================================================
# core/hpa_dco_manager.py - HPA/DCO Detection and Management
# =============================================================================

import os
import sys
import subprocess
import logging
import re
from typing import Dict, Any, Tuple, Optional

class HPADCOManager:
    """Manages HPA (Host Protected Area) and DCO (Device Configuration Overlay) detection and unlocking for HDDs"""
    
    def _init_(self):
        self.logger = logging.getLogger(_name_)
        self.original_hpa_state = None
        self.original_dco_state = None
        self.device_path = None
    
    def detect_and_unlock_hidden_areas(self, device_path: str) -> Dict[str, Any]:
        """
        Detect and unlock HPA/DCO hidden areas
        Returns information about hidden partitions found and actions taken
        """
        self.device_path = device_path
        result = {
            'hpa_detected': False,
            'dco_detected': False,
            'hpa_unlocked': False,
            'dco_unlocked': False,
            'hidden_sectors': 0,
            'original_size': 0,
            'accessible_size': 0,
            'actions_taken': [],
            'warnings': []
        }
        
        # Skip processing for test files and non-physical drives
        if 'test_drive' in os.path.basename(device_path) or not self._is_physical_drive(device_path):
            return result
        
        try:
            # Detect HPA
            hpa_info = self._detect_hpa(device_path)
            if hpa_info['detected']:
                result['hpa_detected'] = True
                result['hidden_sectors'] += hpa_info['hidden_sectors']
                result['actions_taken'].append(f"HPA detected: {hpa_info['hidden_sectors']} hidden sectors")
                
                # Unlock HPA
                if self._unlock_hpa(device_path):
                    result['hpa_unlocked'] = True
                    result['actions_taken'].append("HPA successfully unlocked")
                else:
                    result['warnings'].append("Failed to unlock HPA")
            
            # Detect DCO
            dco_info = self._detect_dco(device_path)
            if dco_info['detected']:
                result['dco_detected'] = True
                result['hidden_sectors'] += dco_info['hidden_sectors']
                result['actions_taken'].append(f"DCO detected: {dco_info['hidden_sectors']} hidden sectors")
                
                # Unlock DCO
                if self._unlock_dco(device_path):
                    result['dco_unlocked'] = True
                    result['actions_taken'].append("DCO successfully unlocked")
                else:
                    result['warnings'].append("Failed to unlock DCO")
            
            # Get size information
            size_info = self._get_device_sizes(device_path)
            result.update(size_info)
            
            if result['hpa_detected'] or result['dco_detected']:
                total_hidden_mb = (result['hidden_sectors'] * 512) // (1024 * 1024)
                result['actions_taken'].append(f"Total hidden space found: {total_hidden_mb} MB")
        
        except Exception as e:
            self.logger.error(f"Error managing HPA/DCO for {device_path}: {e}")
            result['warnings'].append(f"HPA/DCO detection error: {str(e)}")
        
        return result
    
    def restore_original_state(self) -> bool:
        """Restore original HPA/DCO state after wiping"""
        if not self.device_path:
            return True
        
        success = True
        try:
            if self.original_hpa_state and self.original_hpa_state['was_enabled']:
                if not self._restore_hpa(self.device_path):
                    success = False
                    self.logger.warning("Failed to restore original HPA state")
            
            if self.original_dco_state and self.original_dco_state['was_enabled']:
                if not self._restore_dco(self.device_path):
                    success = False
                    self.logger.warning("Failed to restore original DCO state")
        
        except Exception as e:
            self.logger.error(f"Error restoring HPA/DCO state: {e}")
            success = False
        
        return success
    
    def _is_physical_drive(self, device_path: str) -> bool:
        """Check if this is a physical drive that might have HPA/DCO"""
        if sys.platform.startswith('win'):
            return 'physicaldrive' in device_path.lower()
        elif sys.platform.startswith('linux'):
            return device_path.startswith('/dev/sd') or device_path.startswith('/dev/hd')
        return False
    
    def _detect_hpa(self, device_path: str) -> Dict[str, Any]:
        """Detect HPA using hdparm or similar tools"""
        result = {'detected': False, 'hidden_sectors': 0, 'max_lba': 0, 'current_lba': 0}
        
        try:
            if sys.platform.startswith('linux'):
                # Use hdparm to check HPA
                cmd = ['hdparm', '-N', device_path]
                proc_result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if proc_result.returncode == 0:
                    output = proc_result.stdout
                    
                    # Parse hdparm output for HPA information
                    # Example: "max sectors   = 1953525168/1953525168, HPA is disabled"
                    hpa_match = re.search(r'max sectors\s*=\s*(\d+)/(\d+)', output)
                    if hpa_match:
                        current_sectors = int(hpa_match.group(1))
                        max_sectors = int(hpa_match.group(2))
                        
                        if max_sectors > current_sectors:
                            result['detected'] = True
                            result['hidden_sectors'] = max_sectors - current_sectors
                            result['max_lba'] = max_sectors
                            result['current_lba'] = current_sectors
                            
                            # Store original state
                            self.original_hpa_state = {
                                'was_enabled': True,
                                'current_sectors': current_sectors,
                                'max_sectors': max_sectors
                            }
            
            elif sys.platform.startswith('win'):
                # Use Windows diskpart or WMI to check for HPA
                # This is more complex on Windows, would need specialized tools
                self.logger.info("HPA detection on Windows requires specialized tools")
        
        except subprocess.TimeoutExpired:
            self.logger.warning(f"HPA detection timed out for {device_path}")
        except Exception as e:
            self.logger.error(f"HPA detection failed for {device_path}: {e}")
        
        return result
    
    def _detect_dco(self, device_path: str) -> Dict[str, Any]:
        """Detect DCO using hdparm or similar tools"""
        result = {'detected': False, 'hidden_sectors': 0}
        
        try:
            if sys.platform.startswith('linux'):
                # Use hdparm to check DCO
                cmd = ['hdparm', '--dco-identify', device_path]
                proc_result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if proc_result.returncode == 0:
                    output = proc_result.stdout
                    
                    # Check if DCO is active
                    if 'DCO' in output and 'enabled' in output.lower():
                        # Parse for sector information
                        sector_match = re.search(r'(\d+)\s+sectors', output)
                        if sector_match:
                            hidden_sectors = int(sector_match.group(1))
                            result['detected'] = True
                            result['hidden_sectors'] = hidden_sectors
                            
                            # Store original state
                            self.original_dco_state = {
                                'was_enabled': True,
                                'hidden_sectors': hidden_sectors
                            }
        
        except subprocess.TimeoutExpired:
            self.logger.warning(f"DCO detection timed out for {device_path}")
        except Exception as e:
            self.logger.error(f"DCO detection failed for {device_path}: {e}")
        
        return result
    
    def _unlock_hpa(self, device_path: str) -> bool:
        """Unlock HPA to access hidden areas"""
        try:
            if sys.platform.startswith('linux'):
                if self.original_hpa_state:
                    max_sectors = self.original_hpa_state['max_sectors']
                    cmd = ['hdparm', '-N', f'p{max_sectors}', device_path]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    
                    if result.returncode == 0:
                        self.logger.info(f"HPA unlocked for {device_path}")
                        return True
                    else:
                        self.logger.error(f"Failed to unlock HPA: {result.stderr}")
        
        except Exception as e:
            self.logger.error(f"HPA unlock failed: {e}")
        
        return False
    
    def _unlock_dco(self, device_path: str) -> bool:
        """Unlock DCO to access hidden areas"""
        try:
            if sys.platform.startswith('linux'):
                cmd = ['hdparm', '--dco-restore', device_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    self.logger.info(f"DCO unlocked for {device_path}")
                    return True
                else:
                    self.logger.error(f"Failed to unlock DCO: {result.stderr}")
        
        except Exception as e:
            self.logger.error(f"DCO unlock failed: {e}")
        
        return False
    
    def _restore_hpa(self, device_path: str) -> bool:
        """Restore original HPA settings"""
        try:
            if sys.platform.startswith('linux') and self.original_hpa_state:
                current_sectors = self.original_hpa_state['current_sectors']
                cmd = ['hdparm', '-N', f'p{current_sectors}', device_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                return result.returncode == 0
        except Exception as e:
            self.logger.error(f"HPA restore failed: {e}")
        
        return False
    
    def _restore_dco(self, device_path: str) -> bool:
        """Restore original DCO settings"""
        try:
            if sys.platform.startswith('linux'):
                cmd = ['hdparm', '--dco-freeze', device_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                return result.returncode == 0
        except Exception as e:
            self.logger.error(f"DCO restore failed: {e}")
        
        return False
    
    def _get_device_sizes(self, device_path: str) -> Dict[str, int]:
        """Get original and accessible device sizes"""
        result = {'original_size': 0, 'accessible_size': 0}
        
        try:
            # Get current accessible size
            with open(device_path, 'rb') as device:
                device.seek(0, os.SEEK_END)
                result['accessible_size'] = device.tell()
            
            # Original size would be accessible + hidden
            if self.original_hpa_state or self.original_dco_state:
                hidden_bytes = 0
                if self.original_hpa_state:
                    hidden_bytes += (self.original_hpa_state['max_sectors'] - self.original_hpa_state['current_sectors']) * 512
                if self.original_dco_state:
                    hidden_bytes += self.original_dco_state['hidden_sectors'] * 512
                
                result['original_size'] = result['accessible_size'] + hidden_bytes
            else:
                result['original_size'] = result['accessible_size']
        
        except Exception as e:
            self.logger.error(f"Failed to get device sizes: {e}")
        
        return result