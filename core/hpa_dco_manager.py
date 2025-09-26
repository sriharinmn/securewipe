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
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
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
            'hidden_details': [],  # Add list for detailed hidden area info
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
                hidden_mb = (hpa_info['hidden_sectors'] * 512) // (1024 * 1024)
                
                # Add detailed HPA info
                result['hidden_details'].append({
                    'type': 'HPA',
                    'sectors': hpa_info['hidden_sectors'],
                    'size_mb': hidden_mb,
                    'start_lba': hpa_info['current_lba'],
                    'end_lba': hpa_info['max_lba']
                })
                
                result['actions_taken'].append(
                    f"HPA detected: {hidden_mb} MB hidden "
                    f"(sectors {hpa_info['current_lba']} to {hpa_info['max_lba']})"
                )
                
                self.logger.warning(
                    f"⚠ HPA found: {hidden_mb} MB hidden area detected "
                    f"(sectors {hpa_info['current_lba']} to {hpa_info['max_lba']})"
                )
                
            # Detect DCO
            dco_info = self._detect_dco(device_path)
            if dco_info['detected']:
                result['dco_detected'] = True
                result['hidden_sectors'] += dco_info['hidden_sectors']
                hidden_mb = (dco_info['hidden_sectors'] * 512) // (1024 * 1024)
                
                # Add detailed DCO info
                result['hidden_details'].append({
                    'type': 'DCO',
                    'sectors': dco_info['hidden_sectors'],
                    'size_mb': hidden_mb
                })
                
                result['actions_taken'].append(
                    f"DCO detected: {hidden_mb} MB hidden"
                )
                
                self.logger.warning(
                    f"⚠ DCO found: {hidden_mb} MB hidden area detected"
                )
                
            # Total hidden space summary
            if result['hidden_sectors'] > 0:
                total_hidden_mb = (result['hidden_sectors'] * 512) // (1024 * 1024)
                self.logger.warning(
                    f"⚠ Total hidden space: {total_hidden_mb} MB "
                    f"({result['hidden_sectors']} sectors)"
                )

            # Unlock HPA
            if result['hpa_detected'] and self._unlock_hpa(device_path):
                result['hpa_unlocked'] = True
                result['actions_taken'].append("HPA successfully unlocked")
            else:
                result['warnings'].append("Failed to unlock HPA")
            
            # Unlock DCO
            if result['dco_detected'] and self._unlock_dco(device_path):
                result['dco_unlocked'] = True
                result['actions_taken'].append("DCO successfully unlocked")
            else:
                result['warnings'].append("Failed to unlock DCO")
            
            # Get size information
            size_info = self._get_device_sizes(device_path)
            result.update(size_info)
        
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
                current_sectors = self.original_hpa_state['current_sectors']
                max_sectors = self.original_hpa_state['max_sectors']
                
                # Only restore if there was a significant difference
                if (max_sectors - current_sectors) > 1:
                    if self._restore_hpa(self.device_path):
                        self.logger.info("Successfully restored HPA state")
                    else:
                        success = False
                        self.logger.warning("Failed to restore HPA state - drive may need power cycle")
                else:
                    self.logger.info("Skipping HPA restoration - no significant hidden area")
            
            if self.original_dco_state and self.original_dco_state['was_enabled']:
                if self._restore_dco(self.device_path):
                    self.logger.info("Successfully restored DCO state")
                else:
                    success = False
                    self.logger.warning("Failed to restore DCO state - drive may need power cycle")
        except Exception as e:
            self.logger.error(f"Error restoring states: {e}")
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
                cmd = ['hdparm', '-N', device_path]
                proc_result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if proc_result.returncode == 0:
                    output = proc_result.stdout
                    self.logger.info(f"HPA check output: {output.strip()}")
                    
                    hpa_match = re.search(r'max sectors\s*=\s*(\d+)/(\d+)', output)
                    if hpa_match:
                        current_sectors = int(hpa_match.group(1))
                        max_sectors = int(hpa_match.group(2))
                        
                        # Only detect HPA if difference is more than 1 sector
                        if max_sectors > current_sectors and (max_sectors - current_sectors) > 1:
                            result['detected'] = True
                            result['hidden_sectors'] = max_sectors - current_sectors
                            result['max_lba'] = max_sectors
                            result['current_lba'] = current_sectors
                            
                            self.original_hpa_state = {
                                'was_enabled': True,
                                'current_sectors': current_sectors,
                                'max_sectors': max_sectors
                            }
                            self.logger.info(f"HPA detected with {result['hidden_sectors']} hidden sectors")
                        else:
                            self.logger.info("No significant HPA found (difference ≤ 1 sector)")
                    else:
                        self.logger.info("No HPA information found in output")
            
            elif sys.platform.startswith('win'):
                self.logger.info("HPA detection on Windows requires specialized tools")
        except Exception as e:
            self.logger.error(f"HPA detection failed: {e}")
        
        return result
    
    def _detect_dco(self, device_path: str) -> Dict[str, Any]:
        """Detect DCO using hdparm or similar tools"""
        result = {'detected': False, 'hidden_sectors': 0}
        
        try:
            if sys.platform.startswith('linux'):
                # First check if DCO is supported
                cmd_check = ['hdparm', '-I', device_path]
                check_result = subprocess.run(cmd_check, capture_output=True, text=True, timeout=30)
                
                self.logger.info(f"DCO support check output: {check_result.stdout.strip()}")
                
                if 'DCO is' not in check_result.stdout:
                    self.logger.info("DCO is not supported on this device")
                    return result
                
                # Check DCO status
                cmd = ['hdparm', '--dco-identify', device_path]
                proc_result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if proc_result.returncode == 0:
                    output = proc_result.stdout
                    self.logger.info(f"DCO check output: {output.strip()}")
                    
                    if 'DCO is frozen' in output:
                        self.logger.info("DCO is frozen - cannot modify")
                        return result
                    
                    if 'DCO is not supported' in output:
                        self.logger.info("DCO is not supported")
                        return result
                        
                    if 'DCO' in output and 'enabled' in output.lower():
                        sector_match = re.search(r'(\d+)\s+sectors', output)
                        if sector_match:
                            hidden_sectors = int(sector_match.group(1))
                            if hidden_sectors > 0:
                                result['detected'] = True
                                result['hidden_sectors'] = hidden_sectors
                                self.original_dco_state = {
                                    'was_enabled': True,
                                    'hidden_sectors': hidden_sectors
                                }
                                self.logger.info(f"DCO detected with {hidden_sectors} hidden sectors")
                            else:
                                self.logger.info("DCO present but no hidden sectors")
                    else:
                        self.logger.info("No active DCO configuration found")
                else:
                    self.logger.warning(f"DCO identification failed: {proc_result.stderr}")
        except Exception as e:
            self.logger.error(f"DCO detection failed: {e}")
        
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
