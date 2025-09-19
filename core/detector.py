
# =============================================================================
# core/detector.py - Device Detection
# =============================================================================

import os
import sys
import subprocess
import json
import logging
from typing import List, Dict, Any

class DeviceDetector:
    """Detect and analyze storage devices"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def get_all_devices(self) -> List[Dict[str, Any]]:
        """Get list of all storage devices"""
        devices = []
        
        if sys.platform.startswith('linux'):
            devices = self._get_linux_devices()
        elif sys.platform.startswith('win'):
            devices = self._get_windows_devices()
        else:
            self.logger.warning(f"Unsupported platform: {sys.platform}")
        
        return devices
    
    def _get_linux_devices(self) -> List[Dict[str, Any]]:
        """Get Linux storage devices"""
        devices = []
        
        try:
            # Use lsblk to get block devices
            result = subprocess.run(['lsblk', '-J', '-o', 'NAME,SIZE,TYPE,MOUNTPOINT,MODEL'], 
                                  capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            
            for device in data.get('blockdevices', []):
                if device.get('type') == 'disk':
                    devices.append({
                        'path': f"/dev/{device['name']}",
                        'name': device['name'],
                        'size': device.get('size', 'Unknown'),
                        'model': device.get('model', 'Unknown'),
                        'mounted': device.get('mountpoint') is not None,
                        'type': 'disk'
                    })
        
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            self.logger.error(f"Failed to detect Linux devices: {e}")
        
        return devices
    
    def _get_windows_devices(self) -> List[Dict[str, Any]]:
        """Get Windows storage devices"""
        devices = []
        
        try:
            # Use wmic to get disk drives
            result = subprocess.run([
                'wmic', 'diskdrive', 'get', 
                'DeviceID,Size,Model,MediaType', '/format:csv'
            ], capture_output=True, text=True, check=True)
            
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            for line in lines:
                if line.strip():
                    parts = line.split(',')
                    if len(parts) >= 4:
                        devices.append({
                            'path': parts[1].strip(),
                            'name': parts[1].strip(),
                            'size': parts[4].strip() if parts[4].strip() else 'Unknown',
                            'model': parts[3].strip() if parts[3].strip() else 'Unknown',
                            'type': parts[2].strip() if parts[2].strip() else 'Unknown',
                            'mounted': False
                        })
        
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to detect Windows devices: {e}")
        
        return devices
    
    def is_device_safe_to_wipe(self, device_path: str) -> tuple[bool, str]:
        """Check if device is safe to wipe"""
        if not os.path.exists(device_path):
            return False, "Device does not exist"
        
        # Check if device is mounted
        if self._is_device_mounted(device_path):
            return False, "Device is currently mounted"
        
        # Check if it's the system drive
        if self._is_system_drive(device_path):
            return False, "Cannot wipe system drive"
        
        return True, "Device is safe to wipe"
    
    def _is_device_mounted(self, device_path: str) -> bool:
        """Check if device is mounted"""
        try:
            if sys.platform.startswith('linux'):
                result = subprocess.run(['mount'], capture_output=True, text=True)
                return device_path in result.stdout
            else:
                # Windows check would go here
                return False
        except Exception:
            return True  # Assume mounted if we can't check
    
    def _is_system_drive(self, device_path: str) -> bool:
        """Check if this is the system drive"""
        if sys.platform.startswith('linux'):
            # Check if device contains root filesystem
            try:
                result = subprocess.run(['df', '/'], capture_output=True, text=True)
                return device_path in result.stdout
            except Exception:
                return True  # Assume system drive if we can't check
        
        return False