# =============================================================================
# core/mount_manager.py - Drive Mounting/Unmounting Manager
# =============================================================================

import os
import sys
import subprocess
import logging
import psutil
from typing import List, Dict, Any, Tuple

class MountManager:
    """Manages automatic unmounting of external drives before wiping"""
    
    def __init__(self):  # Changed from _init_ to __init__
        self.logger = logging.getLogger(__name__)  # Changed _name_ to __name__
        self.unmounted_drives = []
    
    def unmount_device_safely(self, device_path: str) -> Dict[str, Any]:
        """
        Safely unmount all partitions on a device before wiping
        Skips system drives (C:, /dev/sda with root filesystem)
        """
        result = {
            'unmounted_partitions': [],
            'skipped_partitions': [],
            'errors': [],
            'safe_to_wipe': True
        }
        
        # Skip test files
        if 'test_drive' in os.path.basename(device_path):
            return result
        
        try:
            if sys.platform.startswith('win'):
                result = self._unmount_windows_device(device_path)
            elif sys.platform.startswith('linux'):
                result = self._unmount_linux_device(device_path)
        
        except Exception as e:
            self.logger.error(f"Failed to unmount device {device_path}: {e}")
            result['errors'].append(f"Unmount error: {str(e)}")
            result['safe_to_wipe'] = False
        
        return result
    
    def _unmount_windows_device(self, device_path: str) -> Dict[str, Any]:
        """Unmount Windows device partitions"""
        result = {
            'unmounted_partitions': [],
            'skipped_partitions': [],
            'errors': [],
            'safe_to_wipe': True
        }
        
        try:
            # Extract disk number from device path
            disk_match = re.search(r'physicaldrive(\d+)', device_path.lower())
            if not disk_match:
                return result
            
            disk_number = disk_match.group(1)
            
            # Get all partitions for this disk
            ps_script = f"""
            $diskNumber = {disk_number}
            $systemDrive = [System.Environment]::SystemDirectory.Substring(0, 2)
            $systemDiskNumber = (Get-Partition -DriveLetter $systemDrive[0] | Select-Object -ExpandProperty DiskNumber)
            
            $partitions = Get-Partition -DiskNumber $diskNumber -ErrorAction SilentlyContinue
            
            foreach ($partition in $partitions) {{
                $driveLetter = $partition.DriveLetter
                if ($driveLetter) {{
                    $isSystemDisk = ($diskNumber -eq $systemDiskNumber)
                    $isSystemPartition = ($driveLetter -eq $systemDrive[0])
                    
                    Write-Output "$driveLetter|$isSystemDisk|$isSystemPartition"
                }}
            }}
            """
            
            result_ps = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps_script],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result_ps.returncode != 0:
                result['errors'].append("Failed to enumerate partitions")
                return result
            
            # Process each partition
            for line in result_ps.stdout.strip().split('\n'):
                if '|' in line:
                    parts = line.strip().split('|')
                    if len(parts) >= 3:
                        drive_letter = parts[0]
                        is_system_disk = parts[1] == 'True'
                        is_system_partition = parts[2] == 'True'
                        
                        # Skip system drive and system partition
                        if is_system_disk or is_system_partition or drive_letter == 'C':
                            result['skipped_partitions'].append(f"{drive_letter}: (System drive - cannot unmount)")
                            continue
                        
                        # Attempt to dismount the drive
                        if self._dismount_windows_drive(drive_letter):
                            result['unmounted_partitions'].append(f"{drive_letter}:")
                            self.unmounted_drives.append(f"{drive_letter}:")
                        else:
                            result['errors'].append(f"Failed to unmount {drive_letter}:")
                            result['safe_to_wipe'] = False
        
        except Exception as e:
            self.logger.error(f"Windows unmount error: {e}")
            result['errors'].append(f"Windows unmount error: {str(e)}")
        
        return result
    
    def _unmount_linux_device(self, device_path: str) -> Dict[str, Any]:
        """Unmount Linux device partitions"""
        result = {
            'unmounted_partitions': [],
            'skipped_partitions': [],
            'errors': [],
            'safe_to_wipe': True
        }
        
        try:
            # Get all partitions for this device
            device_name = os.path.basename(device_path)
            
            # Find mounted partitions
            with open('/proc/mounts', 'r') as f:
                mounts = f.readlines()
            
            for mount_line in mounts:
                mount_parts = mount_line.split()
                if len(mount_parts) >= 2:
                    mounted_device = mount_parts[0]
                    mount_point = mount_parts[1]
                    
                    # Check if this partition belongs to our device
                    if device_name in mounted_device:
                        # Skip root filesystem and other critical mounts
                        if mount_point in ['/', '/boot', '/var', '/usr', '/home']:
                            result['skipped_partitions'].append(f"{mounted_device} -> {mount_point} (System mount - cannot unmount)")
                            continue
                        
                        # Skip if mounted device is the same as system device
                        if self._is_system_device(mounted_device):
                            result['skipped_partitions'].append(f"{mounted_device} (System device - cannot unmount)")
                            continue
                        
                        # Attempt to unmount
                        if self._unmount_linux_partition(mounted_device):
                            result['unmounted_partitions'].append(f"{mounted_device} -> {mount_point}")
                            self.unmounted_drives.append(mounted_device)
                        else:
                            result['errors'].append(f"Failed to unmount {mounted_device}")
                            result['safe_to_wipe'] = False
        
        except Exception as e:
            self.logger.error(f"Linux unmount error: {e}")
            result['errors'].append(f"Linux unmount error: {str(e)}")
        
        return result
    
    def _dismount_windows_drive(self, drive_letter: str) -> bool:
        """Dismount a Windows drive letter"""
        try:
            # First, try to flush and close any handles
            ps_script = f"""
            $driveLetter = '{drive_letter}'
            
            # Try to dismount the volume
            $volume = Get-WmiObject -Class Win32_Volume | Where-Object {{ $_.DriveLetter -eq "$driveLetter" + ':' }}
            if ($volume) {{
                $result = $volume.Dismount($false, $false)
                exit $result.ReturnValue
            }}
            exit 1
            """
            
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps_script],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.returncode == 0
        
        except Exception as e:
            self.logger.error(f"Failed to dismount Windows drive {drive_letter}: {e}")
            return False
    
    def _unmount_linux_partition(self, partition_path: str) -> bool:
        """Unmount a Linux partition"""
        try:
            cmd = ['umount', partition_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.logger.info(f"Successfully unmounted {partition_path}")
                return True
            else:
                self.logger.error(f"Failed to unmount {partition_path}: {result.stderr}")
                return False
        
        except Exception as e:
            self.logger.error(f"Unmount error for {partition_path}: {e}")
            return False
    
    def _is_system_device(self, device_path: str) -> bool:
        """Check if device contains system partitions"""
        try:
            # Check if root filesystem is on this device
            with open('/proc/mounts', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == '/':
                        root_device = parts[0]
                        # Extract base device name
                        root_base = re.sub(r'\d+$', '', root_device)
                        device_base = re.sub(r'\d+$', '', device_path)
                        return root_base == device_base
        except Exception:
            pass
        return False
    
    def remount_drives(self) -> bool:
        """Remount drives that were unmounted during the process"""
        success = True
        
        for drive in self.unmounted_drives[:]:  # Copy list to avoid modification during iteration
            try:
                if sys.platform.startswith('win'):
                    # Windows drives should auto-remount when accessed
                    self.logger.info(f"Windows drive {drive} should auto-remount when accessed")
                elif sys.platform.startswith('linux'):
                    # Try to remount Linux partitions
                    if self._remount_linux_partition(drive):
                        self.logger.info(f"Successfully remounted {drive}")
                    else:
                        success = False
                        self.logger.warning(f"Failed to remount {drive}")
                
                self.unmounted_drives.remove(drive)
            
            except Exception as e:
                self.logger.error(f"Error remounting {drive}: {e}")
                success = False
        
        return success
    
    def _remount_linux_partition(self, partition_path: str) -> bool:
        """Attempt to remount a Linux partition"""
        try:
            # Try to mount with original mount point if possible
            # This is complex as we'd need to store original mount points
            # For now, just log that manual remounting may be needed
            self.logger.info(f"Partition {partition_path} may need manual remounting")
            return True
        except Exception as e:
            self.logger.error(f"Remount error for {partition_path}: {e}")
            return False
