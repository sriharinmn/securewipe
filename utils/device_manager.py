# =============================================================================
# utils/device_manager.py - Device Mounting/Unmounting Management
# =============================================================================

import os
import sys
import subprocess
import logging
import time
import psutil
from typing import List, Dict, Tuple, Optional

class DeviceManager:
    """Manages device mounting and unmounting operations with safety checks"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.unmounted_devices = []  # Track devices we unmounted for potential remounting
        
    def get_mounted_partitions(self, device_path: str) -> List[Dict[str, str]]:
        """Get all mounted partitions for a given device"""
        mounted_partitions = []
        
        try:
            if sys.platform.startswith('linux'):
                mounted_partitions = self._get_linux_mounted_partitions(device_path)
            elif sys.platform.startswith('win'):
                mounted_partitions = self._get_windows_mounted_partitions(device_path)
        except Exception as e:
            self.logger.error(f"Failed to get mounted partitions: {e}")
            
        return mounted_partitions
    
    def _get_linux_mounted_partitions(self, device_path: str) -> List[Dict[str, str]]:
        """Get Linux mounted partitions for a device"""
        mounted_partitions = []
        
        try:
            # Get device basename (e.g., sda from /dev/sda)
            device_name = os.path.basename(device_path)
            
            # Use lsblk to find all partitions and their mount points
            result = subprocess.run(
                ['lsblk', '-J', '-o', 'NAME,MOUNTPOINT,TYPE,FSTYPE'],
                capture_output=True, text=True, check=True
            )
            
            import json
            data = json.loads(result.stdout)
            
            for device in data.get('blockdevices', []):
                if device['name'] == device_name:
                    # Check main device
                    if device.get('mountpoint'):
                        mounted_partitions.append({
                            'partition': f"/dev/{device['name']}",
                            'mountpoint': device['mountpoint'],
                            'fstype': device.get('fstype', 'unknown')
                        })
                    
                    # Check child partitions
                    for child in device.get('children', []):
                        if child.get('mountpoint'):
                            mounted_partitions.append({
                                'partition': f"/dev/{child['name']}",
                                'mountpoint': child['mountpoint'],
                                'fstype': child.get('fstype', 'unknown')
                            })
                            
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            self.logger.error(f"Failed to get Linux mounted partitions: {e}")
            
        return mounted_partitions
    
    def _get_windows_mounted_partitions(self, device_path: str) -> List[Dict[str, str]]:
        """Get Windows mounted partitions for a device"""
        mounted_partitions = []
        
        try:
            # Extract disk number from path like \\.\PHYSICALDRIVE0
            import re
            match = re.search(r'PHYSICALDRIVE(\d+)', device_path)
            if not match:
                return mounted_partitions
                
            disk_number = match.group(1)
            
            ps_script = f"""
            $diskNumber = {disk_number}
            $partitions = Get-Partition -DiskNumber $diskNumber -ErrorAction SilentlyContinue
            $results = @()
            
            foreach ($partition in $partitions) {{
                if ($partition.DriveLetter -or $partition.AccessPaths.Count -gt 0) {{
                    $driveLetter = if ($partition.DriveLetter) {{ $partition.DriveLetter + ":" }} else {{ "" }}
                    $accessPaths = $partition.AccessPaths -join ";"
                    
                    $results += [PSCustomObject]@{{
                        Partition = "Disk$diskNumber Partition$($partition.PartitionNumber)"
                        DriveLetter = $driveLetter  
                        AccessPaths = $accessPaths
                        FileSystem = $partition.FileSystem
                        Size = $partition.Size
                    }}
                }}
            }}
            
            $results | ConvertTo-Json -Depth 2
            """
            
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps_script],
                capture_output=True, text=True, check=True
            )
            
            if result.stdout.strip():
                import json
                data = json.loads(result.stdout)
                
                # Handle single partition (not array) case
                if isinstance(data, dict):
                    data = [data]
                    
                for partition in data:
                    mounted_partitions.append({
                        'partition': partition['Partition'],
                        'mountpoint': partition.get('DriveLetter', '') or partition.get('AccessPaths', ''),
                        'fstype': partition.get('FileSystem', 'unknown')
                    })
        
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            self.logger.error(f"Failed to get Windows mounted partitions: {e}")
            
        return mounted_partitions
    
    def unmount_device(self, device_path: str, force: bool = False) -> Tuple[bool, str, List[Dict]]:
        """
        Unmount all partitions of a device
        Returns: (success, message, list_of_unmounted_partitions)
        """
        self.logger.info(f"Attempting to unmount device: {device_path}")
        
        # Get mounted partitions
        mounted_partitions = self.get_mounted_partitions(device_path)
        
        if not mounted_partitions:
            return True, "Device has no mounted partitions", []
        
        self.logger.info(f"Found {len(mounted_partitions)} mounted partitions")
        
        # Check for system critical partitions
        if not force and self._has_critical_partitions(mounted_partitions):
            return False, "Device contains system critical partitions. Use force=True to override (DANGEROUS!)", []
        
        unmounted_partitions = []
        failed_partitions = []
        
        # Try to unmount each partition
        for partition_info in mounted_partitions:
            success, message = self._unmount_partition(partition_info)
            if success:
                unmounted_partitions.append(partition_info)
                self.logger.info(f"Successfully unmounted: {partition_info['partition']}")
            else:
                failed_partitions.append(partition_info)
                self.logger.error(f"Failed to unmount {partition_info['partition']}: {message}")
        
        # Store unmounted devices for potential remounting
        if unmounted_partitions:
            self.unmounted_devices.append({
                'device_path': device_path,
                'unmounted_partitions': unmounted_partitions,
                'timestamp': time.time()
            })
        
        if failed_partitions:
            failed_names = [p['partition'] for p in failed_partitions]
            return False, f"Failed to unmount partitions: {', '.join(failed_names)}", unmounted_partitions
        
        return True, f"Successfully unmounted {len(unmounted_partitions)} partitions", unmounted_partitions
    
    def _has_critical_partitions(self, partitions: List[Dict]) -> bool:
        """Check if any partition is system critical"""
        for partition in partitions:
            mountpoint = partition.get('mountpoint', '')
            
            if sys.platform.startswith('linux'):
                # Critical Linux mount points
                critical_points = ['/', '/boot', '/boot/efi', '/usr', '/var', '/home']
                if any(mountpoint.startswith(cp) for cp in critical_points):
                    return True
                    
            elif sys.platform.startswith('win'):
                # Critical Windows drive letters
                critical_drives = ['C:', 'C:\\']
                if any(mountpoint.upper().startswith(cd) for cd in critical_drives):
                    return True
        
        return False
    
    def _unmount_partition(self, partition_info: Dict) -> Tuple[bool, str]:
        """Unmount a single partition"""
        partition = partition_info['partition']
        mountpoint = partition_info['mountpoint']
        
        try:
            if sys.platform.startswith('linux'):
                return self._unmount_linux_partition(partition, mountpoint)
            elif sys.platform.startswith('win'):
                return self._unmount_windows_partition(partition, mountpoint)
            else:
                return False, f"Unsupported platform: {sys.platform}"
        except Exception as e:
            return False, f"Exception during unmount: {e}"
    
    def _unmount_linux_partition(self, partition: str, mountpoint: str) -> Tuple[bool, str]:
        """Unmount Linux partition"""
        try:
            # First try graceful unmount
            result = subprocess.run(
                ['umount', mountpoint],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                return True, "Successfully unmounted"
            
            # If graceful fails, try lazy unmount
            self.logger.warning(f"Graceful unmount failed, trying lazy unmount: {result.stderr}")
            result = subprocess.run(
                ['umount', '-l', mountpoint],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                return True, "Successfully unmounted (lazy)"
            
            # If still fails, try force unmount  
            self.logger.warning(f"Lazy unmount failed, trying force unmount: {result.stderr}")
            result = subprocess.run(
                ['umount', '-f', mountpoint],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                return True, "Successfully unmounted (forced)"
            
            return False, f"All unmount attempts failed: {result.stderr}"
            
        except subprocess.TimeoutExpired:
            return False, "Unmount operation timed out"
        except Exception as e:
            return False, f"Unmount exception: {e}"
    
    def _unmount_windows_partition(self, partition: str, mountpoint: str) -> Tuple[bool, str]:
        """Unmount Windows partition"""
        try:
            # For drive letters, use diskpart to remove drive letter
            if ':' in mountpoint and len(mountpoint) == 2:
                drive_letter = mountpoint[0]
                
                diskpart_script = f"""
                select volume {drive_letter}
                remove letter={drive_letter}
                """
                
                # Create temporary diskpart script file
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                    f.write(diskpart_script)
                    script_path = f.name
                
                try:
                    result = subprocess.run(
                        ['diskpart', '/s', script_path],
                        capture_output=True, text=True, timeout=60
                    )
                    
                    os.unlink(script_path)  # Clean up temp file
                    
                    if result.returncode == 0:
                        return True, "Successfully removed drive letter"
                    else:
                        return False, f"Diskpart failed: {result.stderr}"
                        
                except subprocess.TimeoutExpired:
                    os.unlink(script_path)
                    return False, "Diskpart operation timed out"
                    
            else:
                # For access paths, try to remove them
                return False, "Access path unmounting not implemented yet"
                
        except Exception as e:
            return False, f"Windows unmount exception: {e}"
    
    def force_kill_processes_using_device(self, device_path: str) -> Tuple[bool, str]:
        """Force kill processes that are using the device"""
        killed_processes = []
        
        try:
            # Get mounted partitions to find mount points
            mounted_partitions = self.get_mounted_partitions(device_path)
            
            for partition_info in mounted_partitions:
                mountpoint = partition_info['mountpoint']
                
                # Find processes using this mount point
                for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                    try:
                        open_files = proc.info['open_files'] or []
                        for file_info in open_files:
                            if file_info.path.startswith(mountpoint):
                                proc_name = proc.info['name']
                                proc_pid = proc.info['pid']
                                
                                self.logger.warning(f"Killing process {proc_name} (PID: {proc_pid}) using {mountpoint}")
                                
                                # Try graceful termination first
                                proc.terminate()
                                try:
                                    proc.wait(timeout=5)
                                except psutil.TimeoutExpired:
                                    # Force kill if graceful fails
                                    proc.kill()
                                    proc.wait()
                                
                                killed_processes.append(f"{proc_name} (PID: {proc_pid})")
                                break
                                
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            
            if killed_processes:
                return True, f"Killed processes: {', '.join(killed_processes)}"
            else:
                return True, "No processes were using the device"
                
        except Exception as e:
            return False, f"Failed to kill processes: {e}"
    
    def remount_device(self, device_path: str) -> Tuple[bool, str]:
        """Remount previously unmounted partitions"""
        # Find the device in our unmounted devices list
        device_record = None
        for record in self.unmounted_devices:
            if record['device_path'] == device_path:
                device_record = record
                break
        
        if not device_record:
            return False, "No unmounting record found for this device"
        
        remounted_partitions = []
        failed_partitions = []
        
        for partition_info in device_record['unmounted_partitions']:
            success, message = self._remount_partition(partition_info)
            if success:
                remounted_partitions.append(partition_info['partition'])
            else:
                failed_partitions.append(partition_info['partition'])
                self.logger.error(f"Failed to remount {partition_info['partition']}: {message}")
        
        # Remove from unmounted devices list
        self.unmounted_devices.remove(device_record)
        
        if failed_partitions:
            return False, f"Failed to remount: {', '.join(failed_partitions)}"
        
        return True, f"Successfully remounted {len(remounted_partitions)} partitions"
    
    def _remount_partition(self, partition_info: Dict) -> Tuple[bool, str]:
        """Remount a single partition"""
        if sys.platform.startswith('linux'):
            # For Linux, try to mount back to original location
            try:
                result = subprocess.run(
                    ['mount', partition_info['partition'], partition_info['mountpoint']],
                    capture_output=True, text=True, timeout=30
                )
                return result.returncode == 0, result.stderr or "Remounted successfully"
            except Exception as e:
                return False, f"Remount failed: {e}"
                
        elif sys.platform.startswith('win'):
            # For Windows, restore drive letter using diskpart
            mountpoint = partition_info['mountpoint']
            if ':' in mountpoint and len(mountpoint) == 2:
                drive_letter = mountpoint[0]
                
                # Extract partition info from partition name
                import re
                match = re.search(r'Disk(\d+) Partition(\d+)', partition_info['partition'])
                if match:
                    disk_num = match.group(1)
                    partition_num = match.group(2)
                    
                    diskpart_script = f"""
                    select disk {disk_num}
                    select partition {partition_num}
                    assign letter={drive_letter}
                    """
                    
                    import tempfile
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                        f.write(diskpart_script)
                        script_path = f.name
                    
                    try:
                        result = subprocess.run(
                            ['diskpart', '/s', script_path],
                            capture_output=True, text=True, timeout=60
                        )
                        os.unlink(script_path)
                        return result.returncode == 0, result.stderr or "Drive letter restored"
                    except Exception as e:
                        os.unlink(script_path)
                        return False, f"Diskpart remount failed: {e}"
        
        return False, "Remounting not supported for this partition"
    
    def cleanup_unmounted_devices(self, max_age_hours: int = 24):
        """Clean up old unmounted device records"""
        current_time = time.time()
        max_age_seconds = max_age_hours * 3600
        
        self.unmounted_devices = [
            record for record in self.unmounted_devices
            if (current_time - record['timestamp']) < max_age_seconds
        ]