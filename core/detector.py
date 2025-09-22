
# =============================================================================
# core/detector.py - Device Detection
# =============================================================================

import os
import sys
import subprocess
import json
import logging
import glob
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
        
        # Add test files in /tmp for safe testing
        import glob
        test_files = glob.glob('/tmp/test_drive*.img')
        for test_file in test_files:
            if os.path.exists(test_file):
                size = os.path.getsize(test_file)
                devices.append({
                    'path': test_file,
                    'name': os.path.basename(test_file),
                    'size': f"{size} bytes",
                    'model': 'Test Image File',
                    'mounted': False,
                    'type': 'file'
                })
        
        return devices
    
    def _get_windows_devices(self) -> List[Dict[str, Any]]:
        """Get Windows storage devices"""
        devices = []
        
        try:
            # Use PowerShell and WMI to get disk information
            ps_script = """
            $disks = Get-Disk | Where-Object { $_.BusType -ne 'File Backed Virtual' }
            $results = @()
            
            foreach ($disk in $disks) {
                $result += [PSCustomObject]@{
                    DeviceID = $disk.DeviceID
                    Path = "\\\\.\\PHYSICALDRIVE$($disk.DeviceID)"
                    Model = $disk.FriendlyName
                    Size = if ($disk.Size) { "{0} bytes" -f $disk.Size } else { "Unknown" }
                    Type = $disk.MediaType
                    Status = $disk.OperationalStatus
                    Health = $disk.HealthStatus
                    IsMounted = $false  # Default value
                    IsSystem = $false   # Default value
                    IsBoot = $false     # Default value
                }
            }
            
            # Add test files
            $testFiles = Get-ChildItem -Path $env:TEMP -Filter "test_drive*.img" -ErrorAction SilentlyContinue
            foreach ($file in $testFiles) {
                $result += [PSCustomObject]@{
                    DeviceID = -1
                    Path = $file.FullName
                    Model = "Test Image File"
                    Size = if ($file.Length) { "{0} bytes".Format($file.Length) } else { "Unknown" }
                    Type = "File"
                    Status = "OK"
                    Health = "Healthy"
                    IsMounted = $false
                    IsSystem = $false
                    IsBoot = $false
                }
            }
            
            $result | ConvertTo-Json -Depth 5 -Compress
            """
            
            # Execute PowerShell script
            result = subprocess.run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse JSON output
            try:
                data = json.loads(result.stdout)
                
                # Ensure data is a list
                if not isinstance(data, list):
                    data = [data]
                
                # Convert to consistent format
                for disk in data:
                    try:
                        devices.append({
                            'path': str(disk.get('Path', '')),
                            'name': f"PhysicalDrive{disk.get('DeviceID', '0')}",
                            'size': str(disk.get('Size', 'Unknown')),
                            'model': str(disk.get('Model', 'Unknown')).strip(),
                            'mounted': bool(disk.get('IsMounted', False)),
                            'type': str(disk.get('Type', 'disk')).lower(),
                            'is_system': bool(disk.get('IsSystem', False)),
                            'is_boot': bool(disk.get('IsBoot', False))
                        })
                    except Exception as e:
                        self.logger.error(f"Error processing device: {e}")
                        continue
                        
            except json.JSONDecodeError as e:
                self.logger.error(f"Failed to parse device data: {e}")
                self.logger.debug(f"Raw output: {result.stdout}")
                self.logger.debug(f"Error output: {result.stderr}")
                
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            self.logger.error(f"Failed to detect Windows devices: {e}")
        
        # Add test files in %TEMP% for safe testing (Windows equivalent of /tmp)
        try:
            temp_dir = os.environ.get('TEMP', '')
            self.logger.info(f"TEMP directory: {temp_dir}")
            
            if not temp_dir:
                self.logger.warning("TEMP environment variable is not set")
                return devices
                
            test_glob = os.path.join(temp_dir, 'test_drive*.img')
            self.logger.info(f"Looking for test files matching: {test_glob}")
            
            # List all files in TEMP for debugging
            try:
                all_files = os.listdir(temp_dir)
                self.logger.debug(f"Files in TEMP directory: {all_files}")
            except Exception as e:
                self.logger.warning(f"Could not list files in TEMP directory: {e}")
            
            test_files = glob.glob(test_glob)
            self.logger.info(f"Found {len(test_files)} test files")
            
            for test_file in test_files:
                try:
                    if not os.path.isfile(test_file):
                        self.logger.warning(f"Skipping non-file: {test_file}")
                        continue
                        
                    size = os.path.getsize(test_file)
                    device_info = {
                        'path': test_file,
                        'name': os.path.basename(test_file),
                        'size': f"{size} bytes",
                        'model': 'Test Image File',
                        'mounted': False,
                        'type': 'file',
                        'is_system': False,
                        'is_boot': False
                    }
                    devices.append(device_info)
                    self.logger.info(f"Added test file: {test_file} (Size: {size} bytes)")
                    
                except Exception as e:
                    self.logger.error(f"Error processing test file {test_file}: {str(e)}", exc_info=True)
                    
        except Exception as e:
            self.logger.error(f"Unexpected error in test file detection: {str(e)}", exc_info=True)
        
        self.logger.debug(f"Total devices found: {len(devices)}")
        
        return devices
    
    def is_device_safe_to_wipe(self, device_path: str) -> tuple[bool, str]:
        """Check if device is safe to wipe"""
        if not os.path.exists(device_path):
            return False, "Device does not exist"
        
        # Skip mount and system checks for test files
        if 'test_drive' in os.path.basename(device_path):
            return True, "Test file is safe to wipe"
        
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
            elif sys.platform.startswith('win'):
                # Check if any partition on the disk has a drive letter or mount point
                try:
                    ps_script = """
                    $driveNum = [regex]::Match('{0}', 'PHYSICALDRIVE(\\d+)').Groups[1].Value
                    if ($driveNum) {{
                        $partitions = Get-Partition -DiskNumber $driveNum -ErrorAction SilentlyContinue
                        foreach ($part in $partitions) {{
                            if ($part.DriveLetter -or $part.AccessPaths) {{ 
                                exit 1  # Found mounted partition
                            }}
                        }}
                    }}
                    exit 0  # No mounted partitions found
                    """.format(device_path)
                    
                    result = subprocess.run(
                        ['powershell', '-NoProfile', '-Command', ps_script],
                        capture_output=True,
                        text=True
                    )
                    return result.returncode == 1  # Return true if mounted (exit code 1)
                except Exception:
                    return True  # Assume mounted if we can't check
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
        elif sys.platform.startswith('win'):
            try:
                # Check if this is the system disk using WMI
                ps_script = """
                $systemDrive = [System.Environment]::SystemDirectory.Substring(0, 2)
                $systemDisk = Get-Partition -DriveLetter $systemDrive[0] | Select-Object -ExpandProperty DiskNumber
                $diskNum = [regex]::Match('{0}', 'PHYSICALDRIVE(\\d+)').Groups[1].Value
                if ($diskNum -and $systemDisk -eq [int]$diskNum) {{
                    exit 1  # This is the system disk
                }}
                exit 0  # Not the system disk
                """.format(device_path)
                
                result = subprocess.run(
                    ['powershell', '-NoProfile', '-Command', ps_script],
                    capture_output=True,
                    text=True
                )
                return result.returncode == 1  # Return true if system disk (exit code 1)
            except Exception:
                return True  # Assume system drive if we can't check
        
        return False