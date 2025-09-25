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
            result = subprocess.run(['lsblk', '-J', '-o', 'NAME,SIZE,TYPE,MOUNTPOINT,MODEL,HOTPLUG,RM'], 
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
                        'type': 'disk',
                        'removable': device.get('rm') == '1',
                        'hotplug': device.get('hotplug') == '1'
                    })
        
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            self.logger.error(f"Failed to detect Linux devices: {e}")
        
        # Add test files in /tmp for safe testing
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
                    'type': 'file',
                    'removable': True,
                    'hotplug': False
                })
        
        return devices
    
    def _get_windows_devices(self) -> List[Dict[str, Any]]:
        """Get Windows storage devices - ALL devices including external"""
        devices = []
        
        try:
            # Enhanced PowerShell script to detect ALL storage devices
            ps_script = """
            $results = @()
            
            # Get ALL disks (including USB, external, etc.)
            try {
                $disks = Get-Disk -ErrorAction SilentlyContinue | Where-Object { $_.Size -gt 0 }
                
                foreach ($disk in $disks) {
                    $isRemovable = $false
                    $busType = $disk.BusType
                    $isExternal = $false
                    
                    # Detect removable/external drives
                    if ($busType -eq 'USB' -or $busType -eq 'SATA' -or $busType -eq 'SAS' -or 
                        $busType -eq 'SCSi' -or $busType -eq 'Fibre Channel' -or 
                        $busType -eq 'File Backed Virtual' -or $busType -eq 'Unknown') {
                        $isExternal = $true
                    }
                    
                    # Check if removable
                    try {
                        $wmiDisk = Get-WmiObject -Class Win32_DiskDrive | Where-Object { $_.DeviceID -eq "\\\\.\\PHYSICALDRIVE$($disk.Number)" }
                        if ($wmiDisk) {
                            $isRemovable = $wmiDisk.MediaType -match "Removable" -or $wmiDisk.InterfaceType -eq "USB"
                        }
                    } catch {}
                    
                    $results += [PSCustomObject]@{
                        DeviceID = $disk.Number
                        Path = "\\\\.\\PHYSICALDRIVE$($disk.Number)"
                        Model = if ($disk.FriendlyName) { $disk.FriendlyName } else { "Unknown Drive" }
                        Size = if ($disk.Size) { $disk.Size.ToString() + " bytes" } else { "Unknown" }
                        Type = $disk.MediaType
                        BusType = $disk.BusType
                        Status = $disk.OperationalStatus
                        Health = $disk.HealthStatus
                        IsRemovable = $isRemovable
                        IsExternal = $isExternal
                        IsMounted = $false
                        IsSystem = $false
                        IsBoot = $false
                    }
                }
            } catch {
                Write-Host "Error getting disks: $_" -ForegroundColor Red
            }
            
            # Track physical disk numbers we've already processed
            $processedDisks = @()
            foreach ($disk in $disks) {
                $processedDisks += $disk.Number
            }
            
            # Also get logical drives (drive letters)
            try {
                $logicalDisks = Get-WmiObject -Class Win32_LogicalDisk -ErrorAction SilentlyContinue | 
                    Where-Object { $_.DriveType -eq 2 }  # Only removable disks
                
                foreach ($logicalDisk in $logicalDisks) {
                    $isDuplicate = $false
                    
                    # Check if this logical disk belongs to a physical disk we've already processed
                    try {
                        $partition = Get-WmiObject -Class Win32_LogicalDiskToPartition | 
                            Where-Object { $_.Dependent -match $logicalDisk.DeviceID }
                            
                        if ($partition) {
                            $diskDrive = Get-WmiObject -Class Win32_DiskDriveToDiskPartition | 
                                Where-Object { $_.Dependent -eq $partition.Antecedent }
                                
                            if ($diskDrive) {
                                $diskMatch = [regex]::Match($diskDrive.Antecedent, 'PHYSICALDRIVE(\\d+)')
                                if ($diskMatch.Success) {
                                    $diskNum = [int]$diskMatch.Groups[1].Value
                                    # Skip if we've already processed this physical disk
                                    if ($processedDisks -contains $diskNum) {
                                        $isDuplicate = $true
                                    }
                                }
                            }
                        }
                    } catch { 
                        # If we can't determine, assume it's not a duplicate
                        $isDuplicate = $false
                    }
                    
                    # Only add if not a duplicate
                    if (-not $isDuplicate) {
                        $results += [PSCustomObject]@{
                            DeviceID = -1
                            Path = $logicalDisk.DeviceID
                            Model = if ($logicalDisk.VolumeName) { "$($logicalDisk.VolumeName) ($($logicalDisk.DeviceID))" } else { "Removable Drive ($($logicalDisk.DeviceID))" }
                            Size = if ($logicalDisk.Size) { $logicalDisk.Size.ToString() + " bytes" } else { "Unknown" }
                            Type = "Removable"
                            BusType = "USB"
                            Status = "OK"
                            Health = "Healthy"
                            IsRemovable = $true
                            IsExternal = $true
                            IsMounted = $true
                            IsSystem = $false
                            IsBoot = $false
                        }
                    }
                }
            } catch {
                Write-Host "Error getting logical disks: $_" -ForegroundColor Red
            }
            
            # Add USB devices using WMI
            try {
                $usbDevices = Get-WmiObject -Class Win32_DiskDrive | Where-Object { $_.InterfaceType -eq "USB" }
                foreach ($usbDevice in $usbDevices) {
                    # Check if we already added this device
                    $deviceNum = [regex]::Match($usbDevice.DeviceID, 'PHYSICALDRIVE(\\d+)').Groups[1].Value
                    $alreadyAdded = $results | Where-Object { $_.DeviceID -eq [int]$deviceNum }
                    
                    if (-not $alreadyAdded -and $deviceNum) {
                        $results += [PSCustomObject]@{
                            DeviceID = [int]$deviceNum
                            Path = $usbDevice.DeviceID
                            Model = if ($usbDevice.Model) { $usbDevice.Model } else { "USB Drive" }
                            Size = if ($usbDevice.Size) { $usbDevice.Size.ToString() + " bytes" } else { "Unknown" }
                            Type = "USB"
                            BusType = "USB"
                            Status = "OK"
                            Health = "Healthy"
                            IsRemovable = $true
                            IsExternal = $true
                            IsMounted = $false
                            IsSystem = $false
                            IsBoot = $false
                        }
                    }
                }
            } catch {
                Write-Host "Error getting USB devices: $_" -ForegroundColor Red
            }
            
            # Add test files
            try {
                $testFiles = Get-ChildItem -Path $env:TEMP -Filter "test_drive*.img" -ErrorAction SilentlyContinue
                foreach ($file in $testFiles) {
                    $results += [PSCustomObject]@{
                        DeviceID = -1
                        Path = $file.FullName
                        Model = "Test Image File"
                        Size = if ($file.Length) { $file.Length.ToString() + " bytes" } else { "0 bytes" }
                        Type = "File"
                        BusType = "File"
                        Status = "OK"
                        Health = "Healthy"
                        IsRemovable = $true
                        IsExternal = $false
                        IsMounted = $false
                        IsSystem = $false
                        IsBoot = $false
                    }
                }
            } catch {
                Write-Host "Error getting test files: $_" -ForegroundColor Red
            }
            
            # Output results
            if ($results.Count -gt 0) {
                $results | ConvertTo-Json -Depth 5 -Compress
            } else {
                Write-Host "[]"
            }
            """
            
            # Execute PowerShell script
            result = subprocess.run(
                ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
                capture_output=True,
                text=True,
                check=True
            )
            
            self.logger.debug(f"PowerShell output: {result.stdout}")
            self.logger.debug(f"PowerShell errors: {result.stderr}")
            
            # Parse JSON output
            try:
                if result.stdout.strip():
                    data = json.loads(result.stdout)
                    
                    # Ensure data is a list
                    if not isinstance(data, list):
                        data = [data] if data else []
                    
                    # Convert to consistent format
                    for disk in data:
                        try:
                            device_info = {
                                'path': str(disk.get('Path', '')),
                                'name': self._get_device_name(disk),
                                'size': str(disk.get('Size', 'Unknown')),
                                'model': str(disk.get('Model', 'Unknown')).strip(),
                                'mounted': bool(disk.get('IsMounted', False)),
                                'type': str(disk.get('Type', 'disk')).lower(),
                                'bus_type': str(disk.get('BusType', 'Unknown')),
                                'is_removable': bool(disk.get('IsRemovable', False)),
                                'is_external': bool(disk.get('IsExternal', False)),
                                'is_system': bool(disk.get('IsSystem', False)),
                                'is_boot': bool(disk.get('IsBoot', False)),
                                'status': str(disk.get('Status', 'Unknown')),
                                'health': str(disk.get('Health', 'Unknown'))
                            }
                            devices.append(device_info)
                            self.logger.info(f"Found device: {device_info['name']} - {device_info['model']} ({device_info['bus_type']})")
                        except Exception as e:
                            self.logger.error(f"Error processing device: {e}")
                            continue
                else:
                    self.logger.warning("No output from PowerShell script")
                        
            except json.JSONDecodeError as e:
                self.logger.error(f"Failed to parse device data: {e}")
                self.logger.debug(f"Raw output: {result.stdout}")
                self.logger.debug(f"Error output: {result.stderr}")
                
        except subprocess.CalledProcessError as e:
            self.logger.error(f"PowerShell command failed: {e}")
            self.logger.debug(f"Return code: {e.returncode}")
            self.logger.debug(f"Output: {e.stdout}")
            self.logger.debug(f"Error: {e.stderr}")
        except Exception as e:
            self.logger.error(f"Unexpected error detecting Windows devices: {e}", exc_info=True)
        
        # Fallback: Add test files in %TEMP% for safe testing
        try:
            temp_dir = os.environ.get('TEMP', '')
            if temp_dir:
                test_glob = os.path.join(temp_dir, 'test_drive*.img')
                test_files = glob.glob(test_glob)
                
                for test_file in test_files:
                    try:
                        if os.path.isfile(test_file):
                            size = os.path.getsize(test_file)
                            device_info = {
                                'path': test_file,
                                'name': os.path.basename(test_file),
                                'size': f"{size} bytes",
                                'model': 'Test Image File',
                                'mounted': False,
                                'type': 'file',
                                'bus_type': 'File',
                                'is_removable': True,
                                'is_external': False,
                                'is_system': False,
                                'is_boot': False,
                                'status': 'OK',
                                'health': 'Healthy'
                            }
                            # Check if already added
                            if not any(d['path'] == test_file for d in devices):
                                devices.append(device_info)
                                self.logger.info(f"Added test file: {test_file}")
                    except Exception as e:
                        self.logger.error(f"Error processing test file {test_file}: {e}")
        except Exception as e:
            self.logger.error(f"Error in fallback test file detection: {e}")
        
        self.logger.info(f"Total devices found: {len(devices)}")
        for device in devices:
            self.logger.info(f"  - {device['name']}: {device['model']} ({device.get('bus_type', 'Unknown')} - {'External' if device.get('is_external') else 'Internal'})")
        
        # Remove duplicates - prioritize PhysicalDrive entries over logical drives
        seen_devices = {}  # key: (model, size), value: device
        deduplicated_devices = []
        
        for device in devices:
            if device.get('is_external') and device.get('model') != 'Unknown':
                # Create a unique key based on model and size
                model_key = device['model'].strip().lower()
                size_key = device.get('size', '').strip().lower()
                device_key = (model_key, size_key)
                
                if device_key in seen_devices:
                    # Keep PhysicalDrive entries over logical drive entries
                    existing_device = seen_devices[device_key]
                    if 'physicaldrive' in device['name'].lower() and 'physicaldrive' not in existing_device['name'].lower():
                        # Replace logical drive with physical drive
                        seen_devices[device_key] = device
                        # Remove existing device from deduplicated_devices
                        deduplicated_devices = [d for d in deduplicated_devices if d != existing_device]
                        deduplicated_devices.append(device)
                    # If existing is already PhysicalDrive or both are same type, skip this duplicate
                    continue
                else:
                    seen_devices[device_key] = device
                    deduplicated_devices.append(device)
            else:
                deduplicated_devices.append(device)
        
        return deduplicated_devices
    
    def _get_device_name(self, disk_data: Dict[str, Any]) -> str:
        """Generate a consistent device name"""
        device_id = disk_data.get('DeviceID', -1)
        if device_id >= 0:
            return f"PhysicalDrive{device_id}"
        else:
            path = disk_data.get('Path', '')
            if path:
                return os.path.basename(path)
            return "Unknown Device"
    
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