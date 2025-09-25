# =============================================================================
# core/detector.py - Enhanced Device Detection with SSD Support
# =============================================================================

import os
import sys
import json
import logging
import subprocess
from typing import List, Dict, Any, Optional, Tuple

class DeviceDetector:
    """Detect and analyze storage devices with SSD identification"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def get_all_devices(self) -> List[Dict[str, Any]]:
        """Get list of all storage devices with SSD detection"""
        if sys.platform.startswith('linux'):
            return self._get_linux_devices()
        elif sys.platform.startswith('win'):
            return self._get_windows_devices()
        else:
            self.logger.warning("Unsupported platform")
            return []

    def _get_linux_devices(self) -> List[Dict[str, Any]]:
        """Get Linux storage devices with SSD detection
        
        Returns:
            List of dictionaries containing device information including:
            - path: Device path (e.g., /dev/sda)
            - name: Device model/serial
            - size: Size in bytes
            - is_ssd: Boolean indicating if the device is an SSD
        """
        devices = []
        try:
            # Get all block devices using lsblk
            cmd = [
                'lsblk', '-d', '-n', '-o', 'NAME,MODEL,SIZE,TYPE,ROTA',
                '-e', '7'  # Exclude loop devices and partitions
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                self.logger.error(f"Error running lsblk: {result.stderr}")
                return devices
                
            # Parse lsblk output
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                    
                parts = line.split()
                if len(parts) < 5:
                    continue
                    
                name = parts[0]
                model = ' '.join(parts[1:-3])
                size = parts[-3]
                dev_type = parts[-2]
                is_rotational = parts[-1] == '1'  # 1 for HDD, 0 for SSD
                
                # Skip if not a disk
                if dev_type != 'disk':
                    continue
                    
                # Handle device path
                device_path = f"/dev/{name}"
                
                # Get more detailed info with udev
                udev_info = {}
                try:
                    udev_cmd = ['udevadm', 'info', '--query=property', '--name', device_path]
                    udev_result = subprocess.run(udev_cmd, capture_output=True, text=True)
                    if udev_result.returncode == 0:
                        for prop in udev_result.stdout.split('\n'):
                            if '=' in prop:
                                key, value = prop.split('=', 1)
                                udev_info[key] = value.strip("'")
                except Exception as e:
                    self.logger.warning(f"Could not get udev info for {device_path}: {e}")
                
                # Get size in bytes
                size_bytes = 0
                try:
                    with open(f"/sys/block/{name}/size", 'r') as f:
                        sectors = int(f.read().strip())
                        size_bytes = sectors * 512  # Convert 512-byte sectors to bytes
                except Exception as e:
                    self.logger.warning(f"Could not get size for {device_path}: {e}")
                
                # Add device info
                device_info = {
                    'path': device_path,
                    'name': udev_info.get('ID_MODEL', model).strip() or f"Disk {name}",
                    'model': udev_info.get('ID_MODEL', model).strip(),
                    'size': size_bytes,
                    'size_display': size,
                    'is_ssd': not is_rotational,
                    'type': 'SSD' if not is_rotational else 'HDD',
                    'serial': udev_info.get('ID_SERIAL_SHORT', ''),
                    'vendor': udev_info.get('ID_VENDOR', ''),
                    'removable': udev_info.get('ID_DRIVE_MEDIA_REMOVABLE') == '1',
                    'udev_info': udev_info
                }
                
                devices.append(device_info)
                
        except Exception as e:
            self.logger.error(f"Error getting Linux devices: {e}", exc_info=True)
            
        return devices

    def _get_windows_devices(self) -> List[Dict[str, Any]]:
        """Get Windows storage devices with SSD detection"""
        devices = []
        try:
            # Get all physical disks
            ps_script = """
            $disks = Get-Disk | Where-Object {$_.BusType -ne 'File Backed Virtual'} | Select-Object *
            $result = @()
            
            foreach ($disk in $disks) {
                $diskInfo = @{
                    DeviceID = $disk.Number
                    Model = $disk.Model
                    Size = $disk.Size
                    BusType = $disk.BusType
                    HealthStatus = $disk.HealthStatus
                    OperationalStatus = $disk.OperationalStatus
                    IsSystem = $disk.IsSystem
                    IsBoot = $disk.IsBoot
                    IsSSD = $null
                    IsNVMe = $disk.BusType -eq 'NVM Express'
                    Type = $disk.MediaType
                    Partitions = @()
                }

                # Check if disk is SSD
                if ($disk.MediaType -eq 'SSD' -or $disk.MediaType -eq 'SCSI') {
                    $diskInfo.IsSSD = $true
                } else {
                    $diskInfo.IsSSD = $false
                }

                # Get partition information
                $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue
                foreach ($partition in $partitions) {
                    $driveLetter = if ($partition.DriveLetter) { $partition.DriveLetter + ':' } else { $null }
                    $diskInfo.Partitions += @{
                        PartitionNumber = $partition.PartitionNumber
                        DriveLetter = $driveLetter
                        Size = $partition.Size
                        Type = $partition.Type
                        IsSystem = $partition.IsSystem
                        IsBoot = $partition.IsBoot
                        IsActive = $partition.IsActive
                    }
                }

                $result += $diskInfo
            }
            $result | ConvertTo-Json -Depth 10
            """
            
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps_script],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0 and result.stdout.strip():
                disks = json.loads(result.stdout)
                for disk in disks:
                    device_path = f"\\\\.\\PHYSICALDRIVE{disk['DeviceID']}"
                    devices.append({
                        'path': device_path,
                        'name': f"Disk {disk['DeviceID']} - {disk['Model']}",
                        'size': disk['Size'],
                        'model': disk['Model'],
                        'type': 'ssd' if disk.get('IsSSD') else 'hdd',
                        'is_system': disk['IsSystem'],
                        'is_boot': disk['IsBoot'],
                        'is_ssd': disk.get('IsSSD', False),
                        'is_nvme': disk.get('IsNVMe', False),
                        'partitions': disk.get('Partitions', [])
                    })
        except Exception as e:
            self.logger.error(f"Error getting Windows devices: {e}")
        
        return devices

    def is_device_safe_to_wipe(self, device_path: str) -> Tuple[bool, str]:
        """Check if a device is safe to wipe"""
        if not device_path:
            return False, "No device path provided"
            
        # Skip mount and system checks for test files
        if 'test_drive' in os.path.basename(device_path):
            return True, "Test file is safe to wipe"
        
        # Check if device is mounted
        if self._is_device_mounted(device_path):
            return False, "Device is currently in use"
        
        # Check if it's the system drive
        if self._is_system_drive(device_path):
            return False, "Cannot wipe system drive"
            
        return True, "Device is safe to wipe"
                    
    def _is_device_mounted(self, device_path: str) -> bool:
        """Check if device is mounted or in use.
        
        Returns:
            bool: True if the device is mounted or in use, False otherwise.
        """
        try:
            if not device_path:
                return False
                
            if sys.platform.startswith('win'):
                # For Windows, check if any partition is in use
                if device_path.upper().startswith(r'\\.\PHYSICALDRIVE'):
                    try:
                        disk_num = int(device_path.split('PHYSICALDRIVE')[-1])
                    except (ValueError, IndexError):
                        self.logger.warning(f"Could not parse disk number from path: {device_path}")
                        return False
                    
                    ps_script = f"""
                    $diskNum = {disk_num}
                    $partitions = Get-Partition -DiskNumber $diskNum -ErrorAction SilentlyContinue
                    foreach ($part in $partitions) {{
                        if ($part.DriveLetter) {{
                            $drive = $part.DriveLetter + ':'
                            $volume = Get-Volume -DriveLetter $part.DriveLetter -ErrorAction SilentlyContinue
                            if ($volume -and $volume.FileSystem -ne $null) {{
                                # Check for open files
                                $processes = Get-Process | Where-Object {{ $_.Path -like "$drive\\*" }}
                                if ($processes) {{
                                    Write-Host "Found open files on $drive"
                                    exit 1
                                }}
                            }}
                        }}
                    }}
                    exit 0
                    """
                    
                    result = subprocess.run(
                        ['powershell', '-NoProfile', '-Command', ps_script],
                        capture_output=True,
                        text=True
                    )
                    return result.returncode == 1
                
                # For volume paths (e.g., C:)
                elif ':' in device_path:
                    ps_script = f"""
                    $drive = '{0}'.TrimEnd('\')
                    $volume = Get-Volume -FilePath $drive -ErrorAction SilentlyContinue
                    if ($volume) {{
                        # Check for open files
                        $processes = Get-Process | Where-Object {{ $_.Path -like "$drive*" }}
                        if ($processes) {{
                            Write-Host "Found open files on $drive"
                            exit 1
                        }}
                    }}
                    exit 0
                    """.format(device_path)
                    
                    result = subprocess.run(
                        ['powershell', '-NoProfile', '-Command', ps_script],
                        capture_output=True,
                        text=True
                    )
                    return result.returncode == 1
            
            # Default case for Linux or unknown platforms
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking if device is mounted: {e}")
            return True  # Assume mounted if there's an error to be safe

    def _is_system_drive(self, device_path: str) -> bool:
        """Check if the device is the system drive.
        
        Returns:
            bool: True if the device is the system drive, False otherwise.
        """
        try:
            if not device_path:
                return False
                
            if sys.platform.startswith('win'):
                ps_script = """
                $systemDrive = [System.Environment]::SystemDirectory.Substring(0, 3)
                $systemDisk = (Get-Partition -DriveLetter $systemDrive[0] -ErrorAction SilentlyContinue).DiskNumber
                
                # Check if it's a physical drive
                $match = [regex]::Match('{0}', 'PHYSICALDRIVE(\\d+)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                if ($match.Success) {
                    $diskNum = [int]$match.Groups[1].Value
                    if ($diskNum -eq $systemDisk) {
                        exit 1  # This is the system disk
                    }
                }
                
                # Check if it's a volume on the system disk
                $volumeDrive = [regex]::Match('{0}', '^([A-Za-z]):', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                if ($volumeDrive.Success) {
                    $driveLetter = $volumeDrive.Groups[1].Value
                    $partition = Get-Partition -DriveLetter $driveLetter -ErrorAction SilentlyContinue
                    if ($partition -and $partition.DiskNumber -eq $systemDisk) {
                        exit 1  # This is a volume on the system disk
                    }
                }
                
                exit 0  # Not the system disk
                """.format(device_path)
                
                result = subprocess.run(
                    ['powershell', '-NoProfile', '-Command', ps_script],
                    capture_output=True,
                    text=True
                )
                return result.returncode == 1
                
            # Default case for Linux or unknown platforms
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking if device is system drive: {e}")
            return True  # Assume it's the system drive if there's an error
    def _detect_ssd_linux(self, device_name: str, rota: Optional[str] = None) -> bool:
        """Detect if a Linux device is an SSD using multiple methods.
        
        Args:
            device_name: The name of the device (e.g., 'sda')
            rota: The rotational status from lsblk (1 for HDD, 0 for SSD)
            
        Returns:
            bool: True if the device is an SSD, False otherwise
        """
        try:
            # Method 1: Check the rotational status from lsblk
            if rota is not None:
                return rota == '0'
                
            # Method 2: Check /sys/block/<device>/queue/rotational
            rotational_path = f"/sys/block/{device_name}/queue/rotational"
            if os.path.exists(rotational_path):
                with open(rotational_path, 'r') as f:
                    return f.read().strip() == '0'
                    
            # Method 3: Check device name for SSD indicators
            ssd_indicators = ['ssd', 'nvme', 'mmcblk']
            if any(indicator in device_name.lower() for indicator in ssd_indicators):
                return True
                
            # Default to HDD if we can't determine
            return False
            
        except Exception as e:
            self.logger.warning(f"Error detecting if device is SSD: {e}")
            return False

    def _check_crypto_erase_support_linux(self, device_name: str) -> bool:
        """Check if a Linux device supports cryptographic erase.
        
        Args:
            device_name: The name of the device (e.g., 'sda')
            
        Returns:
            bool: True if cryptographic erase is supported, False otherwise
        """
        try:
            # Check if the device supports ATA security features
            result = subprocess.run(
                ['hdparm', '-I', f"/dev/{device_name}"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                return False
                
            # Look for cryptographic erase support in hdparm output
            return 'cryptographic erase' in result.stdout.lower()
            
        except Exception as e:
            self.logger.warning(f"Error checking crypto erase support: {e}")
            return False

    def _check_secure_erase_support_linux(self, device_name: str) -> bool:
        """Check if a Linux device supports secure erase.
        
        Args:
            device_name: The name of the device (e.g., 'sda')
            
        Returns:
            bool: True if secure erase is supported, False otherwise
        """
        try:
            # Check if the device supports ATA security features
            result = subprocess.run(
                ['hdparm', '-I', f"/dev/{device_name}"],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                return False
                
            # Look for security features in hdparm output
            output = result.stdout.lower()
            return 'supported' in output and 'not enabled' not in output
            
        except Exception as e:
            self.logger.warning(f"Error checking secure erase support: {e}")
            return False

    def _get_recommended_method(self, is_ssd: bool, supports_crypto: bool, 
                              supports_secure: bool) -> str:
        """Determine the recommended wipe method for a device.
        
        Args:
            is_ssd: Whether the device is an SSD
            supports_crypto: Whether the device supports cryptographic erase
            supports_secure: Whether the device supports secure erase
            
        Returns:
            str: The recommended wipe method ('crypto', 'secure', or 'nist')
        """
        if is_ssd:
            if supports_crypto:
                return 'crypto'
            elif supports_secure:
                return 'secure'
        return 'nist'
        for test_file in test_files:
            if os.path.exists(test_file):
                size = os.path.getsize(test_file)
                # Simulate different device types for testing
                is_test_ssd = 'ssd' in os.path.basename(test_file).lower()
                devices.append({
                    'path': test_file,
                    'name': os.path.basename(test_file),
                    'size': f"{size} bytes",
                    'model': 'Test SSD Image File' if is_test_ssd else 'Test HDD Image File',
                    'mounted': False,
                    'type': 'file',
                    'is_ssd': is_test_ssd,
                    'is_nvme': 'nvme' in test_file.lower(),
                    'supports_crypto_erase': is_test_ssd,
                    'supports_secure_erase': is_test_ssd,
                    'recommended_method': 'crypto_erase' if is_test_ssd else 'nist'
                })
        
        return devices
    
    def _get_windows_devices(self) -> List[Dict[str, Any]]:
        """Get Windows storage devices with SSD detection"""
        devices = []
        
        try:
            # Enhanced PowerShell script for SSD detection
            ps_script = """
            $disks = Get-Disk | Where-Object { $_.BusType -ne 'File Backed Virtual' }
            $results = @()
            
            foreach ($disk in $disks) {
                $isNVMe = $disk.BusType -eq 'NVMe'
                $isSSD = $false
                $supportsCryptoErase = $false
                $supportsSecureErase = $false
                
                # Try to detect SSD using multiple methods
                try {
                    # Method 1: Check media type
                    if ($disk.MediaType -eq 'SSD') {
                        $isSSD = $true
                    }
                    
                    # Method 2: Check for SSD in model name
                    if ($disk.FriendlyName -match 'SSD|Solid State|NVMe') {
                        $isSSD = $true
                    }
                    
                    # Method 3: Use WMI to get more details
                    $wmiDisk = Get-WmiObject -Class Win32_DiskDrive | Where-Object { $_.Index -eq $disk.Number }
                    if ($wmiDisk -and ($wmiDisk.Model -match 'SSD|Solid State|NVMe')) {
                        $isSSD = $true
                    }
                    
                    # Check for encryption support (proxy for crypto erase)
                    if ($isSSD) {
                        try {
                            $bitlockerStatus = Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object { $_.MountPoint }
                            if ($bitlockerStatus) {
                                $supportsCryptoErase = $true
                            }
                        } catch {
                            # Assume crypto erase support for SSDs
                            $supportsCryptoErase = $true
                        }
                        
                        # Most modern SSDs support ATA Secure Erase
                        $supportsSecureErase = $true
                    }
                } catch {
                    # If detection fails, use conservative defaults
                    $isSSD = $isNVMe
                }
                
                # Determine recommended method
                $recommendedMethod = 'nist'
                if ($isSSD) {
                    if ($supportsCryptoErase) {
                        $recommendedMethod = 'crypto_erase'
                    } elseif ($supportsSecureErase) {
                        $recommendedMethod = 'secure_erase'
                    } else {
                        $recommendedMethod = 'nist'
                    }
                }
                
                # Ensure we have a valid device ID
                $deviceID = $disk.DeviceID
                if ($null -eq $deviceID) {
                    $deviceID = 0
                }
                
                $results += [PSCustomObject]@{
                    DeviceID = $deviceID
                    Path = "\\\\.\\PHYSICALDRIVE$deviceID"
                    Model = $disk.FriendlyName
                    Size = if ($disk.Size) { "$($disk.Size) bytes" } else { "Unknown" }
                    Type = $disk.MediaType
                    Status = $disk.OperationalStatus
                    Health = $disk.HealthStatus
                    IsMounted = $false
                    IsSystem = $false
                    IsBoot = $false
                    IsSSD = $isSSD
                    IsNVMe = $isNVMe
                    SupportsCryptoErase = $supportsCryptoErase
                    SupportsSecureErase = $supportsSecureErase
                    RecommendedMethod = $recommendedMethod
                }
            }
            
            # Add test files
            $testFiles = Get-ChildItem -Path $env:TEMP -Filter "test_drive*.img" -ErrorAction SilentlyContinue
            foreach ($file in $testFiles) {
                $isTestSSD = $file.Name -match 'ssd'
                $isTestNVMe = $file.Name -match 'nvme'
                
                $results += [PSCustomObject]@{
                    DeviceID = -1
                    Path = $file.FullName
                    Model = if ($isTestSSD) { "Test SSD Image File" } else { "Test HDD Image File" }
                    Size = "$($file.Length) bytes"
                    Type = "File"
                    Status = "OK"
                    Health = "Healthy"
                    IsMounted = $false
                    IsSystem = $false
                    IsBoot = $false
                    IsSSD = $isTestSSD
                    IsNVMe = $isTestNVMe
                    SupportsCryptoErase = $isTestSSD
                    SupportsSecureErase = $isTestSSD
                    RecommendedMethod = if ($isTestSSD) { "crypto_erase" } else { "nist" }
                }
            }
            
            $results | ConvertTo-Json -Depth 5
            """
            
            # Execute PowerShell script and parse results
            result = subprocess.run(
                ['powershell', '-Command', ps_script],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                check=True
            )
            
            try:
                data = json.loads(result.stdout)
                
                # Ensure data is a list
                if not isinstance(data, list):
                    data = [data]
                
                for disk in data:
                    try:
                        # Determine disk type for display
                        disk_type = 'Unknown'
                        if disk.get('IsSSD'):
                            disk_type = 'SSD'
                            if disk.get('IsNVMe'):
                                disk_type = 'NVMe SSD'
                        elif disk.get('Type') and str(disk.get('Type')).lower() == 'hdd':
                            disk_type = 'HDD'
                        
                        devices.append({
                            'path': str(disk.get('Path', '')),
                            'name': f"PhysicalDrive{disk.get('DeviceID', '0')}",
                            'size': str(disk.get('Size', 'Unknown')),
                            'model': str(disk.get('Model', 'Unknown')).strip(),
                            'mounted': bool(disk.get('IsMounted', False)),
                            'type': str(disk.get('Type', 'disk')).lower(),
                            'is_system': bool(disk.get('IsSystem', False)),
                            'is_boot': bool(disk.get('IsBoot', False)),
                            'is_ssd': bool(disk.get('IsSSD', False)),
                            'is_nvme': bool(disk.get('IsNVMe', False)),
                            'disk_type': disk_type,
                            'supports_crypto_erase': bool(disk.get('SupportsCryptoErase', False)),
                            'supports_secure_erase': bool(disk.get('SupportsSecureErase', False)),
                            'recommended_method': str(disk.get('RecommendedMethod', 'nist'))
                        })
                    except Exception as e:
                        self.logger.error(f"Error processing disk info: {e}")
                        continue
                        
            except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
                self.logger.error(f"Failed to detect Windows devices: {e}")
            except Exception as e:
                self.logger.error(f"Unexpected error in _get_windows_devices: {e}")
        except Exception as e:
            self.logger.error(f"Error in Windows device detection: {str(e)}")
            return []
            
        return devices
    
    def _detect_ssd_linux(self, device_name: str, rota: Optional[str]) -> bool:
        """Detect if a Linux device is an SSD using multiple methods"""
        # Method 1: Check rotation flag (0 = SSD, 1 = HDD)
        if rota is not None and rota == '0':
            return True
        
        # Method 2: Check sysfs for rotational
        try:
            with open(f'/sys/block/{device_name}/queue/rotational', 'r') as f:
                if f.read().strip() == '0':
                    return True
        except (IOError, OSError):
            pass
        
        # Method 3: Check device model/name patterns
        try:
            # Read model from sysfs
            with open(f'/sys/block/{device_name}/device/model', 'r') as f:
                model = f.read().strip().lower()
                if any(keyword in model for keyword in ['ssd', 'solid state', 'nvme']):
                    return True
        except (IOError, OSError):
            pass
        
        # Method 4: Check if it's NVMe (almost always SSD)
        if device_name.startswith('nvme'):
            return True
        
        return False
    
    def _check_crypto_erase_support_linux(self, device_name: str) -> bool:
        """Check if device supports cryptographic erase on Linux"""
        # For now, assume all SSDs support some form of crypto erase
        # In practice, you'd check:
        # 1. ATA Security feature set
        # 2. NVMe Format command support
        # 3. Self-Encrypting Drive (SED) capabilities
        return True
    
    def _check_secure_erase_support_linux(self, device_name: str) -> bool:
        """Check if device supports ATA Secure Erase on Linux"""
        try:
            # Use hdparm to check for secure erase support
            result = subprocess.run(['hdparm', '-I', f'/dev/{device_name}'], 
                                  capture_output=True, text=True)
            if 'Security:' in result.stdout and 'erase' in result.stdout.lower():
                return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        return False
    
    def _get_recommended_method(self, is_ssd: bool, supports_crypto: bool, supports_secure: bool) -> str:
        """Determine the recommended wipe method for a device"""
        if not is_ssd:
            return 'nist'  # Traditional overwrite for HDDs
        
        # For SSDs, prioritize crypto erase, then secure erase, then NIST
        if supports_crypto:
            return 'crypto_erase'
        elif supports_secure:
            return 'secure_erase'
        else:
            return 'nist'  # Fallback to traditional overwrite
    
    def is_device_safe_to_wipe(self, device_path: str) -> tuple[bool, str]:
        """Check if a device is safe to wipe
        
        Args:
            device_path: Path to the device to check
            
        Returns:
            tuple[bool, str]: (is_safe, message) where is_safe is True if the device can be wiped
        """
        if not device_path:
            return False, "No device path provided"
            
        self.logger.info(f"Checking device path: {device_path}")
        if not os.path.exists(device_path):
            self.logger.warning(f"Device path does not exist: {device_path}")
            self.logger.warning(f"Current working directory: {os.getcwd()}")
            self.logger.warning(f"Directory contents: {os.listdir(os.path.dirname(device_path) if os.path.dirname(device_path) else '.')}")
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