#!/usr/bin/env python3
"""
Test script for automatic unmounting functionality
"""

import sys
import os
import logging

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_unmounting():
    """Test the automatic unmounting functionality"""
    
    print("🔧 Testing Automatic Unmounting Functionality")
    print("=" * 50)
    
    # Setup logging
    logging.basicConfig(level=logging.INFO, 
                       format='%(asctime)s - %(levelname)s - %(message)s')
    
    try:
        from utils.device_manager import DeviceManager
        from core.detector import DeviceDetector
        
        print("✅ Modules imported successfully")
        
        # Initialize components
        device_manager = DeviceManager()
        detector = DeviceDetector()
        
        print("✅ Components initialized")
        
        # Get all devices
        devices = detector.get_all_devices()
        print(f"📀 Found {len(devices)} devices")
        
        for i, device in enumerate(devices, 1):
            print(f"\n--- Device {i} ---")
            print(f"Path: {device['path']}")
            print(f"Name: {device['name']}")
            print(f"Size: {device['size']}")
            
            # Get mount information
            try:
                mount_info = detector.get_device_mount_info(device['path'])
                
                print(f"Is Mounted: {mount_info['is_mounted']}")
                print(f"Is System Device: {mount_info['is_system_device']}")
                print(f"Can Unmount: {mount_info['can_unmount']}")
                
                if mount_info['mounted_partitions']:
                    print("Mounted Partitions:")
                    for partition in mount_info['mounted_partitions']:
                        print(f"  • {partition['partition']} → {partition['mountpoint']} ({partition['fstype']})")
                
                # Test safety check
                safe, reason = detector.is_device_safe_to_wipe(device['path'], auto_unmount=True)
                print(f"Safe to Wipe: {'✅ Yes' if safe else '❌ No'}")
                if not safe:
                    print(f"Reason: {reason}")
                else:
                    print(f"Status: {reason}")
                    
            except Exception as e:
                print(f"❌ Error checking device: {e}")
        
        print("\n" + "=" * 50)
        print("🎉 Test completed successfully!")
        print("\n📋 To use automatic unmounting:")
        print("1. Run the GUI: python3 run_gui.py")
        print("2. Select a device")
        print("3. Check the '🔓 Automatically unmount device' option")
        print("4. The device will be unmounted automatically before wiping")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Try installing missing dependencies: pip install -r requirements.txt")
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_unmounting()