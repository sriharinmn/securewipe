#!/usr/bin/env python3
"""
Safety Test Script - Verify that critical safety checks work
DO NOT RUN WITH REAL DRIVES
"""

import sys
import os
import tempfile

# Add the project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.safety import SafetyChecker
from core.wiper import DataWiper
from core.detector import DeviceDetector

def test_safety_checks():
    """Test that safety checks prevent dangerous operations"""
    
    print("🛡️  Testing Safety Checks")
    print("=" * 50)
    
    safety = SafetyChecker()
    
    # Test 1: Dangerous paths should be blocked
    dangerous_paths = [
        "/dev/disk0",           # macOS main disk
        "/dev/sda",             # Linux main disk
        r"\\.\PHYSICALDRIVE0",  # Windows main disk
        "/System/Applications", # macOS system path
        "C:\\Windows\\System32", # Windows system path
        "/home/user/Documents"  # User documents
    ]
    
    print("Test 1: Blocking dangerous paths")
    for path in dangerous_paths:
        is_safe, reason = safety.is_device_safe_to_wipe(path)
        status = "✅ BLOCKED" if not is_safe else "❌ ALLOWED (DANGER!)"
        print(f"  {path}: {status}")
        if is_safe:
            print(f"    ⚠️  WARNING: This should have been blocked! Reason: {reason}")
    
    # Test 2: Safe test files should be allowed
    print("\\nTest 2: Allowing safe test files")
    
    # Create a temporary test file
    with tempfile.NamedTemporaryFile(prefix="test_drive_", suffix=".img", 
                                   dir="/tmp", delete=False) as tmp:
        tmp.write(b"test data" * 1000)  # Write some test data
        test_file = tmp.name
    
    is_safe, reason = safety.is_device_safe_to_wipe(test_file)
    status = "✅ ALLOWED" if is_safe else "❌ BLOCKED"
    print(f"  {test_file}: {status}")
    if not is_safe:
        print(f"    Reason: {reason}")
    
    # Test 3: Test wiper safety integration
    print("\\nTest 3: Testing wiper safety integration")
    wiper = DataWiper()
    
    # This should fail with safety check
    try:
        result = wiper.wipe_device("/dev/disk0", force_unsafe=False)
        print("  ❌ DANGER: Wiper allowed dangerous operation!")
    except ValueError as e:
        print(f"  ✅ BLOCKED: {e}")
    except Exception as e:
        print(f"  ✅ BLOCKED: Unexpected error (good): {e}")
    
    # Test 4: Test device detector safety markings
    print("\\nTest 4: Testing device detector safety markings")
    detector = DeviceDetector()
    devices = detector.get_all_devices()
    
    unsafe_count = 0
    safe_count = 0
    
    for device in devices:
        if device.get('is_safe_to_wipe', False):
            safe_count += 1
            print(f"  ✅ SAFE: {device['path']}")
        else:
            unsafe_count += 1
            print(f"  🚫 UNSAFE: {device['path']} - {device.get('safety_reason', 'Unknown')}")
    
    print(f"\\nSummary: {unsafe_count} unsafe devices blocked, {safe_count} safe devices found")
    
    # Cleanup
    try:
        os.unlink(test_file)
    except:
        pass
    
    print("\\n🛡️  Safety testing completed!")
    print("If you see any '❌ ALLOWED' messages above, DO NOT USE this tool!")

if __name__ == "__main__":
    test_safety_checks()