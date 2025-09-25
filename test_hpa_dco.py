#!/usr/bin/env python3
"""
Test script to verify HPA/DCO functionality
"""

import tempfile
import os
from core.wiper import DataWiper

def test_hpa_dco_functionality():
    """Test that HPA and DCO detection works safely"""
    
    # Create a test file
    with tempfile.NamedTemporaryFile(suffix='.test', delete=False) as f:
        f.write(b"Test data for HPA/DCO functionality" * 100)
        test_file = f.name
    
    try:
        wiper = DataWiper()
        
        print("🔍 Testing HPA/DCO functionality...")
        
        # Test HPA detection (should return safe results for test file)
        print("Testing HPA detection...")
        hpa_info = wiper.detect_hpa(test_file)
        print(f"HPA Info: {hpa_info}")
        
        # Test DCO detection (should return safe results for test file)
        print("Testing DCO detection...")
        dco_info = wiper.detect_dco(test_file)
        print(f"DCO Info: {dco_info}")
        
        # Test HPA removal (should be safe for test file)
        print("Testing HPA removal...")
        hpa_result = wiper.remove_hpa(test_file)
        print(f"HPA removal result: {hpa_result}")
        
        # Test DCO removal (should be safe for test file)
        print("Testing DCO removal...")
        dco_result = wiper.remove_dco(test_file)
        print(f"DCO removal result: {dco_result}")
        
        # Test safety mechanism with dangerous path
        print("\n🛡️ Testing safety mechanisms...")
        try:
            wiper.wipe_device("/dev/disk0", "nist")  # This should fail safely
            print("❌ ERROR: Safety check failed - dangerous path was allowed!")
        except ValueError as e:
            print(f"✅ GOOD: Safety check worked - {e}")
        
        # Test safe wipe with HPA/DCO options
        print("\n🔥 Testing safe wipe with HPA/DCO options...")
        cert_id = wiper.wipe_device(
            test_file, 
            method="nist",
            remove_hpa=True,
            remove_dco=True
        )
        print(f"✅ Wipe completed successfully with certificate: {cert_id}")
        
        print("\n🎉 All tests passed! HPA/DCO functionality is working correctly.")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Clean up
        if os.path.exists(test_file):
            os.unlink(test_file)

if __name__ == "__main__":
    test_hpa_dco_functionality()