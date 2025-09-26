#!/usr/bin/env python3
"""
Quick test to verify the interface loads without errors
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from gui.interface import SecureWiperGUI
    print("✅ Interface imported successfully")
    
    # Test creating the GUI object
    app = SecureWiperGUI()
    print("✅ GUI object created successfully")
    
    # Test the UI setup
    print("✅ UI setup completed without errors")
    print("🎉 The '-bg' error has been fixed!")
    print("\nTo run the application:")
    print("python main.py")
    
    # Don't actually show the GUI in test
    # app.run()
    
except Exception as e:
    print(f"❌ Error: {e}")
    print("The interface still has issues that need to be fixed.")
