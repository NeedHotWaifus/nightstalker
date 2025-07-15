#!/usr/bin/env python3
"""
Comprehensive test script for NightStalker framework
Tests all major modules and components
"""

import sys
import os
import traceback

def test_imports():
    """Test all major imports"""
    print("Testing imports...")
    
    try:
        # Test main framework import
        import nightstalker
        print("✓ Main framework import successful")
        
        # Test core modules
        from nightstalker.core.automation import AttackChain
        print("✓ Core automation import successful")
        
        # Test redteam modules
        from nightstalker.redteam.payload_builder import PayloadBuilder, PayloadConfig
        print("✓ Payload builder import successful")
        
        from nightstalker.redteam.polymorph import PolymorphicEngine
        print("✓ Polymorphic engine import successful")
        
        from nightstalker.redteam.exfiltration import CovertChannels
        print("✓ Exfiltration import successful")
        
        from nightstalker.redteam.infection_watchers import FileMonitor
        print("✓ File monitor import successful")
        
        from nightstalker.redteam.self_rebuild import EnvironmentManager, EnvironmentConfig
        print("✓ Environment manager import successful")
        
        from nightstalker.redteam.fuzzer import GeneticFuzzer
        print("✓ Genetic fuzzer import successful")
        
        # Test C2 modules
        from nightstalker.redteam.c2.command_control import C2Server, C2Client
        print("✓ C2 command control import successful")
        
        from nightstalker.redteam.c2.channels import DNSChannel, HTTPSChannel, ICMPChannel, TorDNSChannel
        print("✓ C2 channels import successful")
        
        from nightstalker.redteam.c2.stealth import StealthManager
        print("✓ C2 stealth import successful")
        
        # Test CLI
        from nightstalker.cli import NightStalkerCLI
        print("✓ CLI import successful")
        
        return True
        
    except Exception as e:
        print(f"✗ Import failed: {e}")
        traceback.print_exc()
        return False

def test_payload_builder():
    """Test payload builder functionality"""
    print("\nTesting payload builder...")
    
    try:
        from nightstalker.redteam.payload_builder import PayloadBuilder
        
        # Create payload builder
        builder = PayloadBuilder()
        print("✓ Payload builder created")
        
        # List available payloads
        payloads = builder.list_payloads()
        print(f"✓ Found {len(payloads)} payloads")
        
        # List available formats
        formats = builder.list_formats()
        print(f"✓ Available formats: {formats}")
        
        return True
        
    except Exception as e:
        print(f"✗ Payload builder test failed: {e}")
        traceback.print_exc()
        return False

def test_gui_builder():
    """Test GUI EXE builder"""
    print("\nTesting GUI EXE builder...")
    
    try:
        import gui_exe_builder
        print("✓ GUI EXE builder import successful")
        
        # Test if we can create the main window (without showing it)
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()  # Hide the window
        
        app = gui_exe_builder.ExeBuilderGUI(root)
        print("✓ GUI application created successfully")
        
        root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ GUI builder test failed: {e}")
        traceback.print_exc()
        return False

def test_example_scripts():
    """Test example scripts"""
    print("\nTesting example scripts...")
    
    try:
        # Test payload builder example
        import test_payload_builder
        print("✓ Payload builder example import successful")
        
        # Test exfiltration example
        import exfil_example
        print("✓ Exfiltration example import successful")
        
        # Test build examples
        import build_example
        print("✓ Build example import successful")
        
        import build_clean_example
        print("✓ Clean build example import successful")
        
        return True
        
    except Exception as e:
        print(f"✗ Example scripts test failed: {e}")
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("NightStalker Framework - Module Test Suite")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_payload_builder,
        test_gui_builder,
        test_example_scripts
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! NightStalker framework is ready to use.")
        return 0
    else:
        print("❌ Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 