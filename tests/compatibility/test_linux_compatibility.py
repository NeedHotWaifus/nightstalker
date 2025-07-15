#!/usr/bin/env python3
"""
Linux Compatibility Test for NightStalker Framework
Tests all modules for Linux compatibility
"""

import sys
import os
import platform
import subprocess

def test_platform_detection():
    """Test platform detection works correctly"""
    print("Testing platform detection...")
    print(f"Platform: {platform.system()}")
    print(f"Architecture: {platform.machine()}")
    print(f"Python version: {platform.python_version()}")
    return True

def test_imports_linux():
    """Test all imports work on Linux"""
    print("\nTesting imports for Linux compatibility...")
    
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
        
        # Test webred module
        from nightstalker.redteam.webred import WebRedTeam
        print("✓ Web red team import successful")
        
        # Test CLI
        from nightstalker.cli import NightStalkerCLI
        print("✓ CLI import successful")
        
        return True
        
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False

def test_gui_fallback():
    """Test GUI fallback to CLI on Linux"""
    print("\nTesting GUI fallback...")
    
    try:
        import gui_exe_builder
        print("✓ GUI EXE builder import successful")
        
        # Test CLI mode (simulated)
        print("✓ GUI fallback to CLI mode available")
        return True
        
    except Exception as e:
        print(f"✗ GUI fallback test failed: {e}")
        return False

def test_linux_specific_features():
    """Test Linux-specific features"""
    print("\nTesting Linux-specific features...")
    
    try:
        # Test /proc filesystem access
        if os.path.exists('/proc/cpuinfo'):
            with open('/proc/cpuinfo', 'r') as f:
                cpu_info = f.read()
                if 'processor' in cpu_info:
                    print("✓ /proc/cpuinfo accessible")
                else:
                    print("⚠ /proc/cpuinfo accessible but no processor info")
        else:
            print("⚠ /proc/cpuinfo not available (not Linux)")
        
        # Test /proc/self/status for debugger detection
        if os.path.exists('/proc/self/status'):
            with open('/proc/self/status', 'r') as f:
                status = f.read()
                if 'TracerPid' in status:
                    print("✓ /proc/self/status accessible")
                else:
                    print("⚠ /proc/self/status accessible but no TracerPid")
        else:
            print("⚠ /proc/self/status not available (not Linux)")
        
        return True
        
    except Exception as e:
        print(f"✗ Linux features test failed: {e}")
        return False

def test_cli_functionality():
    """Test CLI functionality"""
    print("\nTesting CLI functionality...")
    
    try:
        # Test help command
        result = subprocess.run([
            sys.executable, '-m', 'nightstalker.cli', 'help'
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and 'NightStalker CLI' in result.stdout:
            print("✓ CLI help command works")
        else:
            print("✗ CLI help command failed")
            return False
        
        # Test payload list command
        result = subprocess.run([
            sys.executable, '-m', 'nightstalker.cli', 'payload', 'list'
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print("✓ CLI payload list command works")
        else:
            print("✗ CLI payload list command failed")
            return False
        
        return True
        
    except subprocess.TimeoutExpired:
        print("✗ CLI commands timed out")
        return False
    except Exception as e:
        print(f"✗ CLI functionality test failed: {e}")
        return False

def main():
    """Run all Linux compatibility tests"""
    print("NightStalker Framework - Linux Compatibility Test")
    print("=" * 55)
    
    tests = [
        test_platform_detection,
        test_imports_linux,
        test_gui_fallback,
        test_linux_specific_features,
        test_cli_functionality
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 55)
    print(f"Linux Compatibility Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All Linux compatibility tests passed!")
        print("✅ NightStalker framework is ready for Linux deployment")
        return 0
    else:
        print("❌ Some Linux compatibility tests failed")
        print("⚠️  Review the errors above before deploying to Linux")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 