#!/usr/bin/env python3
"""
NightStalker Framework Test Script
Tests basic functionality of the framework components
"""

import sys
import os
import json
import tempfile
from pathlib import Path

def test_imports():
    """Test that all modules can be imported"""
    print("Testing module imports...")
    
    try:
        # Test core imports
        from nightstalker.core.automation import AttackChain
        from nightstalker.core.fuzzer import GeneticFuzzer
        from nightstalker.core.exfiltration import CovertChannels
        from nightstalker.core.infection_watchers import FileMonitor
        from nightstalker.core.self_rebuild import EnvironmentManager
        
        # Test builder imports
        from nightstalker.redteam.payload_builder import PayloadBuilder, PayloadConfig
        from nightstalker.redteam.polymorph import PolymorphicEngine
        
        print("✓ All core modules imported successfully")
        return True
        
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False

def test_attack_chain():
    """Test AttackChain functionality"""
    print("Testing AttackChain...")
    
    try:
        from nightstalker.core.automation import AttackChain
        
        # Create attack chain
        chain = AttackChain()
        
        # Test configuration loading
        if hasattr(chain, 'phases') and len(chain.phases) > 0:
            print("✓ AttackChain created with default configuration")
            return True
        else:
            print("✗ AttackChain configuration not loaded")
            return False
            
    except Exception as e:
        print(f"✗ AttackChain test failed: {e}")
        return False

def test_fuzzer():
    """Test GeneticFuzzer functionality"""
    print("Testing GeneticFuzzer...")
    
    try:
        from nightstalker.core.fuzzer import GeneticFuzzer
        
        # Create fuzzer
        fuzzer = GeneticFuzzer()
        
        # Test population initialization
        if hasattr(fuzzer, 'population') and len(fuzzer.population) > 0:
            print("✓ GeneticFuzzer initialized with population")
            return True
        else:
            print("✗ GeneticFuzzer population not initialized")
            return False
            
    except Exception as e:
        print(f"✗ GeneticFuzzer test failed: {e}")
        return False

def test_exfiltration():
    """Test CovertChannels functionality"""
    print("Testing CovertChannels...")
    
    try:
        from nightstalker.core.exfiltration import CovertChannels
        
        # Create exfiltration channels
        exfil = CovertChannels()
        
        # Test channel setup
        if hasattr(exfil, 'channels') and len(exfil.channels) > 0:
            print("✓ CovertChannels initialized with channels")
            return True
        else:
            print("✗ CovertChannels not properly initialized")
            return False
            
    except Exception as e:
        print(f"✗ CovertChannels test failed: {e}")
        return False

def test_file_monitor():
    """Test FileMonitor functionality"""
    print("Testing FileMonitor...")
    
    try:
        from nightstalker.core.infection_watchers import FileMonitor
        
        # Create file monitor
        monitor = FileMonitor()
        
        # Test trigger setup
        if hasattr(monitor, 'triggers') and len(monitor.triggers) > 0:
            print("✓ FileMonitor initialized with triggers")
            return True
        else:
            print("✗ FileMonitor triggers not loaded")
            return False
            
    except Exception as e:
        print(f"✗ FileMonitor test failed: {e}")
        return False

def test_environment_manager():
    """Test EnvironmentManager functionality"""
    print("Testing EnvironmentManager...")
    
    try:
        from nightstalker.core.self_rebuild import EnvironmentManager, EnvironmentConfig
        
        # Create environment manager
        config = EnvironmentConfig(portable_mode=False, burn_after_use=False)
        env_manager = EnvironmentManager(config)
        
        # Test environment setup
        if hasattr(env_manager, 'workspace_path') and env_manager.workspace_path.exists():
            print("✓ EnvironmentManager initialized successfully")
            return True
        else:
            print("✗ EnvironmentManager not properly initialized")
            return False
            
    except Exception as e:
        print(f"✗ EnvironmentManager test failed: {e}")
        return False

def test_payload_builder():
    """Test PayloadBuilder functionality"""
    print("Testing PayloadBuilder...")
    
    try:
        from nightstalker.redteam.payload_builder import PayloadBuilder, PayloadConfig
        
        # Create payload builder
        builder = PayloadBuilder()
        
        # Test shellcode templates
        if hasattr(builder, 'shellcode_templates') and len(builder.shellcode_templates) > 0:
            print("✓ PayloadBuilder initialized with templates")
            return True
        else:
            print("✗ PayloadBuilder templates not loaded")
            return False
            
    except Exception as e:
        print(f"✗ PayloadBuilder test failed: {e}")
        return False

def test_cli():
    """Test CLI functionality"""
    print("Testing CLI...")
    
    try:
        from nightstalker.cli import NightStalkerCLI
        
        # Create CLI instance
        cli = NightStalkerCLI()
        
        # Test parser creation
        if hasattr(cli, 'parser') and cli.parser is not None:
            print("✓ CLI parser created successfully")
            return True
        else:
            print("✗ CLI parser not created")
            return False
            
    except Exception as e:
        print(f"✗ CLI test failed: {e}")
        return False

def test_configuration():
    """Test configuration file loading"""
    print("Testing configuration...")
    
    try:
        config_path = Path("config/campaign.yaml")
        if config_path.exists():
            import yaml
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            if 'phases' in config and len(config['phases']) > 0:
                print("✓ Configuration file loaded successfully")
                return True
            else:
                print("✗ Configuration file missing phases")
                return False
        else:
            print("✗ Configuration file not found")
            return False
            
    except Exception as e:
        print(f"✗ Configuration test failed: {e}")
        return False

def test_directory_structure():
    """Test directory structure"""
    print("Testing directory structure...")
    
    required_dirs = [
        "nightstalker",
        "nightstalker/core",
        "nightstalker/builder",
        "config",
        "results"
    ]
    
    required_files = [
        "nightstalker/__init__.py",
        "nightstalker/core/automation.py",
        "nightstalker/core/fuzzer.py",
        "nightstalker/core/exfiltration.py",
        "nightstalker/core/infection_watchers.py",
        "nightstalker/core/self_rebuild.py",
        "nightstalker/builder/payload_builder.py",
        "nightstalker/cli.py",
        "config/campaign.yaml",
        "requirements.txt",
        "setup.py",
        "README.md"
    ]
    
    missing_dirs = []
    missing_files = []
    
    for dir_path in required_dirs:
        if not Path(dir_path).exists():
            missing_dirs.append(dir_path)
    
    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
    
    if not missing_dirs and not missing_files:
        print("✓ All required directories and files present")
        return True
    else:
        if missing_dirs:
            print(f"✗ Missing directories: {missing_dirs}")
        if missing_files:
            print(f"✗ Missing files: {missing_files}")
        return False

def run_all_tests():
    """Run all tests"""
    print("NightStalker Framework Test Suite")
    print("=================================")
    print()
    
    tests = [
        ("Directory Structure", test_directory_structure),
        ("Module Imports", test_imports),
        ("Configuration", test_configuration),
        ("AttackChain", test_attack_chain),
        ("GeneticFuzzer", test_fuzzer),
        ("CovertChannels", test_exfiltration),
        ("FileMonitor", test_file_monitor),
        ("EnvironmentManager", test_environment_manager),
        ("PayloadBuilder", test_payload_builder),
        ("CLI", test_cli)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        print("-" * len(test_name))
        
        try:
            if test_func():
                passed += 1
                print(f"✓ {test_name} PASSED")
            else:
                print(f"✗ {test_name} FAILED")
        except Exception as e:
            print(f"✗ {test_name} ERROR: {e}")
    
    print(f"\nTest Results:")
    print(f"=============")
    print(f"Passed: {passed}/{total}")
    print(f"Failed: {total - passed}/{total}")
    
    if passed == total:
        print("\n🎉 All tests passed! NightStalker framework is ready to use.")
        return True
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please check the installation.")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1) 