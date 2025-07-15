#!/usr/bin/env python3
"""
Test Python payload execution
"""

import base64
import sys

def test_payload():
    """Test the payload execution"""
    # This is the same payload code that should be executed
    payload_code = '''
import os
import sys
import platform
import socket

def main():
    print("NightStalker Python Payload - System Reconnaissance")
    print(f"Hostname: {socket.gethostname()}")
    print(f"Platform: {platform.platform()}")
    print(f"Python Version: {sys.version}")
    print(f"Current User: {os.getenv('USERNAME', os.getenv('USER', 'Unknown'))}")
    print("Payload execution completed")

if __name__ == "__main__":
    main()
'''
    
    print("Testing direct payload execution:")
    print("=" * 40)
    
    try:
        exec(payload_code)
        print("✓ Direct execution successful")
    except Exception as e:
        print(f"✗ Direct execution failed: {e}")
        return False
    
    print("\nTesting base64 encoded payload:")
    print("=" * 40)
    
    try:
        # Encode and decode like the payload does
        encoded = base64.b64encode(payload_code.encode()).decode()
        decoded = base64.b64decode(encoded).decode()
        exec(decoded)
        print("✓ Base64 execution successful")
        return True
    except Exception as e:
        print(f"✗ Base64 execution failed: {e}")
        return False

if __name__ == "__main__":
    success = test_payload()
    sys.exit(0 if success else 1) 