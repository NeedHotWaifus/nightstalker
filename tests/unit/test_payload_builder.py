#!/usr/bin/env python3
"""
Test script for NightStalker payload builder
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'nightstalker'))

from redteam.payload_builder import PayloadBuilder

def test_payload_builder():
    """Test the payload builder functionality"""
    print("Testing NightStalker Payload Builder...")
    
    try:
        # Initialize payload builder
        builder = PayloadBuilder()
        print("✓ Payload builder initialized successfully")
        
        # Test Python payload
        python_code = '''
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
        
        # Build Python payload
        output_path = builder.build_payload(
            payload_type="recon",
            payload_code=python_code,
            output_format="python",
            metadata={'description': 'System reconnaissance payload'}
        )
        
        print(f"✓ Python payload built: {output_path}")
        
        # Test PowerShell payload
        powershell_code = '''
# NightStalker PowerShell Payload
Write-Host "NightStalker PowerShell Payload - System Reconnaissance" -ForegroundColor Green
Write-Host "Hostname: $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host "Username: $env:USERNAME" -ForegroundColor Yellow
Write-Host "OS: $((Get-WmiObject -Class Win32_OperatingSystem).Caption)" -ForegroundColor Yellow
Write-Host "Payload execution completed" -ForegroundColor Green
'''
        
        # Build PowerShell payload
        ps_output_path = builder.build_payload(
            payload_type="recon",
            payload_code=powershell_code,
            output_format="powershell",
            metadata={'description': 'PowerShell reconnaissance payload'}
        )
        
        print(f"✓ PowerShell payload built: {ps_output_path}")
        
        # Test Bash payload
        bash_code = '''
#!/bin/bash
echo "NightStalker Bash Payload - System Reconnaissance"
echo "Hostname: $(hostname)"
echo "Username: $(whoami)"
echo "OS: $(uname -a)"
echo "Payload execution completed"
'''
        
        # Build Bash payload
        bash_output_path = builder.build_payload(
            payload_type="recon",
            payload_code=bash_code,
            output_format="bash",
            metadata={'description': 'Bash reconnaissance payload'}
        )
        
        print(f"✓ Bash payload built: {bash_output_path}")
        
        # List available formats
        formats = builder.list_formats()
        print(f"✓ Available formats: {formats}")
        
        print("\n🎉 All payload builder tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_payload_builder()
    sys.exit(0 if success else 1) 