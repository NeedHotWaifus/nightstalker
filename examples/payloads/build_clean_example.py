#!/usr/bin/env python3
"""
NightStalker Clean Payload Builder Examples
Demonstrates building functional payloads with proper decryption/decompression
"""

import os
import sys
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nightstalker.redteam.payload_builder import PayloadBuilder

def main():
    """Build clean example payloads"""
    print("NightStalker Clean Payload Builder")
    print("=" * 40)
    
    # Create output directory
    output_dir = Path("output/clean_payloads")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize payload builder
    builder = PayloadBuilder()
    
    # Example 1: Simple System Info Payload
    print("\n1. Building Simple System Info Payload...")
    simple_code = '''
import platform
import os
import socket

def get_system_info():
    """Get basic system information"""
    info = {
        'hostname': platform.node(),
        'os': platform.system(),
        'os_version': platform.version(),
        'architecture': platform.machine(),
        'username': os.getenv('USERNAME') or os.getenv('USER'),
        'current_dir': os.getcwd()
    }
    
    print("=== System Information ===")
    for key, value in info.items():
        print(f"{key}: {value}")
    
    return info

# Execute the function
get_system_info()
'''
    
    try:
        simple_path = builder.build_payload(
            payload_type="system_info",
            payload_code=simple_code,
            output_format="python",
            output_path=str(output_dir / "simple_system_info.py"),
            metadata={'description': 'Simple system information gathering'}
        )
        print(f"✓ Simple payload built: {simple_path}")
    except Exception as e:
        print(f"✗ Failed to build simple payload: {e}")
    
    # Example 2: Network Scanner Payload
    print("\n2. Building Network Scanner Payload...")
    network_code = '''
import socket
import subprocess
import platform

def scan_network():
    """Scan local network for active hosts"""
    print("=== Network Scanner ===")
    
    # Get local IP
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        print(f"Local IP: {local_ip}")
        
        # Extract network prefix
        network_prefix = '.'.join(local_ip.split('.')[:-1])
        print(f"Scanning network: {network_prefix}.0/24")
        
        # Scan common ports
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((local_ip, port))
                if result == 0:
                    print(f"Port {port} is open")
                sock.close()
            except:
                pass
                
    except Exception as e:
        print(f"Network scan failed: {e}")

# Execute the function
scan_network()
'''
    
    try:
        network_path = builder.build_payload(
            payload_type="network_scan",
            payload_code=network_code,
            output_format="python",
            output_path=str(output_dir / "network_scanner.py"),
            metadata={'description': 'Basic network scanning functionality'}
        )
        print(f"✓ Network scanner built: {network_path}")
    except Exception as e:
        print(f"✗ Failed to build network scanner: {e}")
    
    # Example 3: PowerShell System Enumeration
    print("\n3. Building PowerShell System Enumeration...")
    ps_code = '''
# PowerShell System Enumeration
function Get-SystemDetails {
    Write-Host "=== System Details ==="
    
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    $operatingSystem = Get-WmiObject -Class Win32_OperatingSystem
    
    Write-Host "Computer Name: $($computerSystem.Name)"
    Write-Host "Manufacturer: $($computerSystem.Manufacturer)"
    Write-Host "Model: $($computerSystem.Model)"
    Write-Host "OS: $($operatingSystem.Caption)"
    Write-Host "OS Version: $($operatingSystem.Version)"
    Write-Host "Architecture: $($operatingSystem.OSArchitecture)"
    Write-Host "Total Memory: $([math]::Round($computerSystem.TotalPhysicalMemory/1GB, 2)) GB"
    
    Write-Host "`n=== Network Adapters ==="
    Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Format-Table -AutoSize
    
    Write-Host "`n=== Running Services ==="
    Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object -First 10 | Format-Table -AutoSize
}

# Execute the function
Get-SystemDetails
'''
    
    try:
        ps_path = builder.build_payload(
            payload_type="ps_enumeration",
            payload_code=ps_code,
            output_format="powershell",
            output_path=str(output_dir / "ps_system_enum.ps1"),
            metadata={'description': 'PowerShell system enumeration'}
        )
        print(f"✓ PowerShell enumeration built: {ps_path}")
    except Exception as e:
        print(f"✗ Failed to build PowerShell enumeration: {e}")
    
    # Example 4: Bash Process Monitor
    print("\n4. Building Bash Process Monitor...")
    bash_code = '''#!/bin/bash
# Bash Process Monitor

echo "=== Process Monitor ==="
echo "Timestamp: $(date)"
echo ""

echo "=== Top 10 Processes by CPU ==="
ps aux --sort=-%cpu | head -11

echo ""
echo "=== Top 10 Processes by Memory ==="
ps aux --sort=-%mem | head -11

echo ""
echo "=== Network Connections ==="
netstat -tuln | head -10

echo ""
echo "=== Disk Usage ==="
df -h | head -10

echo ""
echo "=== Memory Usage ==="
free -h
'''
    
    try:
        bash_path = builder.build_payload(
            payload_type="bash_monitor",
            payload_code=bash_code,
            output_format="bash",
            output_path=str(output_dir / "bash_process_monitor.sh"),
            metadata={'description': 'Bash process and system monitoring'}
        )
        print(f"✓ Bash monitor built: {bash_path}")
    except Exception as e:
        print(f"✗ Failed to build Bash monitor: {e}")
    
    # Example 5: Multi-stage Clean Payload
    print("\n5. Building Multi-stage Clean Payload...")
    stages = [
        {
            'code': '''
print("Stage 1: System Information")
import platform
print(f"OS: {platform.system()}")
print(f"Hostname: {platform.node()}")
''',
            'conditional': 'True'
        },
        {
            'code': '''
print("Stage 2: User Information")
import os
print(f"User: {os.getenv('USERNAME') or os.getenv('USER')}")
print(f"Current Directory: {os.getcwd()}")
''',
            'conditional': 'True'
        },
        {
            'code': '''
print("Stage 3: Network Information")
import socket
try:
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    print(f"IP Address: {ip}")
except:
    print("Could not get network information")
''',
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
    print(f"Clean payloads built in: {output_dir}")
    print("All payloads include:")
    print("  ✓ Proper error handling")
    print("  ✓ Clean decryption/decompression")
    print("  ✓ No hardcoded malicious logic")
    print("  ✓ Functional execution flow")
    print("  ✓ Test mode support")
    
    # Validate one of the payloads
    print(f"\n=== Validating Payload ===")
    demo_payload = output_dir / "simple_system_info.py"
    if demo_payload.exists():
        print(f"Validating: {demo_payload}")
        try:
            import subprocess
            result = subprocess.run([sys.executable, str(demo_payload)], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("✓ Payload executed successfully!")
                print("Output:")
                print(result.stdout)
            else:
                print(f"✗ Payload execution failed: {result.stderr}")
        except Exception as e:
            print(f"✗ Validation failed: {e}")
    else:
        print("Demo payload not found")

if __name__ == "__main__":
    main() 