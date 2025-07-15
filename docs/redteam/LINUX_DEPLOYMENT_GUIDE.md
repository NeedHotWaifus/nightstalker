# NightStalker Framework - Linux Deployment Guide

## Overview
NightStalker is a comprehensive offensive security framework that has been tested and optimized for Linux deployment. This guide covers installation, configuration, and usage on Linux systems.

## ✅ Linux Compatibility Status
- **All core modules**: ✅ Compatible
- **CLI interface**: ✅ Fully functional
- **GUI fallback**: ✅ CLI mode when Tkinter unavailable
- **Platform detection**: ✅ Automatic Linux detection
- **File system operations**: ✅ Linux-compatible paths
- **Process management**: ✅ Linux-specific implementations
- **Network operations**: ✅ Cross-platform compatible

## 🚀 Quick Installation

### Prerequisites
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3.8+ and pip
sudo apt install python3 python3-pip python3-venv -y

# Install development tools (optional, for building)
sudo apt install build-essential -y
```

### Framework Installation
```bash
# Clone or copy framework to Linux system
git clone <repository-url> nightstalker
cd nightstalker

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Test installation
python test_linux_compatibility.py
```

## 📋 Framework Components

### Core Modules
- **Automation**: Attack chain management with Linux-specific detection
- **Payload Builder**: Cross-platform payload generation
- **Polymorphic Engine**: Code obfuscation and mutation
- **Exfiltration**: Covert data channels (DNS, HTTPS, ICMP)
- **File Monitoring**: Linux inotify-based file system monitoring
- **Environment Manager**: Portable and burn-after-use modes
- **Genetic Fuzzer**: Intelligent fuzzing with Linux process management

### Red Team Modules
- **C2 Infrastructure**: Command & control with Linux service support
- **Web Red Team**: Web scanning and exploitation tools
- **Stealth Manager**: Linux-specific anti-analysis techniques

## 🖥️ CLI Usage

### Basic Commands
```bash
# Show help
python -m nightstalker.cli help

# List available payloads
python -m nightstalker.cli payload list

# Build a payload
python -m nightstalker.cli payload build --type custom --format python -o output/my_payload.py

# Run penetration testing
python -m nightstalker.cli pentest --target 192.168.1.0/24 --chain full_chain

# Execute red team operations
python -m nightstalker.cli redteam attack --target 10.0.0.5 --payload memory_only
python -m nightstalker.cli redteam fuzz --target http://victim.com/api

# Data exfiltration
python -m nightstalker.cli exfil --data secrets.txt --channels https dns

# File monitoring
python -m nightstalker.cli monitor --paths /tmp /var/log

# Environment management
python -m nightstalker.cli env --status

# Web red teaming
python -m nightstalker.cli webred scan --url https://target.com
python -m nightstalker.cli webred exploit --url https://target.com --exploit sqlmap
```

### Command Groups
1. **payload**: Build, list, and manage payloads
2. **pentest**: Penetration testing campaigns
3. **redteam**: Offensive operations (attack, fuzz)
4. **exfil**: Data exfiltration
5. **monitor**: File system monitoring
6. **env**: Environment management
7. **webred**: Web red teaming operations

## 🛠️ GUI Alternative

### Tkinter Available
```bash
# Run GUI if Tkinter is available
python gui_exe_builder.py
```

### Tkinter Not Available
```bash
# Automatically falls back to CLI interface
python gui_exe_builder.py
# Interactive CLI prompts for payload building
```

## 🔧 Linux-Specific Features

### Platform Detection
- Automatic detection of Linux environment
- `/proc/cpuinfo` for VM detection
- `/proc/self/status` for debugger detection
- Linux-specific file paths and permissions

### File System Monitoring
- Uses Linux `inotify` for efficient file monitoring
- Supports Linux file permissions and ownership
- Monitors `/tmp`, `/var/log`, and custom paths

### Process Management
- Linux process enumeration via `/proc`
- Systemd service integration
- Cron job persistence mechanisms

### Network Operations
- Linux network interface detection
- Socket operations optimized for Linux
- DNS and network scanning capabilities

## 🛡️ Security Considerations

### Permissions
```bash
# Run with appropriate permissions
sudo python -m nightstalker.cli pentest --target 192.168.1.0/24

# For file monitoring (requires read access)
sudo python -m nightstalker.cli monitor --paths /var/log
```

### Firewall Configuration
```bash
# Allow outbound connections for exfiltration
sudo ufw allow out 53/tcp   # DNS
sudo ufw allow out 443/tcp  # HTTPS
sudo ufw allow out 80/tcp   # HTTP
```

### SELinux/AppArmor
```bash
# Check security modules
sestatus
aa-status

# Configure if needed for framework operations
```

## 📊 Testing and Validation

### Run Compatibility Tests
```bash
# Test all modules
python test_all_modules.py

# Test Linux-specific features
python test_linux_compatibility.py

# Test CLI functionality
python -m nightstalker.cli help
```

### Expected Output
```
NightStalker Framework - Linux Compatibility Test
=======================================================
Testing platform detection...
Platform: Linux
Architecture: x86_64
Python version: 3.8.10

Testing imports for Linux compatibility...
✓ All imports successful

Testing GUI fallback...
✓ GUI fallback to CLI mode available

Testing Linux-specific features...
✓ /proc/cpuinfo accessible
✓ /proc/self/status accessible

Testing CLI functionality...
✓ CLI help command works
✓ CLI payload list command works

=======================================================
Linux Compatibility Test Results: 5/5 tests passed
🎉 All Linux compatibility tests passed!
✅ NightStalker framework is ready for Linux deployment
```

## 🚨 Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   # Ensure virtual environment is activated
   source .venv/bin/activate
   
   # Reinstall dependencies
   pip install -r requirements.txt
   ```

2. **Permission Denied**
   ```bash
   # Check file permissions
   ls -la nightstalker/
   
   # Fix permissions if needed
   chmod +x nightstalker/cli.py
   ```

3. **Missing Dependencies**
   ```bash
   # Install system dependencies
   sudo apt install python3-dev libffi-dev libssl-dev -y
   
   # Reinstall Python packages
   pip install --force-reinstall -r requirements.txt
   ```

4. **GUI Not Working**
   ```bash
   # Install Tkinter
   sudo apt install python3-tk -y
   
   # Or use CLI mode
   python gui_exe_builder.py
   ```

### Log Files
```bash
# Check for errors
tail -f /var/log/syslog | grep python

# Framework logs (if configured)
tail -f nightstalker.log
```

## 📈 Performance Optimization

### System Resources
```bash
# Monitor resource usage
htop
iotop
nethogs

# Optimize for high-load operations
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Network Optimization
```bash
# Optimize network settings
echo 'net.core.rmem_max=16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max=16777216' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## 🔄 Updates and Maintenance

### Framework Updates
```bash
# Backup current installation
cp -r nightstalker nightstalker_backup_$(date +%Y%m%d)

# Update framework
git pull origin main

# Test after update
python test_linux_compatibility.py
```

### Dependency Updates
```bash
# Update Python packages
pip install --upgrade -r requirements.txt

# Check for security updates
pip list --outdated
```

## 📞 Support

### Documentation
- Framework documentation: `README.md`
- CLI help: `python -m nightstalker.cli help`
- Module-specific help: `python -m nightstalker.cli <group> --help`

### Testing
- Run all tests: `python test_all_modules.py`
- Linux compatibility: `python test_linux_compatibility.py`
- Individual module tests available in `test_*.py` files

---

**NightStalker Framework is now fully compatible with Linux systems and ready for deployment!** 🎉

For additional support or feature requests, refer to the main documentation or create an issue in the repository. 