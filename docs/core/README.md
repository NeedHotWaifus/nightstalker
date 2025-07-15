# 🌙 NightStalker - Advanced Offensive Security Framework

A comprehensive offensive security framework featuring two specialized subsystems:

## 📋 Table of Contents
- [🌐 NightStalkerWeb - Web Exploitation Framework](#-nightstalkerweb---web-exploitation-framework)
- [🦠 NightStalker - Malware & Red Teaming Framework](#-nightstalker---malware--red-teaming-framework)
- [🚀 Quick Start](#-quick-start)
- [📚 Documentation](#-documentation)
- [📁 Project Files](#-project-files)
- [🔧 Installation](#-installation)
- [⚠️ Legal Disclaimer](#️-legal-disclaimer)

---

# 🌐 NightStalkerWeb - Web Exploitation Framework

**Specialized web penetration testing and exploitation framework with automated tool management and modular architecture.**

## 🎯 Features
- **Automated Tool Installation**: One-click setup of essential web pentesting tools
- **Modular Architecture**: Organized modules for recon, exploit, bruteforce, post-exploitation
- **Rich TUI Interface**: User-friendly text interface for web security assessments
- **Integrated Reporting**: Comprehensive HTML reports with evidence collection
- **Tool Integration**: Sn1per, SQLMap, Nuclei, WPScan, Nikto, and more

## 🛠️ Included Tools
- **Reconnaissance**: Sn1per, Nuclei, Nikto, Dirsearch, Httpx, WPScan
- **Exploitation**: SQLMap, Metasploit Framework, Nuclei
- **Bruteforce**: OpenBullet 2, Hydra
- **Post-Exploitation**: Metasploit, Netcat
- **Auxiliary**: Proxychains, Ngrok, Burp Suite

## 📁 Structure
```
nightstalker_web/
├── modules/
│   ├── recon/          # Reconnaissance modules
│   ├── exploit/        # Exploitation modules
│   ├── bruteforce/     # Bruteforce modules
│   ├── post/           # Post-exploitation modules
│   └── auxiliary/      # Supporting tools
├── tools/              # Installed tools (Sn1per, etc.)
├── loot/               # Target-specific results
└── bin/                # Wrapper scripts
```

## 🚀 Quick Start (Web Exploitation)
```bash
# Install the web exploitation framework
python install_web_exploit_framework.py

# Launch the TUI interface
python -m nightstalker.redteam.web_exploit_tui

# Or use CLI commands
python -m nightstalker.cli webred scan --url https://target.com
python -m nightstalker.cli webred exploit --url https://target.com --exploit sqlmap
```

## 📚 Documentation
- [Web Exploitation Framework Guide](WEB_EXPLOIT_FRAMEWORK_README.md)
- [Web Red Teaming Guide](WEB_RED_TEAMING_GUIDE.md)

---

# 🦠 NightStalker - Malware & Red Teaming Framework

**Advanced malware development, red teaming, and offensive security framework with stealth capabilities and modular payload system.**

## 🎯 Features
- **Modular Payload System**: Build, customize, and deploy various payload types
- **Polymorphic Engine**: Advanced obfuscation and anti-detection techniques
- **Command & Control**: Multi-channel C2 with stealth capabilities
- **Exfiltration**: Covert data exfiltration via multiple channels
- **Persistence**: Advanced persistence mechanisms
- **Anti-Analysis**: Anti-debug, anti-sandbox, and anti-VM techniques

## 🛠️ Core Components
- **Payload Builder**: Python, PowerShell, Bash, EXE payloads
- **C2 Infrastructure**: DNS, HTTPS, ICMP channels
- **Exfiltration**: HTTPS, DNS, Email, Telegram, GitHub
- **Monitoring**: File system and process monitoring
- **Self-Rebuild**: Environment reconstruction capabilities

## 📁 Structure
```
nightstalker/
├── redteam/            # Red teaming modules
│   ├── c2/            # Command & Control
│   ├── webred.py      # Web red teaming
│   ├── exfiltration.py # Data exfiltration
│   ├── fuzzer.py      # Genetic fuzzing
│   └── ...
├── pentest/            # Penetration testing
├── core/               # Core framework
├── builder/            # Payload building
└── payloads/           # Payload templates
```

## 🚀 Quick Start (Malware/Red Teaming)
```bash
# Build a payload
python -m nightstalker.cli payload build --type recon --format python -o payload.py

# Run red team operations
python -m nightstalker.cli redteam attack --target 10.0.0.5 --payload memory_only

# Exfiltrate data
python -m nightstalker.cli exfil --data secrets.txt --channels https dns

# Monitor file system
python -m nightstalker.cli monitor --paths /tmp /var/log
```

## 📚 Documentation
- [Linux Deployment Guide](LINUX_DEPLOYMENT_GUIDE.md)
- [Exfiltration Guide](EXFILTRATION_GUIDE.md)
- [Covert Server Guide](COVERT_SERVER_GUIDE.md)

---

# 🚀 Quick Start

## Prerequisites
- Python 3.8+
- Linux/macOS (recommended) or Windows
- Git

## Installation

### Option 1: Web Exploitation Only
```bash
# Install web exploitation framework
python install_web_exploit_framework.py
```

### Option 2: Full Framework
```bash
# Install all dependencies
pip install -r requirements.txt

# Setup the framework
python setup.py install
```

### Option 3: Development Setup
```bash
# Clone and setup
git clone <repository>
cd nightstalker
pip install -r requirements.txt
python setup.py develop
```

## Usage Examples

### Web Exploitation
```bash
# Launch web exploitation TUI
python -m nightstalker.redteam.web_exploit_tui

# Run web reconnaissance
python -m nightstalker.cli webred scan --url https://target.com --modules all

# Execute web exploits
python -m nightstalker.cli webred exploit --url https://target.com --exploit sqlmap
```

### Malware/Red Teaming
```bash
# Build polymorphic payload
python -m nightstalker.cli payload build --type backdoor --format python --encrypt --obfuscate

# Run red team attack
python -m nightstalker.cli redteam attack --target 192.168.1.100 --stealth-level 9

# Exfiltrate data covertly
python -m nightstalker.cli exfil --data sensitive.txt --channels dns https
```

---

# 📚 Documentation

## 📖 Core Documentation
- **[README.md](README.md)** - Main project documentation (this file)
- **[DIRECTORY_STRUCTURE.md](DIRECTORY_STRUCTURE.md)** - Complete project structure guide
- **[FRAMEWORK_SELECTION_GUIDE.md](FRAMEWORK_SELECTION_GUIDE.md)** - Choose the right framework

## 🌐 Web Exploitation Framework
- **[WEB_EXPLOIT_FRAMEWORK_README.md](WEB_EXPLOIT_FRAMEWORK_README.md)** - Complete web exploitation guide
- **[WEB_RED_TEAMING_GUIDE.md](WEB_RED_TEAMING_GUIDE.md)** - Web red teaming guide
- **[web_exploit_framework_demo.py](web_exploit_framework_demo.py)** - Framework demonstration

## 🦠 Malware & Red Teaming Framework
- **[LINUX_DEPLOYMENT_GUIDE.md](LINUX_DEPLOYMENT_GUIDE.md)** - Linux deployment guide
- **[EXFILTRATION_GUIDE.md](EXFILTRATION_GUIDE.md)** - Data exfiltration guide
- **[COVERT_SERVER_GUIDE.md](COVERT_SERVER_GUIDE.md)** - Covert server setup
- **[TOR_QUICK_SETUP.md](TOR_QUICK_SETUP.md)** - Tor hidden service setup

## 📋 Examples & Demos
- **[demo.py](demo.py)** - Main framework demonstration
- **[build_example.py](build_example.py)** - Payload building examples
- **[build_clean_example.py](build_clean_example.py)** - Clean payload examples
- **[exfil_example.py](exfil_example.py)** - Exfiltration examples
- **[no_server_exfil.py](no_server_exfil.py)** - No-server exfiltration
- **[webred_example.py](webred_example.py)** - Web red teaming examples

## 🧪 Testing & Development
- **[test_framework.py](test_framework.py)** - Framework testing
- **[test_all_modules.py](test_all_modules.py)** - Module testing
- **[test_linux_compatibility.py](test_linux_compatibility.py)** - Linux compatibility testing

---

# 📁 Project Files

## 🔧 Installation & Setup
- **[requirements.txt](requirements.txt)** - Python dependencies
- **[setup.py](setup.py)** - Framework installation script
- **[install.sh](install.sh)** - Linux installation script
- **[install_web_exploit_framework.py](install_web_exploit_framework.py)** - Web framework installer

## 🎨 User Interfaces
- **[gui_exe_builder.py](gui_exe_builder.py)** - GUI payload builder
- **[nightstalker/redteam/web_exploit_tui.py](nightstalker/redteam/web_exploit_tui.py)** - Web exploitation TUI

## ⚙️ Configuration & Data
- **[config/](config/)** - Configuration files directory
  - **[config/example_config.yaml](config/example_config.yaml)** - Example configuration
  - **[config/config_manager.py](config/config_manager.py)** - Configuration manager
- **[payloads/](payloads/)** - Payload templates directory
- **[wordlists/](wordlists/)** - Wordlists and dictionaries
- **[nightstalker_web/config.json](nightstalker_web/config.json)** - Web framework configuration

## 📊 Output & Results
- **[output/](output/)** - Generated output directory
- **[results/](results/)** - Test results and reports
- **[backups/](backups/)** - Backup files
- **[nightstalker_web/loot/](nightstalker_web/loot/)** - Web framework results

## 🔒 Security & Privacy
- **[.gitignore](.gitignore)** - Git ignore rules
- **[LICENSE](LICENSE)** - MIT License
- **[SECURITY.md](SECURITY.md)** - Security policy (future)
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Contributing guidelines (future)

## 🐳 Container & Deployment
- **[Dockerfile](Dockerfile)** - Docker container (future)
- **[docker-compose.yml](docker-compose.yml)** - Docker compose (future)
- **[.dockerignore](.dockerignore)** - Docker ignore rules (future)

## 📝 Development & Maintenance
- **[CHANGELOG.md](CHANGELOG.md)** - Version history (future)
- **[ROADMAP.md](ROADMAP.md)** - Development roadmap (future)
- **[ISSUE_TEMPLATE.md](ISSUE_TEMPLATE.md)** - Issue reporting template (future)
- **[PULL_REQUEST_TEMPLATE.md](PULL_REQUEST_TEMPLATE.md)** - PR template (future)

---

# 🔧 Installation

## System Requirements
- **OS**: Linux (Kali/Ubuntu), macOS, Windows
- **Python**: 3.8 or higher
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 10GB free space

## Dependencies
```bash
# Core dependencies
pip install -r requirements.txt

# Optional: GUI support
pip install tkinter

# Optional: Rich TUI support
pip install rich
```

## Tool Installation
The framework includes automated installers for:
- **Web Tools**: Sn1per, SQLMap, Nuclei, WPScan, Nikto
- **Red Team Tools**: Metasploit, Netcat, Proxychains
- **Development Tools**: Go, Ruby, Docker

---

# 🎯 Use Cases

## NightStalkerWeb (Web Exploitation)
- **Web Application Security Testing**
- **Vulnerability Assessment**
- **Penetration Testing**
- **Security Research**
- **Bug Bounty Hunting**

## NightStalker (Malware/Red Teaming)
- **Red Team Operations**
- **Advanced Persistent Threat Simulation**
- **Malware Research**
- **Security Testing**
- **Incident Response Training**

---

# 🔒 Security & Ethics

## Legal Compliance
- **Authorized Use Only**: Only test systems you own or have explicit permission to test
- **Responsible Disclosure**: Report vulnerabilities through proper channels
- **Data Protection**: Handle sensitive data according to applicable laws
- **Documentation**: Maintain proper records of all testing activities

## Best Practices
- **Scope Definition**: Clearly define testing scope and boundaries
- **Risk Assessment**: Evaluate potential impact before testing
- **Communication**: Keep stakeholders informed of testing activities
- **Cleanup**: Remove all testing artifacts after completion

---

# 🤝 Contributing

## Development Setup
```bash
# Fork and clone
git clone <your-fork>
cd nightstalker

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Submit pull request
```

## Code Standards
- Follow PEP 8 style guidelines
- Add comprehensive documentation
- Include unit tests for new features
- Update relevant documentation

---

# 📞 Support

## Getting Help
- **Documentation**: Check the guides in the docs/ directory
- **Examples**: Review the example scripts
- **Issues**: Report bugs on GitHub Issues
- **Discussions**: Join GitHub Discussions

## Community
- **Discord**: Join our community server
- **Telegram**: Follow for updates
- **Blog**: Read our security blog

---

# ⚠️ Legal Disclaimer

**IMPORTANT**: This framework is designed for authorized security testing and educational purposes only.

## Usage Terms
- **Authorization Required**: Only use on systems you own or have explicit permission to test
- **Educational Purpose**: Use for learning and authorized security assessments
- **No Malicious Use**: Do not use for unauthorized access or malicious activities
- **Compliance**: Follow all applicable laws and regulations

## Liability
The authors and contributors are not responsible for any misuse of this framework. Users are solely responsible for ensuring they have proper authorization before testing any systems.

## Responsible Disclosure
When vulnerabilities are discovered:
1. Document the finding thoroughly
2. Report through proper channels
3. Allow reasonable time for remediation
4. Follow responsible disclosure timelines

---

**Remember**: Always obtain proper authorization before testing any systems, and follow responsible disclosure practices when reporting vulnerabilities.

**Happy Hacking! 🎯** 