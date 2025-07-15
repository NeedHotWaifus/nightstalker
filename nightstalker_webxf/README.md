# NightStalker WebXF - Unified Web Exploitation Framework

A comprehensive, production-ready web exploitation framework that integrates seamlessly with the NightStalker Advanced Offensive Security Framework, providing unified capabilities for ethical security testing, red team operations, and advanced exploitation research.

## 🎯 Overview

NightStalker WebXF is a modular, scalable web exploitation framework designed for professional red team operations, penetration testing, and security research. It provides a unified interface for reconnaissance, exploitation, bruteforce, and post-exploitation activities, now enhanced with advanced exploitation capabilities and sophisticated attack chains.

## 🌟 Enhanced Features

### 🔍 **Advanced Reconnaissance**
- **Subdomain enumeration** with multiple techniques
- **Port scanning** and service detection
- **Directory enumeration** and content discovery
- **Vulnerability scanning** with template-based detection
- **Network mapping** and topology analysis
- **Automated reconnaissance** with comprehensive reporting

### ⚔️ **Comprehensive Exploitation**
- **SQL injection** with SQLMap integration
- **XSS detection** with XSStrike wrapper
- **Template-based scanning** with Nuclei
- **Metasploit integration** for advanced exploitation
- **Custom exploit modules** for specific vulnerabilities
- **Advanced exploitation chains** with multi-phase attacks

### 🔐 **Bruteforce Capabilities**
- **HTTP authentication** bruteforce
- **SSH/FTP/SMTP** service bruteforce
- **Custom wordlist** support
- **Rate limiting** and stealth options
- **Session management** and persistence

### 🛠️ **Post-Exploitation**
- **Session management** and persistence
- **Lateral movement** capabilities
- **Data exfiltration** tools
- **Cleanup** and trace removal
- **Report generation** and analysis

### 🏗️ **Production Architecture**
- **Modular design** with plugin support
- **Configuration management** with YAML
- **Comprehensive logging** and monitoring
- **Error handling** and recovery
- **Cross-platform** compatibility
- **Tool management** with automatic dependency resolution

### 🆕 **New Advanced Features**
- **Attack Chains**: Multi-phase attack sequences (web_to_system, network_to_domain)
- **Advanced Exploitation**: Sophisticated exploitation with configurable parameters
- **Professional Reporting**: HTML and JSON reports with detailed analysis
- **Stealth Operations**: Advanced stealth and evasion capabilities
- **Tool Integration**: Universal tool manager with automatic installation

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd nightstalker_webxf

# Run the installer
sudo ./install.sh

# Or install manually
pip install -r requirements.txt
```

### Integration with Main Framework

```bash
# Use through main NightStalker framework
./nightstalker.sh webred scan --url https://example.com

# Advanced exploitation
./nightstalker.sh redteam exploit --target example.com --type web --chain web_to_system

# Comprehensive reconnaissance
./nightstalker.sh redteam exploit --target example.com --type web
```

### Basic Usage

```bash
# Run with interactive menu
nightstalker-webxf

# Reconnaissance
nightstalker-webxf recon --target example.com --all

# Exploitation
nightstalker-webxf exploit sqlmap --target http://example.com/vuln.php?id=1

# Bruteforce
nightstalker-webxf bruteforce --target http://example.com/login --wordlist wordlist.txt

# Comprehensive scan
nightstalker-webxf exploit all --target http://example.com --automated
```

## 🏗️ Enhanced Architecture

```
nightstalker_webxf/
├── core/                   # Core framework components
│   ├── config.py          # Configuration management
│   ├── logging.py         # Logging system
│   ├── base_tool.py       # Base tool wrapper
│   └── utils.py           # Utility functions
├── modules/               # Exploitation modules
│   ├── recon/            # Reconnaissance tools
│   ├── exploit/          # Exploitation tools
│   ├── bruteforce/       # Bruteforce tools
│   └── post/             # Post-exploitation tools
├── cli/                  # Command-line interface
│   ├── main.py           # Main CLI entry point
│   └── tui.py            # Text-based UI
├── c2/                   # Command & Control
│   ├── stealth_c2.py     # Stealth C2 server
│   └── stealth_client.py # Stealth C2 client
├── payloads/             # Payload generation
│   ├── payload_builder.py # Advanced payload builder
│   ├── shellcode_generator.py # Shellcode generation
│   └── stealth_reverse_shell.py # Stealth payloads
├── config/               # Configuration files
│   ├── default.yaml      # Default configuration
│   └── templates/        # Tool templates
├── loot/                 # Output and results
├── tools/                # External tool management
├── reports/              # Generated reports
├── utils/                # Utilities
│   ├── config.py         # Configuration utilities
│   ├── crypto.py         # Cryptographic functions
│   └── logger.py         # Logging utilities
├── main.py              # Main entry point
├── requirements.txt     # Dependencies
└── install.sh           # Installation script
```

## 📦 Available Modules

### Reconnaissance Modules
- **Subdomain Enumeration**: DNS, certificate transparency, search engines
- **Port Scanning**: TCP/UDP scanning with service detection
- **Directory Enumeration**: Web content discovery
- **Vulnerability Scanning**: Template-based and custom scans
- **Network Mapping**: Topology and service analysis
- **Advanced Reconnaissance**: Comprehensive target enumeration

### Exploitation Modules
- **SQLMap Wrapper**: Advanced SQL injection exploitation
- **XSStrike Wrapper**: XSS detection and exploitation
- **Nuclei Wrapper**: Template-based vulnerability scanning
- **Metasploit Wrapper**: Advanced exploitation framework
- **Custom Exploits**: Framework-specific exploit modules
- **Advanced Exploitation**: Multi-phase attack chains

### Bruteforce Modules
- **HTTP Authentication**: Form-based and basic auth
- **SSH Bruteforce**: SSH service authentication
- **FTP Bruteforce**: FTP service authentication
- **SMTP Bruteforce**: Email service authentication
- **Custom Protocols**: Extensible bruteforce framework

### Post-Exploitation Modules
- **Session Management**: Persistent access maintenance
- **Lateral Movement**: Network traversal capabilities
- **Data Exfiltration**: Secure data extraction
- **Persistence**: Long-term access establishment
- **Cleanup**: Trace removal and sanitization

### 🆕 Advanced Modules
- **Attack Chains**: Multi-phase attack sequences
- **Stealth Operations**: Advanced stealth and evasion
- **Professional Reporting**: Comprehensive report generation
- **Tool Management**: Universal tool manager

## 🔧 Enhanced Configuration

### Main Configuration (`config/default.yaml`)

```yaml
framework:
  name: "NightStalker WebXF"
  version: "2.1.0"
  debug: false
  stealth_mode: true
  advanced_exploitation: true

tools:
  sqlmap:
    path: "/usr/local/bin/sqlmap"
    timeout: 300
    threads: 10
  
  nuclei:
    path: "/usr/local/bin/nuclei"
    templates_path: "~/.local/share/nuclei/templates"
    timeout: 300
  
  xsstrike:
    path: "/usr/local/bin/xsstrike"
    timeout: 300

  # New advanced tools
  nmap:
    path: "/usr/bin/nmap"
    timeout: 600
  
  ffuf:
    path: "/usr/local/bin/ffuf"
    timeout: 300

recon:
  subdomain_enumeration:
    enabled: true
    tools: ["subfinder", "amass", "sublist3r"]
    wordlists: ["/usr/share/wordlists/subdomains.txt"]
  
  port_scanning:
    enabled: true
    tools: ["nmap", "masscan"]
    default_ports: [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
  
  # New advanced reconnaissance
  advanced_recon:
    enabled: true
    comprehensive_scan: true
    vulnerability_assessment: true
    web_application_discovery: true

exploitation:
  sql_injection:
    enabled: true
    risk_level: 1
    threads: 10
  
  xss_detection:
    enabled: true
    payloads_file: "config/payloads/xss.txt"
  
  vulnerability_scanning:
    enabled: true
    severity_levels: ["low", "medium", "high", "critical"]
  
  # New advanced exploitation
  advanced_exploitation:
    enabled: true
    attack_chains: ["web_to_system", "network_to_domain"]
    stealth_level: 8
    persistence: true
    cleanup: true

bruteforce:
  http_auth:
    enabled: true
    default_wordlists: ["/usr/share/wordlists/rockyou.txt"]
    rate_limit: 10
  
  ssh:
    enabled: true
    default_wordlists: ["/usr/share/wordlists/ssh_users.txt"]
    rate_limit: 5

# New advanced features
advanced_features:
  tool_management:
    auto_install: true
    cross_platform: true
    dependency_resolution: true
  
  reporting:
    html_reports: true
    json_export: true
    evidence_collection: true
  
  stealth:
    anti_detection: true
    obfuscation: true
    encryption: true

logging:
  level: "INFO"
  file: "logs/framework.log"
  max_size: "10MB"
  backup_count: 5
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

output:
  directory: "loot"
  format: "json"
  include_screenshots: true
  include_logs: true
  reports_directory: "reports"
```

## 🎮 Enhanced Usage Examples

### 1. **Advanced Reconnaissance**

```bash
# Full reconnaissance scan with advanced features
nightstalker-webxf recon --target example.com --all --advanced --output-dir results/

# Comprehensive reconnaissance through main framework
./nightstalker.sh redteam exploit --target example.com --type web

# Specific reconnaissance
nightstalker-webxf recon --target example.com --subdomain --port --dir --vuln
```

### 2. **Advanced Exploitation Operations**

```bash
# SQL injection exploitation
nightstalker-webxf exploit sqlmap --target http://example.com/vuln.php?id=1 --dump

# XSS detection
nightstalker-webxf exploit xsstrike --target http://example.com/search.php

# Nuclei vulnerability scan
nightstalker-webxf exploit nuclei --target http://example.com --severity high,critical

# Metasploit exploitation
nightstalker-webxf exploit msf --target 192.168.1.100 --exploit exploit/multi/handler

# Advanced exploitation through main framework
./nightstalker.sh redteam exploit --target example.com --type web --chain web_to_system
```

### 3. **Attack Chains**

```bash
# Web to system attack chain
./nightstalker.sh redteam exploit --target example.com --type web --chain web_to_system

# Network to domain attack chain
./nightstalker.sh redteam exploit --target 192.168.1.100 --type network --chain network_to_domain
```

### 4. **Bruteforce Operations**

```bash
# HTTP authentication bruteforce
nightstalker-webxf bruteforce --target http://example.com/login --wordlist users.txt --type http

# SSH bruteforce
nightstalker-webxf bruteforce --target 192.168.1.100 --wordlist passwords.txt --type ssh
```

### 5. **Professional Reporting**

```bash
# Generate HTML report
nightstalker-webxf report --target example.com --format html --output report.html

# Generate JSON report
nightstalker-webxf report --target example.com --format json --output report.json

# Comprehensive report through main framework
./nightstalker.sh redteam exploit --target example.com --type web --output report.html
```

## 🔒 Security & Ethics

**IMPORTANT**: This framework is designed for authorized security testing and educational purposes only.

- **Authorization Required**: Only test systems you own or have explicit permission to test
- **Educational Purpose**: Use for learning and authorized security assessments
- **No Malicious Use**: Do not use for unauthorized access or malicious activities
- **Compliance**: Follow all applicable laws and regulations
- **Responsible Disclosure**: Follow proper vulnerability disclosure procedures

## 📞 Support & Documentation

- **Main Documentation**: Check the main NightStalker documentation
- **Enhancement Summary**: Review `NIGHTSTALKER_ENHANCEMENT_SUMMARY.md`
- **Examples**: Review the example scripts in `examples/`
- **Testing**: Run tests in the `tests/` directory
- **Issues**: Report bugs on GitHub Issues

## 🚀 Integration with Main Framework

NightStalker WebXF is now fully integrated with the main NightStalker framework, providing:

- **Unified Interface**: Access through main NightStalker CLI
- **Advanced Capabilities**: Enhanced exploitation and reconnaissance
- **Professional Features**: Production-ready tooling and reporting
- **Cross-Platform**: Full Windows, Linux, and macOS support

---

**Remember**: Always obtain proper authorization before testing any systems, and follow responsible disclosure practices when reporting vulnerabilities.

**Happy Hacking! 🎯** 