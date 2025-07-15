# NightStalker WebXF - Unified Web Exploitation Framework

A comprehensive, production-ready web exploitation framework that combines the advanced capabilities of NightStalker Web and WebXF into a unified platform for ethical security testing and research.

## 🎯 Overview

NightStalker WebXF is a modular, scalable web exploitation framework designed for professional red team operations, penetration testing, and security research. It provides a unified interface for reconnaissance, exploitation, bruteforce, and post-exploitation activities.

## 🌟 Key Features

### 🔍 **Advanced Reconnaissance**
- **Subdomain enumeration** with multiple techniques
- **Port scanning** and service detection
- **Directory enumeration** and content discovery
- **Vulnerability scanning** with template-based detection
- **Network mapping** and topology analysis

### ⚔️ **Comprehensive Exploitation**
- **SQL injection** with SQLMap integration
- **XSS detection** with XSStrike wrapper
- **Template-based scanning** with Nuclei
- **Metasploit integration** for advanced exploitation
- **Custom exploit modules** for specific vulnerabilities

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

## 🏗️ Architecture

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
├── config/               # Configuration files
│   ├── default.yaml      # Default configuration
│   └── templates/        # Tool templates
├── loot/                 # Output and results
├── tools/                # External tool management
├── reports/              # Generated reports
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

### Exploitation Modules
- **SQLMap Wrapper**: Advanced SQL injection exploitation
- **XSStrike Wrapper**: XSS detection and exploitation
- **Nuclei Wrapper**: Template-based vulnerability scanning
- **Metasploit Wrapper**: Advanced exploitation framework
- **Custom Exploits**: Framework-specific exploit modules

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

## 🔧 Configuration

### Main Configuration (`config/default.yaml`)

```yaml
framework:
  name: "NightStalker WebXF"
  version: "2.0.0"
  debug: false
  stealth_mode: true

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

recon:
  subdomain_enumeration:
    enabled: true
    tools: ["subfinder", "amass", "sublist3r"]
    wordlists: ["/usr/share/wordlists/subdomains.txt"]
  
  port_scanning:
    enabled: true
    tools: ["nmap", "masscan"]
    default_ports: [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]

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

bruteforce:
  http_auth:
    enabled: true
    default_wordlists: ["/usr/share/wordlists/rockyou.txt"]
    rate_limit: 10
  
  ssh:
    enabled: true
    default_wordlists: ["/usr/share/wordlists/ssh_users.txt"]
    rate_limit: 5

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
```

## 🎮 Usage Examples

### 1. **Comprehensive Reconnaissance**

```bash
# Full reconnaissance scan
nightstalker-webxf recon --target example.com --all --output-dir results/

# Specific reconnaissance
nightstalker-webxf recon --target example.com --subdomain --port --dir
```

### 2. **Exploitation Operations**

```bash
# SQL injection exploitation
nightstalker-webxf exploit sqlmap --target http://example.com/vuln.php?id=1 --dump

# XSS detection
nightstalker-webxf exploit xsstrike --target http://example.com/search.php

# Nuclei vulnerability scan
nightstalker-webxf exploit nuclei --target http://example.com --severity high,critical

# Metasploit exploitation
nightstalker-webxf exploit msf --target 192.168.1.100 --exploit exploit/multi/handler
```

### 3. **Bruteforce Operations**

```bash
# HTTP authentication bruteforce
nightstalker-webxf bruteforce --target http://example.com/login --wordlist users.txt --type http

# SSH bruteforce
nightstalker-webxf bruteforce --target 192.168.1.100 --wordlist passwords.txt --type ssh
```

### 4. **Tool Management**

```bash
# Install all tools
nightstalker-webxf tools install --all

# Update specific tool
nightstalker-webxf tools update --tool sqlmap

# Check tool status
nightstalker-webxf tools check --all
```

### 5. **Report Generation**

```bash
# Generate HTML report
nightstalker-webxf report --target example.com --format html --output report.html

# Generate JSON report
nightstalker-webxf report --target example.com --format json --output results.json
```

## 🔒 Security Features

### 1. **Stealth Operations**
- **Rate limiting** to avoid detection
- **Random delays** and jitter
- **User-agent rotation**
- **Proxy support** for anonymity
- **Session management** for persistence

### 2. **OPSEC Considerations**
- **Encrypted communications** where possible
- **Log sanitization** and cleanup
- **Configurable verbosity** levels
- **Audit trails** for compliance
- **Secure credential** handling

### 3. **Detection Avoidance**
- **Sandbox detection** and evasion
- **Timing analysis** protection
- **Process monitoring** avoidance
- **Network fingerprinting** prevention

## 📊 Framework Statistics

### Code Quality Metrics
- **Total Lines**: ~8,000+ lines of Python code
- **Modules**: 15+ exploitation modules
- **Tools**: 20+ external tool integrations
- **Documentation**: Comprehensive inline docs
- **Type Hints**: Full type annotation coverage

### Feature Coverage
- **Reconnaissance**: 5+ reconnaissance techniques
- **Exploitation**: 10+ exploitation methods
- **Bruteforce**: 4+ protocol support
- **Post-Exploitation**: 5+ post-exploitation capabilities
- **Reporting**: 3+ output formats

## 🎯 Production Readiness

### 1. **Code Quality**
- **PEP8 compliance** throughout
- **Type hints** for all functions
- **Comprehensive error handling**
- **Logging and monitoring**
- **Documentation coverage**

### 2. **Security**
- **Input validation** and sanitization
- **Secure subprocess** usage
- **Encrypted communications**
- **Anti-detection** capabilities
- **Resource cleanup**

### 3. **Maintainability**
- **Modular architecture**
- **Configuration management**
- **Extensible design**
- **Clear documentation**
- **Testing framework** ready

### 4. **Deployment**
- **Automated installation**
- **Dependency management**
- **Cross-platform** support
- **Launcher scripts**
- **Virtual environments**

## 🔮 Future Enhancements

### Planned Features
1. **Web UI** for management
2. **API endpoints** for automation
3. **Database backend** for results
4. **Machine learning** for vulnerability detection
5. **Advanced obfuscation** techniques
6. **Docker support** for deployment
7. **Cloud integration** (AWS, Azure, GCP)
8. **Mobile app** for monitoring

### Technical Improvements
1. **Async/await** support
2. **WebSocket** communications
3. **GraphQL API** for data access
4. **Advanced persistence** mechanisms
5. **Memory-only** execution
6. **Process injection** capabilities
7. **Network protocol** analysis
8. **Real-time collaboration**

## 📝 Legal Notice

**⚠️ IMPORTANT: This framework is designed STRICTLY for:**
- Authorized security testing and research
- Educational purposes
- Ethical red teaming with proper authorization
- Security simulation and training

**Users are responsible for ensuring they have proper authorization before using this tool against any target. The authors are not responsible for any misuse of this software.**

## 🆘 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/your-repo/nightstalker-webxf/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/nightstalker-webxf/discussions)
- **Wiki**: [GitHub Wiki](https://github.com/your-repo/nightstalker-webxf/wiki)

---

**NightStalker WebXF** - Unified Web Exploitation Framework  
*Professional • Modular • Stealthy* 