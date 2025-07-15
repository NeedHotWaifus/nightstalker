# 📁 NightStalker Directory Structure

This document provides a comprehensive overview of the NightStalker framework's directory structure, clearly separating the **Web Exploitation Framework** (NightStalkerWeb) from the **Malware & Red Teaming Framework** (NightStalker).

---

# 🌐 NightStalkerWeb - Web Exploitation Framework

**Location**: `nightstalker_web/` (Root level)

## 📋 Overview
The web exploitation framework is a specialized system for web penetration testing, vulnerability assessment, and web application security testing.

## 🗂️ Directory Structure

```
nightstalker_web/
├── 📁 modules/                    # Modular framework components
│   ├── 📁 recon/                 # Reconnaissance modules
│   │   ├── 📄 sn1per_wrapper.py  # Sn1per integration
│   │   ├── 📄 nuclei_wrapper.py  # Nuclei integration (future)
│   │   ├── 📄 nikto_wrapper.py   # Nikto integration (future)
│   │   └── 📄 README.md          # Module documentation
│   ├── 📁 exploit/               # Exploitation modules
│   │   ├── 📄 sqlmap_wrapper.py  # SQLMap integration (future)
│   │   ├── 📄 msf_wrapper.py     # Metasploit integration (future)
│   │   └── 📄 README.md          # Module documentation
│   ├── 📁 bruteforce/            # Bruteforce modules
│   │   ├── 📄 openbullet_wrapper.py # OpenBullet integration (future)
│   │   ├── 📄 hydra_wrapper.py   # Hydra integration (future)
│   │   └── 📄 README.md          # Module documentation
│   ├── 📁 post/                  # Post-exploitation modules
│   │   ├── 📄 persistence.py     # Persistence mechanisms
│   │   ├── 📄 privilege_escalation.py # Privilege escalation
│   │   └── 📄 README.md          # Module documentation
│   └── 📁 auxiliary/             # Auxiliary tools
│       ├── 📄 proxy_setup.py     # Proxy configuration
│       ├── 📄 tunnel_setup.py    # Tunnel configuration
│       └── 📄 README.md          # Module documentation
├── 📁 tools/                     # Installed security tools
│   ├── 📁 sn1per/               # Sn1per tool (cloned from GitHub)
│   │   ├── 📄 sn1per            # Main Sn1per executable
│   │   ├── 📄 install.sh        # Sn1per installer
│   │   └── 📄 README.md         # Tool documentation
│   ├── 📁 sqlmap/               # SQLMap tool (future)
│   ├── 📁 nuclei/               # Nuclei tool (future)
│   ├── 📁 wpscan/               # WPScan tool (future)
│   └── 📄 README.md             # Tools documentation
├── 📁 loot/                      # Target-specific results
│   ├── 📁 target1.com/          # Results for target1.com
│   │   ├── 📁 recon/            # Reconnaissance results
│   │   │   ├── 📁 sn1per/       # Sn1per output
│   │   │   ├── 📁 nuclei/       # Nuclei output
│   │   │   └── 📄 scan_results.json
│   │   ├── 📁 exploit/          # Exploitation results
│   │   ├── 📁 bruteforce/       # Bruteforce results
│   │   ├── 📁 post/             # Post-exploitation results
│   │   ├── 📁 screenshots/      # Screenshots and evidence
│   │   └── 📁 logs/             # Log files
│   └── 📁 target2.com/          # Results for target2.com
├── 📁 bin/                       # Wrapper scripts
│   ├── 📄 web-exploit           # Main framework launcher
│   ├── 📄 nightstalker          # NightStalker CLI wrapper
│   ├── 📄 setup-proxy           # Proxy setup script
│   └── 📄 setup-tunnel          # Tunnel setup script
├── 📄 config.json               # Framework configuration
├── 📄 install.log               # Installation log
├── 📄 install_status.json       # Installation status
└── 📄 framework.log             # Framework operation log
```

## 🔧 Key Components

### Modules Directory
- **recon/**: Information gathering and enumeration tools
- **exploit/**: Vulnerability exploitation tools
- **bruteforce/**: Password and credential testing tools
- **post/**: Post-exploitation and persistence tools
- **auxiliary/**: Supporting utilities and configurations

### Tools Directory
- Contains cloned and installed security tools
- Each tool has its own subdirectory with documentation
- Tools are automatically managed by the framework

### Loot Directory
- Organized by target domain/IP
- Each target has subdirectories for different phases
- Results are automatically categorized and stored

---

# 🦠 NightStalker - Malware & Red Teaming Framework

**Location**: `nightstalker/` (Root level)

## 📋 Overview
The core NightStalker framework provides advanced malware development, red teaming capabilities, and offensive security features.

## 🗂️ Directory Structure

```
nightstalker/
├── 📁 redteam/                   # Red teaming modules
│   ├── 📁 c2/                   # Command & Control
│   │   ├── 📄 __init__.py
│   │   ├── 📄 command_control.py # C2 server implementation
│   │   ├── 📄 channels.py        # Communication channels
│   │   └── 📄 stealth.py         # Stealth techniques
│   ├── 📄 __init__.py
│   ├── 📄 webred.py             # Web red teaming integration
│   ├── 📄 web_exploit_framework.py # Web exploitation framework
│   ├── 📄 web_exploit_tui.py    # Web exploitation TUI
│   ├── 📄 exfiltration.py       # Data exfiltration
│   ├── 📄 fuzzer.py             # Genetic fuzzing
│   ├── 📄 infection_watchers.py # File monitoring
│   ├── 📄 self_rebuild.py       # Environment reconstruction
│   ├── 📄 payload_builder.py    # Payload creation
│   └── 📄 polymorph.py          # Polymorphic engine
├── 📁 pentest/                   # Penetration testing
│   ├── 📄 __init__.py
│   └── 📄 (future modules)
├── 📁 core/                      # Core framework
│   ├── 📄 __init__.py
│   └── 📄 automation.py         # Attack automation
├── 📁 builder/                   # Payload building
│   ├── 📄 __init__.py
│   └── 📄 (future modules)
├── 📄 __init__.py               # Package initialization
└── 📄 cli.py                    # Command-line interface
```

## 🔧 Key Components

### Red Team Modules
- **c2/**: Command and control infrastructure
- **webred.py**: Web red teaming capabilities
- **exfiltration.py**: Covert data exfiltration
- **fuzzer.py**: Genetic fuzzing engine
- **infection_watchers.py**: File system monitoring
- **self_rebuild.py**: Environment persistence

### Core Framework
- **automation.py**: Attack chain automation
- **cli.py**: Unified command-line interface

---

# 📁 Root Level Files

## 🌐 NightStalkerWeb Files
```
📄 install_web_exploit_framework.py  # Web framework installer
📄 web_exploit_framework_demo.py     # Web framework demo
📄 WEB_EXPLOIT_FRAMEWORK_README.md   # Web framework documentation
📄 WEB_RED_TEAMING_GUIDE.md          # Web red teaming guide
📄 webred_example.py                 # Web red teaming examples
```

## 🦠 NightStalker Files
```
📄 demo.py                           # Main framework demo
📄 build_example.py                  # Payload building examples
📄 build_clean_example.py            # Clean payload examples
📄 exfil_example.py                  # Exfiltration examples
📄 no_server_exfil.py                # No-server exfiltration
📄 test_framework.py                 # Framework testing
📄 test_all_modules.py               # Module testing
📄 test_linux_compatibility.py       # Linux compatibility testing
📄 gui_exe_builder.py                # GUI payload builder
```

## 📚 Documentation
```
📄 README.md                         # Main project documentation
📄 DIRECTORY_STRUCTURE.md            # This file
📄 LINUX_DEPLOYMENT_GUIDE.md         # Linux deployment guide
📄 EXFILTRATION_GUIDE.md             # Exfiltration guide
📄 COVERT_SERVER_GUIDE.md            # Covert server guide
📄 TOR_QUICK_SETUP.md                # Tor setup guide
```

## ⚙️ Configuration & Setup
```
📄 requirements.txt                  # Python dependencies
📄 setup.py                         # Framework setup
📄 install.sh                        # Linux installer
📄 LICENSE                           # MIT License
📄 .gitignore                        # Git ignore rules
```

## 📁 Supporting Directories
```
📁 config/                           # Configuration files
📁 payloads/                         # Payload templates
📁 output/                           # Output directory
📁 results/                          # Results directory
📁 backups/                          # Backup files
📁 wordlists/                        # Wordlists
📁 .venv/                            # Virtual environment
```

---

# 🔄 Integration Points

## Web Exploitation → Red Teaming
- **webred.py**: Integrates web exploitation with red teaming
- **web_exploit_framework.py**: Provides web capabilities to red teaming
- **Shared CLI**: Unified command-line interface

## Red Teaming → Web Exploitation
- **Payload Builder**: Can create web-specific payloads
- **Exfiltration**: Web-based exfiltration channels
- **C2**: Web-based command and control

## Shared Components
- **Configuration**: Shared configuration management
- **Logging**: Unified logging system
- **Reporting**: Integrated reporting capabilities

---

# 🚀 Usage Patterns

## Web Exploitation Workflow
1. **Setup**: `python install_web_exploit_framework.py`
2. **Launch**: `python -m nightstalker.redteam.web_exploit_tui`
3. **Scan**: Use TUI or CLI for reconnaissance
4. **Exploit**: Run exploitation modules
5. **Report**: Generate comprehensive reports

## Red Teaming Workflow
1. **Setup**: `pip install -r requirements.txt`
2. **Build**: `python -m nightstalker.cli payload build`
3. **Deploy**: `python -m nightstalker.cli redteam attack`
4. **Exfiltrate**: `python -m nightstalker.cli exfil`
5. **Cleanup**: `python -m nightstalker.cli env --cleanup`

## Integrated Workflow
1. **Web Recon**: Use NightStalkerWeb for initial reconnaissance
2. **Red Team**: Use NightStalker for advanced exploitation
3. **Combined**: Use both frameworks together for comprehensive assessment

---

# 📝 File Naming Conventions

## NightStalkerWeb Files
- **Modules**: `*_wrapper.py` for tool wrappers
- **Scripts**: `web_*` prefix for web-specific scripts
- **Documentation**: `WEB_*` prefix for web documentation

## NightStalker Files
- **Core**: Descriptive names without prefixes
- **Examples**: `*_example.py` for example scripts
- **Tests**: `test_*` prefix for test files

## Shared Files
- **Documentation**: Descriptive names with clear purpose
- **Configuration**: Standard configuration file names
- **Installers**: `install_*` prefix for installers

---

# 🔧 Maintenance

## Adding New Tools
1. **Clone**: Add tool to `nightstalker_web/tools/`
2. **Wrapper**: Create wrapper in appropriate module directory
3. **Integration**: Update framework integration
4. **Documentation**: Update relevant documentation

## Adding New Modules
1. **Directory**: Create new module directory
2. **Scripts**: Add module-specific scripts
3. **Integration**: Update framework to recognize module
4. **Documentation**: Add module documentation

## Updating Framework
1. **Core**: Update core framework files
2. **Integration**: Update integration points
3. **Documentation**: Update all relevant documentation
4. **Testing**: Test all affected components

---

This directory structure provides a clear separation between web exploitation and red teaming capabilities while maintaining integration points for comprehensive security assessments. 