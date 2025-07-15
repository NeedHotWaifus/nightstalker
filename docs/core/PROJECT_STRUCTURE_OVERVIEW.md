# 🌙 NightStalker Project Structure Overview

This document provides a complete visual overview of the NightStalker project structure, showing all files and directories organized by category and purpose.

---

# 📁 Complete Project Tree

```
🌙 nightstalker/
├── 📚 DOCUMENTATION
│   ├── 📖 Core Documentation
│   │   ├── 📄 README.md                           # Main project documentation
│   │   ├── 📄 DIRECTORY_STRUCTURE.md              # Complete directory structure
│   │   ├── 📄 FRAMEWORK_SELECTION_GUIDE.md        # Choose the right framework
│   │   ├── 📄 FILE_ORGANIZATION_GUIDE.md          # File organization guide
│   │   └── 📄 PROJECT_STRUCTURE_OVERVIEW.md       # This file
│   │
│   ├── 🌐 Web Exploitation Documentation
│   │   ├── 📄 WEB_EXPLOIT_FRAMEWORK_README.md     # Web framework guide
│   │   ├── 📄 WEB_RED_TEAMING_GUIDE.md            # Web red teaming guide
│   │   └── 📄 web_exploit_framework_demo.py       # Web framework demo
│   │
│   └── 🦠 Red Teaming Documentation
│       ├── 📄 LINUX_DEPLOYMENT_GUIDE.md           # Linux deployment guide
│       ├── 📄 EXFILTRATION_GUIDE.md               # Exfiltration guide
│       ├── 📄 COVERT_SERVER_GUIDE.md              # Covert server guide
│       └── 📄 TOR_QUICK_SETUP.md                  # Tor setup guide
│
├── 🔧 INSTALLATION & SETUP
│   ├── 📦 Core Installation
│   │   ├── 📄 requirements.txt                    # Python dependencies
│   │   ├── 📄 setup.py                           # Framework installation
│   │   ├── 📄 install.sh                         # Linux installation script
│   │   └── 📄 install_web_exploit_framework.py   # Web framework installer
│   │
│   └── 🐳 Container & Deployment (Future)
│       ├── 📄 Dockerfile                         # Docker container
│       ├── 📄 docker-compose.yml                 # Multi-container setup
│       └── 📄 .dockerignore                      # Docker ignore rules
│
├── 🎨 USER INTERFACES
│   ├── 🖥️ Graphical Interfaces
│   │   ├── 📄 gui_exe_builder.py                 # GUI payload builder
│   │   └── 📄 nightstalker/redteam/web_exploit_tui.py # Web exploitation TUI
│   │
│   └── 💻 Command Line Interfaces
│       ├── 📄 nightstalker/cli.py                # Main CLI interface
│       └── 📄 nightstalker_web/bin/web-exploit   # Web framework launcher
│
├── ⚙️ CONFIGURATION & DATA
│   ├── 🔧 Framework Configuration
│   │   ├── 📁 config/                            # Configuration directory
│   │   │   ├── 📄 example_config.yaml            # Example configuration
│   │   │   └── 📄 config_manager.py              # Configuration manager
│   │   ├── 📄 nightstalker_web/config.json       # Web framework config
│   │   └── 📄 nightstalker_web/install_status.json # Installation status
│   │
│   ├── 📋 Templates & Data
│   │   ├── 📁 payloads/                          # Payload templates
│   │   └── 📁 wordlists/                         # Wordlists and dictionaries
│   │
│   └── 📄 Log Files
│       ├── 📄 nightstalker_web/install.log       # Installation log
│       └── 📄 nightstalker_web/framework.log     # Framework operations log
│
├── 📊 OUTPUT & RESULTS
│   ├── 📁 output/                                # Generated output
│   ├── 📁 results/                               # Test results
│   ├── 📁 backups/                               # Backup files
│   └── 📁 nightstalker_web/loot/                 # Web framework results
│
├── 🧪 TESTING & DEVELOPMENT
│   ├── 🧪 Test Scripts
│   │   ├── 📄 test_framework.py                  # Framework testing
│   │   ├── 📄 test_all_modules.py                # Module testing
│   │   └── 📄 test_linux_compatibility.py        # Linux compatibility testing
│   │
│   └── 📋 Example Scripts
│       ├── 📄 demo.py                            # Main framework demo
│       ├── 📄 build_example.py                   # Payload building examples
│       ├── 📄 build_clean_example.py             # Clean payload examples
│       ├── 📄 exfil_example.py                   # Exfiltration examples
│       ├── 📄 no_server_exfil.py                 # No-server exfiltration
│       └── 📄 webred_example.py                  # Web red teaming examples
│
├── 🔒 SECURITY & LEGAL
│   ├── 📜 Legal Documentation
│   │   ├── 📄 LICENSE                            # MIT License
│   │   ├── 📄 SECURITY.md                        # Security policy (future)
│   │   └── 📄 CONTRIBUTING.md                    # Contributing guidelines (future)
│   │
│   └── 🔐 Security Configuration
│       ├── 📄 .gitignore                         # Git ignore rules
│       └── 📄 .dockerignore                      # Docker ignore rules (future)
│
├── 📝 DEVELOPMENT & MAINTENANCE (Future)
│   ├── 🔄 Version Control
│   │   ├── 📄 CHANGELOG.md                       # Version history
│   │   └── 📄 ROADMAP.md                         # Development roadmap
│   │
│   └── 🐛 Issue Management
│       ├── 📄 ISSUE_TEMPLATE.md                  # Issue reporting template
│       └── 📄 PULL_REQUEST_TEMPLATE.md           # PR template
│
├── 🌐 NIGHTSTALKERWEB FRAMEWORK
│   ├── 📁 modules/                               # Modular components
│   │   ├── 📁 recon/                             # Reconnaissance modules
│   │   │   ├── 📄 sn1per_wrapper.py              # Sn1per integration
│   │   │   ├── 📄 nuclei_wrapper.py              # Nuclei integration (future)
│   │   │   ├── 📄 nikto_wrapper.py               # Nikto integration (future)
│   │   │   └── 📄 README.md                      # Module documentation
│   │   ├── 📁 exploit/                           # Exploitation modules
│   │   │   ├── 📄 sqlmap_wrapper.py              # SQLMap integration (future)
│   │   │   ├── 📄 msf_wrapper.py                 # Metasploit integration (future)
│   │   │   └── 📄 README.md                      # Module documentation
│   │   ├── 📁 bruteforce/                        # Bruteforce modules
│   │   │   ├── 📄 openbullet_wrapper.py          # OpenBullet integration (future)
│   │   │   ├── 📄 hydra_wrapper.py               # Hydra integration (future)
│   │   │   └── 📄 README.md                      # Module documentation
│   │   ├── 📁 post/                              # Post-exploitation modules
│   │   │   ├── 📄 persistence.py                 # Persistence mechanisms
│   │   │   ├── 📄 privilege_escalation.py        # Privilege escalation
│   │   │   └── 📄 README.md                      # Module documentation
│   │   └── 📁 auxiliary/                         # Auxiliary tools
│   │       ├── 📄 proxy_setup.py                 # Proxy configuration
│   │       ├── 📄 tunnel_setup.py                # Tunnel configuration
│   │       └── 📄 README.md                      # Module documentation
│   │
│   ├── 📁 tools/                                 # Installed security tools
│   │   ├── 📁 sn1per/                            # Sn1per tool
│   │   │   ├── 📄 sn1per                         # Main Sn1per executable
│   │   │   ├── 📄 install.sh                     # Sn1per installer
│   │   │   └── 📄 README.md                      # Tool documentation
│   │   ├── 📁 sqlmap/                            # SQLMap tool (future)
│   │   ├── 📁 nuclei/                            # Nuclei tool (future)
│   │   ├── 📁 wpscan/                            # WPScan tool (future)
│   │   └── 📄 README.md                          # Tools documentation
│   │
│   ├── 📁 loot/                                  # Target-specific results
│   │   ├── 📁 target1.com/                       # Results for target1.com
│   │   │   ├── 📁 recon/                         # Reconnaissance results
│   │   │   │   ├── 📁 sn1per/                    # Sn1per output
│   │   │   │   ├── 📁 nuclei/                    # Nuclei output
│   │   │   │   └── 📄 scan_results.json          # Scan results
│   │   │   ├── 📁 exploit/                       # Exploitation results
│   │   │   ├── 📁 bruteforce/                    # Bruteforce results
│   │   │   ├── 📁 post/                          # Post-exploitation results
│   │   │   ├── 📁 screenshots/                   # Screenshots and evidence
│   │   │   └── 📁 logs/                          # Log files
│   │   └── 📁 target2.com/                       # Results for target2.com
│   │
│   └── 📁 bin/                                   # Wrapper scripts
│       ├── 📄 web-exploit                        # Main framework launcher
│       ├── 📄 nightstalker                       # NightStalker CLI wrapper
│       ├── 📄 setup-proxy                        # Proxy setup script
│       └── 📄 setup-tunnel                       # Tunnel setup script
│
└── 🦠 NIGHTSTALKER FRAMEWORK
    ├── 📁 redteam/                               # Red teaming modules
    │   ├── 📁 c2/                                # Command & Control
    │   │   ├── 📄 __init__.py                    # Package initialization
    │   │   ├── 📄 command_control.py             # C2 server implementation
    │   │   ├── 📄 channels.py                    # Communication channels
    │   │   └── 📄 stealth.py                     # Stealth techniques
    │   ├── 📄 __init__.py                        # Package initialization
    │   ├── 📄 webred.py                          # Web red teaming integration
    │   ├── 📄 web_exploit_framework.py           # Web exploitation framework
    │   ├── 📄 web_exploit_tui.py                 # Web exploitation TUI
    │   ├── 📄 exfiltration.py                    # Data exfiltration
    │   ├── 📄 fuzzer.py                          # Genetic fuzzing
    │   ├── 📄 infection_watchers.py              # File monitoring
    │   ├── 📄 self_rebuild.py                    # Environment reconstruction
    │   ├── 📄 payload_builder.py                 # Payload creation
    │   └── 📄 polymorph.py                       # Polymorphic engine
    │
    ├── 📁 pentest/                               # Penetration testing
    │   └── 📄 __init__.py                        # Package initialization
    │
    ├── 📁 core/                                  # Core framework
    │   ├── 📄 __init__.py                        # Package initialization
    │   └── 📄 automation.py                      # Attack automation
    │
    ├── 📁 builder/                               # Payload building
    │   └── 📄 __init__.py                        # Package initialization
    │
    ├── 📄 __init__.py                            # Package initialization
    └── 📄 cli.py                                 # Command-line interface
```

---

# 📊 File Statistics

## 📁 Directory Count
- **Total Directories**: 25+
- **Documentation**: 3 directories
- **Framework Code**: 2 main frameworks
- **Configuration**: 3 directories
- **Output**: 4 directories
- **Testing**: 2 directories

## 📄 File Count
- **Total Files**: 80+
- **Documentation**: 15+ markdown files
- **Python Scripts**: 40+ files
- **Configuration**: 10+ files
- **Templates**: 5+ files
- **Examples**: 8+ files

## 🎯 File Types
- **Markdown (.md)**: Documentation and guides
- **Python (.py)**: Source code and scripts
- **YAML (.yaml)**: Configuration files
- **JSON (.json)**: Data and status files
- **Shell (.sh)**: Installation scripts
- **Text (.txt)**: Requirements and wordlists

---

# 🔄 Framework Integration

## 🌐 NightStalkerWeb → NightStalker
```
Web Reconnaissance → Red Team Exploitation
├── Sn1per Results → Payload Targeting
├── Vulnerability Data → Exploit Selection
├── Web Infrastructure → Network Mapping
└── Tool Output → C2 Integration
```

## 🦠 NightStalker → NightStalkerWeb
```
Red Team Intelligence → Web Assessment
├── Network Discovery → Web Service Enumeration
├── Credential Harvesting → Web Authentication Testing
├── Lateral Movement → Web Application Access
└── Persistence → Web-Based Backdoors
```

---

# 📋 File Categories Summary

## 🎯 User-Facing Files (25%)
- **Documentation**: Guides, README, examples
- **User Interfaces**: GUI, TUI, CLI
- **Configuration**: Settings, templates
- **Installation**: Setup scripts

## 🔧 Development Files (40%)
- **Source Code**: Python modules, packages
- **Testing**: Test scripts, examples
- **Build**: Setup, requirements
- **Version Control**: Git files

## 📊 Data Files (20%)
- **Output**: Generated files, results
- **Configuration**: Settings, templates
- **Logs**: Operation logs, status files
- **Backups**: Configuration backups

## 🔒 Security Files (15%)
- **Legal**: Licenses, policies
- **Privacy**: Ignore files, security configs
- **Documentation**: Security guides

---

# 🛠️ Maintenance Tasks

## 📝 Documentation Maintenance
- [ ] Update README with new features
- [ ] Keep guides current with framework changes
- [ ] Test and update examples regularly
- [ ] Update templates with new capabilities

## 🔧 Code Maintenance
- [ ] Follow coding standards for source code
- [ ] Maintain test coverage for all modules
- [ ] Keep configuration templates current
- [ ] Update dependencies regularly

## 📊 Data Maintenance
- [ ] Clean old output files regularly
- [ ] Rotate and archive log files
- [ ] Maintain backup integrity
- [ ] Organize and categorize results

---

# 🎯 Best Practices

## 📁 Organization
- **Group by purpose**: Related files together
- **Clear naming**: Descriptive file names
- **Consistent structure**: Follow established patterns
- **Documentation**: Document file purposes

## 🔧 Management
- **Version control**: Track all source files
- **Backup strategy**: Regular backups of important files
- **Cleanup routine**: Remove temporary and old files
- **Security**: Protect sensitive configuration files

## 📚 Documentation
- **Keep current**: Update documentation with changes
- **Cross-reference**: Link related files and guides
- **Examples**: Provide working examples
- **Troubleshooting**: Include common issues and solutions

---

This project structure overview provides a complete visual representation of the NightStalker framework organization, making it easy to understand the relationships between different components and maintain a clean, professional project structure. 