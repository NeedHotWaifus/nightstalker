# 📁 NightStalker Organized Directory Structure

This document provides a complete overview of the newly organized NightStalker project structure with categorized subfolders for better organization and maintainability.

---

# 🌙 Complete Organized Project Tree

```
🌙 nightstalker/
├── 📚 docs/                           # Documentation Directory
│   ├── 📖 core/                       # Core Documentation
│   │   ├── 📄 README.md               # Main project documentation
│   │   ├── 📄 DIRECTORY_STRUCTURE.md  # Complete directory structure
│   │   ├── 📄 FRAMEWORK_SELECTION_GUIDE.md # Choose the right framework
│   │   ├── 📄 FILE_ORGANIZATION_GUIDE.md   # File organization guide
│   │   ├── 📄 PROJECT_STRUCTURE_OVERVIEW.md # Visual structure overview
│   │   └── 📄 ORGANIZED_STRUCTURE.md  # This file - organized structure
│   │
│   ├── 🌐 web/                        # Web Exploitation Documentation
│   │   ├── 📄 WEB_EXPLOIT_FRAMEWORK_README.md # Web framework guide
│   │   └── 📄 WEB_RED_TEAMING_GUIDE.md        # Web red teaming guide
│   │
│   ├── 🦠 redteam/                    # Red Teaming Documentation
│   │   ├── 📄 LINUX_DEPLOYMENT_GUIDE.md       # Linux deployment guide
│   │   ├── 📄 EXFILTRATION_GUIDE.md           # Exfiltration guide
│   │   ├── 📄 COVERT_SERVER_GUIDE.md          # Covert server guide
│   │   └── 📄 TOR_QUICK_SETUP.md              # Tor setup guide
│   │
│   └── 📋 guides/                     # Additional Guides (Future)
│       ├── 📄 CONTRIBUTING.md         # Contributing guidelines
│       ├── 📄 SECURITY.md             # Security policy
│       ├── 📄 CHANGELOG.md            # Version history
│       └── 📄 ROADMAP.md              # Development roadmap
│
├── 🧪 tests/                          # Testing Directory
│   ├── 📋 unit/                       # Unit Tests
│   │   ├── 📄 test_framework.py       # Framework testing
│   │   ├── 📄 test_payload_builder.py # Payload builder tests
│   │   ├── 📄 test_exfiltration.py    # Exfiltration tests
│   │   └── 📄 test_webred.py          # Web red teaming tests
│   │
│   ├── 🔗 integration/                # Integration Tests
│   │   ├── 📄 test_all_modules.py     # Module integration testing
│   │   ├── 📄 test_framework_integration.py # Framework integration
│   │   └── 📄 test_cli_commands.py    # CLI command testing
│   │
│   └── 🔄 compatibility/              # Compatibility Tests
│       ├── 📄 test_linux_compatibility.py # Linux compatibility
│       ├── 📄 test_windows_compatibility.py # Windows compatibility
│       └── 📄 test_cross_platform.py  # Cross-platform testing
│
├── 🛠️ setup/                          # Setup & Installation
│   ├── 📄 requirements.txt            # Python dependencies
│   ├── 📄 setup.py                    # Framework installation
│   ├── 📄 install.sh                  # Linux installation script
│   ├── 📄 install_web_exploit_framework.py # Web framework installer
│   ├── 📄 Dockerfile                  # Docker container (future)
│   ├── 📄 docker-compose.yml          # Multi-container setup (future)
│   └── 📄 .dockerignore               # Docker ignore rules (future)
│
├── 📋 examples/                       # Examples Directory
│   ├── 📄 demo.py                     # Main framework demonstration
│   │
│   ├── 📦 payloads/                   # Payload Examples
│   │   ├── 📄 build_example.py        # Payload building examples
│   │   ├── 📄 build_clean_example.py  # Clean payload examples
│   │   ├── 📄 polymorphic_example.py  # Polymorphic payload examples
│   │   └── 📄 custom_payload_example.py # Custom payload examples
│   │
│   ├── 📤 exfiltration/               # Exfiltration Examples
│   │   ├── 📄 exfil_example.py        # Exfiltration examples
│   │   ├── 📄 no_server_exfil.py      # No-server exfiltration
│   │   ├── 📄 dns_exfil_example.py    # DNS exfiltration examples
│   │   └── 📄 https_exfil_example.py  # HTTPS exfiltration examples
│   │
│   └── 🌐 webred/                     # Web Red Teaming Examples
│       ├── 📄 webred_example.py       # Web red teaming examples
│       ├── 📄 web_exploit_framework_demo.py # Web framework demo
│       ├── 📄 sn1per_example.py       # Sn1per integration examples
│       └── 📄 web_scan_example.py     # Web scanning examples
│
├── 🎨 scripts/                        # Scripts Directory
│   ├── 📄 gui_exe_builder.py          # GUI payload builder
│   ├── 📄 setup_proxy.py              # Proxy setup script
│   ├── 📄 setup_tunnel.py             # Tunnel setup script
│   ├── 📄 backup_config.py            # Configuration backup script
│   └── 📄 cleanup_logs.py             # Log cleanup script
│
├── 📊 data/                           # Data Directory
│   ├── ⚙️ config/                     # Configuration Files
│   │   ├── 📄 example_config.yaml     # Example configuration
│   │   ├── 📄 config_manager.py       # Configuration manager
│   │   ├── 📄 nightstalker_config.json # NightStalker config
│   │   └── 📄 web_config.json         # Web framework config
│   │
│   ├── 📄 json/                       # JSON Data Files
│   │   ├── 📄 install_status.json     # Installation status
│   │   ├── 📄 scan_results.json       # Scan results
│   │   ├── 📄 test_results.json       # Test results
│   │   └── 📄 framework_status.json   # Framework status
│   │
│   └── 📝 logs/                       # Log Files
│       ├── 📄 install.log             # Installation log
│       ├── 📄 framework.log           # Framework operations log
│       ├── 📄 error.log               # Error log
│       └── 📄 debug.log               # Debug log
│
├── 🌐 nightstalker_web/               # Web Exploitation Framework
│   ├── 📁 modules/                    # Modular components
│   │   ├── 📁 recon/                  # Reconnaissance modules
│   │   │   ├── 📄 sn1per_wrapper.py   # Sn1per integration
│   │   │   ├── 📄 nuclei_wrapper.py   # Nuclei integration (future)
│   │   │   ├── 📄 nikto_wrapper.py    # Nikto integration (future)
│   │   │   └── 📄 README.md           # Module documentation
│   │   ├── 📁 exploit/                # Exploitation modules
│   │   │   ├── 📄 sqlmap_wrapper.py   # SQLMap integration (future)
│   │   │   ├── 📄 msf_wrapper.py      # Metasploit integration (future)
│   │   │   └── 📄 README.md           # Module documentation
│   │   ├── 📁 bruteforce/             # Bruteforce modules
│   │   │   ├── 📄 openbullet_wrapper.py # OpenBullet integration (future)
│   │   │   ├── 📄 hydra_wrapper.py    # Hydra integration (future)
│   │   │   └── 📄 README.md           # Module documentation
│   │   ├── 📁 post/                   # Post-exploitation modules
│   │   │   ├── 📄 persistence.py      # Persistence mechanisms
│   │   │   ├── 📄 privilege_escalation.py # Privilege escalation
│   │   │   └── 📄 README.md           # Module documentation
│   │   └── 📁 auxiliary/              # Auxiliary tools
│   │       ├── 📄 proxy_setup.py      # Proxy configuration
│   │       ├── 📄 tunnel_setup.py     # Tunnel configuration
│   │       └── 📄 README.md           # Module documentation
│   │
│   ├── 📁 tools/                      # Installed security tools
│   │   ├── 📁 sn1per/                 # Sn1per tool
│   │   │   ├── 📄 sn1per              # Main Sn1per executable
│   │   │   ├── 📄 install.sh          # Sn1per installer
│   │   │   └── 📄 README.md           # Tool documentation
│   │   ├── 📁 sqlmap/                 # SQLMap tool (future)
│   │   ├── 📁 nuclei/                 # Nuclei tool (future)
│   │   ├── 📁 wpscan/                 # WPScan tool (future)
│   │   └── 📄 README.md               # Tools documentation
│   │
│   ├── 📁 loot/                       # Target-specific results
│   │   ├── 📁 target1.com/            # Results for target1.com
│   │   │   ├── 📁 recon/              # Reconnaissance results
│   │   │   │   ├── 📁 sn1per/         # Sn1per output
│   │   │   │   ├── 📁 nuclei/         # Nuclei output
│   │   │   │   └── 📄 scan_results.json
│   │   │   ├── 📁 exploit/            # Exploitation results
│   │   │   ├── 📁 bruteforce/         # Bruteforce results
│   │   │   ├── 📁 post/               # Post-exploitation results
│   │   │   ├── 📁 screenshots/        # Screenshots and evidence
│   │   │   └── 📁 logs/               # Log files
│   │   └── 📁 target2.com/            # Results for target2.com
│   │
│   └── 📁 bin/                        # Wrapper scripts
│       ├── 📄 web-exploit             # Main framework launcher
│       ├── 📄 nightstalker            # NightStalker CLI wrapper
│       ├── 📄 setup-proxy             # Proxy setup script
│       └── 📄 setup-tunnel            # Tunnel setup script
│
├── 🦠 nightstalker/                   # Malware & Red Teaming Framework
│   ├── 📁 redteam/                    # Red teaming modules
│   │   ├── 📁 c2/                     # Command & Control
│   │   │   ├── 📄 __init__.py         # Package initialization
│   │   │   ├── 📄 command_control.py  # C2 server implementation
│   │   │   ├── 📄 channels.py         # Communication channels
│   │   │   └── 📄 stealth.py          # Stealth techniques
│   │   ├── 📄 __init__.py             # Package initialization
│   │   ├── 📄 webred.py               # Web red teaming integration
│   │   ├── 📄 web_exploit_framework.py # Web exploitation framework
│   │   ├── 📄 web_exploit_tui.py      # Web exploitation TUI
│   │   ├── 📄 exfiltration.py         # Data exfiltration
│   │   ├── 📄 fuzzer.py               # Genetic fuzzing
│   │   ├── 📄 infection_watchers.py   # File monitoring
│   │   ├── 📄 self_rebuild.py         # Environment reconstruction
│   │   ├── 📄 payload_builder.py      # Payload creation
│   │   └── 📄 polymorph.py            # Polymorphic engine
│   │
│   ├── 📁 pentest/                    # Penetration testing
│   │   └── 📄 __init__.py             # Package initialization
│   │
│   ├── 📁 core/                       # Core framework
│   │   ├── 📄 __init__.py             # Package initialization
│   │   └── 📄 automation.py           # Attack automation
│   │
│   ├── 📁 builder/                    # Payload building
│   │   └── 📄 __init__.py             # Package initialization
│   │
│   ├── 📄 __init__.py                 # Package initialization
│   └── 📄 cli.py                      # Command-line interface
│
├── 📦 payloads/                       # Payload Templates
│   ├── 📄 recon.yaml                  # Reconnaissance payloads
│   ├── 📄 backdoor.yaml               # Backdoor payloads
│   ├── 📄 keylogger.yaml              # Keylogger payloads
│   ├── 📄 persistence.yaml            # Persistence payloads
│   └── 📄 custom.yaml                 # Custom payloads
│
├── 📝 wordlists/                      # Wordlists & Dictionaries
│   ├── 📄 common_passwords.txt        # Common passwords
│   ├── 📄 usernames.txt               # Username lists
│   ├── 📄 directories.txt             # Directory enumeration
│   └── 📄 payloads.txt                # Payload wordlists
│
├── 📊 output/                         # Generated Output
│   ├── 📁 payloads/                   # Built payloads
│   ├── 📁 reports/                    # Generated reports
│   ├── 📁 screenshots/                # Screenshots
│   └── 📁 exports/                    # Exported data
│
├── 📋 results/                        # Test Results
│   ├── 📁 scans/                      # Scan results
│   ├── 📁 tests/                      # Test outputs
│   ├── 📁 benchmarks/                 # Performance benchmarks
│   └── 📁 analysis/                   # Analysis results
│
├── 💾 backups/                        # Backup Files
│   ├── 📁 config/                     # Configuration backups
│   ├── 📁 data/                       # Data backups
│   └── 📁 logs/                       # Log backups
│
├── 🔒 security/                       # Security & Legal
│   ├── 📄 LICENSE                     # MIT License
│   ├── 📄 SECURITY.md                 # Security policy (future)
│   ├── 📄 CONTRIBUTING.md             # Contributing guidelines (future)
│   ├── 📄 .gitignore                  # Git ignore rules
│   └── 📄 .dockerignore               # Docker ignore rules (future)
│
└── 📄 README.md                       # Main project README
```

---

# 📊 Directory Statistics

## 📁 Directory Count
- **Total Directories**: 35+
- **Documentation**: 4 directories (core, web, redteam, guides)
- **Testing**: 3 directories (unit, integration, compatibility)
- **Examples**: 3 directories (payloads, exfiltration, webred)
- **Data**: 3 directories (config, json, logs)
- **Framework Code**: 2 main frameworks
- **Supporting**: 8 directories (setup, scripts, payloads, wordlists, output, results, backups, security)

## 📄 File Count
- **Total Files**: 100+
- **Documentation**: 20+ markdown files
- **Python Scripts**: 50+ files
- **Configuration**: 15+ files
- **Templates**: 10+ files
- **Examples**: 15+ files
- **Tests**: 10+ files

## 🎯 File Types
- **Markdown (.md)**: Documentation and guides
- **Python (.py)**: Source code and scripts
- **YAML (.yaml)**: Configuration files
- **JSON (.json)**: Data and status files
- **Shell (.sh)**: Installation scripts
- **Text (.txt)**: Requirements and wordlists

---

# 🔄 File Organization Benefits

## 📚 Documentation Organization
- **Core Docs**: Main project documentation in one place
- **Framework-Specific**: Separate docs for web and red teaming
- **Guides**: Additional guides for contributors and maintainers
- **Easy Navigation**: Clear structure for finding information

## 🧪 Testing Organization
- **Unit Tests**: Individual component testing
- **Integration Tests**: Framework integration testing
- **Compatibility Tests**: Cross-platform testing
- **Clear Separation**: Different test types in separate directories

## 📋 Examples Organization
- **Categorized**: Examples grouped by functionality
- **Easy Discovery**: Clear subdirectories for different types
- **Learning Path**: Structured examples for different skill levels
- **Maintenance**: Easy to update and maintain examples

## 🛠️ Setup Organization
- **Installation**: All setup files in one place
- **Dependencies**: Clear requirements and setup scripts
- **Platform Support**: Separate installers for different platforms
- **Container Support**: Future Docker support organized

## 📊 Data Organization
- **Configuration**: All config files centralized
- **JSON Data**: Structured data files organized
- **Logs**: Log files properly categorized
- **Backups**: Backup strategy implemented

---

# 🎯 Usage Patterns

## 📚 Documentation Access
```
docs/
├── core/README.md                    # Start here
├── core/FRAMEWORK_SELECTION_GUIDE.md # Choose framework
├── web/WEB_EXPLOIT_FRAMEWORK_README.md # Web exploitation
└── redteam/LINUX_DEPLOYMENT_GUIDE.md # Red teaming
```

## 🧪 Testing Workflow
```
tests/
├── unit/test_framework.py            # Run unit tests
├── integration/test_all_modules.py   # Run integration tests
└── compatibility/test_linux_compatibility.py # Run compatibility tests
```

## 📋 Examples Learning
```
examples/
├── demo.py                           # Start with main demo
├── payloads/build_example.py         # Learn payload building
├── exfiltration/exfil_example.py     # Learn exfiltration
└── webred/webred_example.py          # Learn web red teaming
```

## 🛠️ Setup Process
```
setup/
├── requirements.txt                  # Install dependencies
├── setup.py                         # Install framework
├── install.sh                       # Linux setup
└── install_web_exploit_framework.py # Web framework setup
```

---

# 🔧 Maintenance Tasks

## 📝 Documentation Maintenance
- [ ] Update core documentation with new features
- [ ] Keep framework-specific docs current
- [ ] Test and update examples regularly
- [ ] Update guides for contributors

## 🧪 Testing Maintenance
- [ ] Maintain test coverage for all modules
- [ ] Update integration tests with new features
- [ ] Test cross-platform compatibility
- [ ] Validate test results

## 📊 Data Maintenance
- [ ] Clean old output files regularly
- [ ] Rotate and archive log files
- [ ] Maintain backup integrity
- [ ] Organize and categorize results

## 🔧 Code Maintenance
- [ ] Follow coding standards for all scripts
- [ ] Keep configuration templates current
- [ ] Update dependencies regularly
- [ ] Maintain framework integration

---

# 🎯 Best Practices

## 📁 Organization
- **Group by purpose**: Related files together
- **Clear naming**: Descriptive file and directory names
- **Consistent structure**: Follow established patterns
- **Documentation**: Document file purposes and relationships

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

This organized structure provides a clean, professional, and maintainable project organization that supports both development and user needs while making it easy to find and work with specific types of files. 