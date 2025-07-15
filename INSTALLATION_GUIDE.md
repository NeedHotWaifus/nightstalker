# NightStalker Framework Installation Guide

## 🌙 Quick Start Installation

After cloning the NightStalker repository, you can install and set up the framework with a single command:

### Linux/macOS
```bash
# Clone the repository
git clone https://github.com/your-username/nightstalker.git
cd nightstalker

# Run the installation script
./install.sh
```

### Windows
```powershell
# Clone the repository
git clone https://github.com/your-username/nightstalker.git
cd nightstalker

# Run the installation script (PowerShell)
.\install.sh
```

After installation, simply run:
```bash
nightstalker
```

## 📋 Prerequisites

### System Requirements
- **Operating System**: Linux, macOS, or Windows
- **Python**: 3.7 or higher
- **Memory**: 2GB RAM minimum (4GB recommended)
- **Storage**: 1GB free space
- **Network**: Internet connection for tool downloads

### Required System Tools
The installation script will automatically install these tools:
- **Git**: Version control
- **curl/wget**: File downloads
- **nmap**: Network scanning
- **netcat**: Network utilities
- **socat**: Multipurpose relay

### Security Tools (Auto-installed)
- **Nuclei**: Vulnerability scanner
- **ffuf**: Web fuzzer
- **SQLMap**: SQL injection tool
- **Amass**: Subdomain enumeration

## 🔧 Installation Process

### What the Installation Script Does

1. **System Dependencies**: Installs required system packages
2. **Python Environment**: Creates virtual environment and installs Python dependencies
3. **NightStalker Home**: Sets up `~/.nightstalker` directory structure
4. **Security Tools**: Downloads and installs security testing tools
5. **Launcher**: Creates system-wide `nightstalker` command
6. **Configuration**: Sets up default configuration files
7. **Permissions**: Configures proper file permissions
8. **Testing**: Verifies installation and tool availability

### Directory Structure Created

```
~/.nightstalker/
├── config/          # Configuration files
├── data/           # Framework data
├── logs/           # Log files
├── output/         # Output files
├── payloads/       # Generated payloads
├── results/        # Test results
└── tools/          # Security tools
```

## 🚀 Post-Installation

### First Run
After installation, restart your terminal or run:
```bash
source ~/.bashrc  # Linux/macOS
# or
source ~/.zshrc   # macOS with zsh
```

### Verify Installation
```bash
# Check if nightstalker command is available
which nightstalker

# Run NightStalker with help
nightstalker --help

# Start interactive menu
nightstalker
```

### Environment Variables
The installation sets these environment variables:
- `NIGHTSTALKER_HOME`: `~/.nightstalker`
- `NIGHTSTALKER_DIR`: Installation directory
- `PYTHONPATH`: Includes NightStalker modules

## 🛠️ Manual Installation

If you prefer manual installation or the script fails:

### 1. Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv git curl wget nmap netcat-openbsd socat
```

**CentOS/RHEL/Fedora:**
```bash
sudo yum update
sudo yum install python3 python3-pip git curl wget nmap nc socat
```

**macOS:**
```bash
brew install python3 git curl wget nmap netcat socat
```

### 2. Setup Python Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Setup NightStalker Home
```bash
# Create home directory
mkdir -p ~/.nightstalker/{config,data,logs,output,payloads,results,tools}

# Set environment variable
echo 'export NIGHTSTALKER_HOME="$HOME/.nightstalker"' >> ~/.bashrc
echo 'export NIGHTSTALKER_DIR="$(pwd)"' >> ~/.bashrc
```

### 4. Create Launcher
```bash
# Create launcher script
sudo tee /usr/local/bin/nightstalker > /dev/null << 'EOF'
#!/bin/bash
export NIGHTSTALKER_HOME="${NIGHTSTALKER_HOME:-$HOME/.nightstalker}"
export NIGHTSTALKER_DIR="${NIGHTSTALKER_DIR:-$(pwd)}"
export PYTHONPATH="$NIGHTSTALKER_DIR:$PYTHONPATH"
cd "$NIGHTSTALKER_DIR"
source venv/bin/activate 2>/dev/null || true
python3 -m nightstalker.cli "$@"
EOF

# Make executable
sudo chmod +x /usr/local/bin/nightstalker
```

## 🔍 Troubleshooting

### Common Issues

**1. "nightstalker command not found"**
```bash
# Check if launcher was created
ls -la /usr/local/bin/nightstalker

# If not found, recreate manually
sudo ./install.sh
```

**2. "Python module not found"**
```bash
# Activate virtual environment
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

**3. "Permission denied"**
```bash
# Fix permissions
chmod +x install.sh
chmod +x *.sh
chmod +x nightstalker/*.py
```

**4. "Tool not found" (nuclei, ffuf, etc.)**
```bash
# Reinstall security tools
cd ~/.nightstalker/tools
# Follow tool-specific installation instructions
```

### Windows-Specific Issues

**1. PowerShell Execution Policy**
```powershell
# Allow script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**2. Python not in PATH**
```powershell
# Add Python to PATH or use full path
C:\Python39\python.exe -m nightstalker.cli
```

**3. Virtual Environment Issues**
```powershell
# Create virtual environment manually
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 🔒 Security Considerations

### Installation Security
- The installation script requires sudo access for system tools
- Security tools are downloaded from official sources
- All downloads are verified for integrity
- Virtual environment isolates Python dependencies

### Runtime Security
- NightStalker home directory has restricted permissions (700)
- Configuration files are stored securely
- Logs are rotated and cleaned automatically
- No sensitive data is stored in plain text

### Ethical Usage
⚠️ **IMPORTANT**: NightStalker is for authorized security testing only.

- Only use on systems you own or have explicit permission to test
- Follow responsible disclosure practices
- Comply with local laws and regulations
- Document all testing activities

## 📚 Next Steps

After successful installation:

1. **Read the Documentation**: Check `docs/` directory for detailed guides
2. **Run Examples**: Try the example scripts in `examples/` directory
3. **Configure Settings**: Customize `~/.nightstalker/config/nightstalker_config.yaml`
4. **Join Community**: Connect with other security professionals

## 🆘 Support

If you encounter issues:

1. Check the troubleshooting section above
2. Review the logs in `~/.nightstalker/logs/`
3. Search existing issues on GitHub
4. Create a new issue with detailed information

### Required Information for Support
- Operating system and version
- Python version (`python3 --version`)
- Installation method used
- Error messages and logs
- Steps to reproduce the issue

---

**Happy Hacking! 🌙**

Remember: With great power comes great responsibility. Use NightStalker ethically and legally. 