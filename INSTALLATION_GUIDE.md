# 🌙 NightStalker Launcher Installation Guide

This guide will help you install the NightStalker CLI launcher for easy access to the Advanced Offensive Security Framework.

## 📋 Prerequisites

Before installing the launcher, ensure you have:

- **Python 3.6+** installed and accessible via `python3`
- **NightStalker framework** already installed and working
- **Bash shell** (Linux/macOS) or **Git Bash** (Windows)
- **sudo access** (for system-wide installation)

## 🚀 Quick Installation

### Method 1: Automated Installer (Recommended)

```bash
# Download and run the installer
curl -sSL https://raw.githubusercontent.com/your-repo/nightstalker/main/install_nightstalker.sh | bash

# Or if you have the installer locally
chmod +x install_nightstalker.sh
./install_nightstalker.sh
```

The installer will:
- Detect your NightStalker installation
- Choose the best installation method
- Set up the launcher with proper configuration
- Test the installation

### Method 2: Manual Installation

#### Step 1: Download the Launcher Script

```bash
# Download the launcher script
curl -o nightstalker.sh https://raw.githubusercontent.com/your-repo/nightstalker/main/nightstalker.sh
chmod +x nightstalker.sh
```

#### Step 2: Configure the Script

Edit the script and update the NightStalker directory:

```bash
# Open the script in your preferred editor
nano nightstalker.sh

# Find and update this line:
NIGHTSTALKER_DIR="$HOME/path/to/nightstalker"
# Change it to your actual NightStalker directory
```

#### Step 3: Install the Launcher

Choose one of the following installation methods:

**A. System-wide Installation (Recommended)**
```bash
# Copy to system bin directory (requires sudo)
sudo cp nightstalker.sh /usr/local/bin/nightstalker
sudo chmod +x /usr/local/bin/nightstalker

# Test the installation
nightstalker --version
```

**B. User-specific Installation**
```bash
# Create user bin directory
mkdir -p ~/.local/bin

# Copy the launcher
cp nightstalker.sh ~/.local/bin/nightstalker
chmod +x ~/.local/bin/nightstalker

# Add to PATH (if not already there)
echo 'export PATH="$PATH:~/.local/bin"' >> ~/.bashrc
source ~/.bashrc

# Test the installation
nightstalker --version
```

**C. Bash Alias Installation**
```bash
# Add alias to bashrc
echo 'alias nightstalker="cd /path/to/your/nightstalker && python3 -m nightstalker.cli"' >> ~/.bashrc
source ~/.bashrc

# Test the installation
nightstalker --version
```

## 🔧 Installation Methods Comparison

| Method | Pros | Cons | Best For |
|--------|------|------|----------|
| **System-wide** | Available to all users, no PATH issues | Requires sudo, affects system | Multi-user systems, servers |
| **User-specific** | No sudo required, isolated | PATH setup needed | Single user, development |
| **Bash Alias** | Simple, no files copied | Limited functionality, shell-specific | Quick setup, testing |

## 🌍 Environment Variable Configuration

You can also use environment variables for flexible configuration:

```bash
# Set NightStalker home directory
export NIGHTSTALKER_HOME="/path/to/your/nightstalker"

# Add to your shell profile for persistence
echo 'export NIGHTSTALKER_HOME="/path/to/your/nightstalker"' >> ~/.bashrc
source ~/.bashrc
```

## 🧪 Testing the Installation

After installation, test the launcher:

```bash
# Test basic functionality
nightstalker --version

# Test interactive menu
nightstalker

# Test stealth payload commands
nightstalker stealth build --help
nightstalker stealth server --help
```

## 📖 Usage Examples

Once installed, you can use the launcher from anywhere:

```bash
# Interactive menu
nightstalker

# Build stealth payload
nightstalker stealth build --lhost 192.168.1.100 --lport 4444

# Start C2 server
nightstalker stealth server --host 0.0.0.0 --port 4444

# Run demo
nightstalker stealth demo

# Build regular payloads
nightstalker payload build --type recon --format python

# Run penetration testing
nightstalker pentest --target 192.168.1.0/24

# Web red teaming
nightstalker webred scan --url https://target.com
```

## 🔍 Troubleshooting

### Common Issues

**1. "Command not found: nightstalker"**
```bash
# Check if the launcher is in PATH
which nightstalker

# If not found, check installation location
ls -la /usr/local/bin/nightstalker
ls -la ~/.local/bin/nightstalker

# Re-add to PATH if needed
export PATH="$PATH:~/.local/bin"
```

**2. "NightStalker directory not found"**
```bash
# Check the directory path in the script
grep "NIGHTSTALKER_DIR" /usr/local/bin/nightstalker

# Set environment variable
export NIGHTSTALKER_HOME="/correct/path/to/nightstalker"
```

**3. "Python 3 is not installed"**
```bash
# Install Python 3
sudo apt update && sudo apt install python3 python3-pip  # Ubuntu/Debian
sudo yum install python3 python3-pip  # CentOS/RHEL
brew install python3  # macOS
```

**4. "NightStalker module not found"**
```bash
# Navigate to NightStalker directory
cd /path/to/nightstalker

# Install dependencies
pip3 install -r requirements.txt

# Test module import
python3 -c "import nightstalker; print('Module found')"
```

**5. "Permission denied"**
```bash
# Fix permissions
sudo chmod +x /usr/local/bin/nightstalker
# or
chmod +x ~/.local/bin/nightstalker
```

### Debug Mode

Enable debug output to troubleshoot issues:

```bash
# Run with verbose output
bash -x /usr/local/bin/nightstalker --version

# Check script execution
bash -n /usr/local/bin/nightstalker  # Syntax check
```

## 🗑️ Uninstallation

To remove the launcher:

**System-wide installation:**
```bash
sudo rm /usr/local/bin/nightstalker
```

**User-specific installation:**
```bash
rm ~/.local/bin/nightstalker
```

**Bash alias:**
```bash
# Remove the alias line from ~/.bashrc
sed -i '/alias nightstalker=/d' ~/.bashrc
source ~/.bashrc
```

## 🔄 Updating the Launcher

To update the launcher:

```bash
# Download the latest version
curl -o nightstalker.sh https://raw.githubusercontent.com/your-repo/nightstalker/main/nightstalker.sh

# Reinstall using your preferred method
sudo cp nightstalker.sh /usr/local/bin/nightstalker
sudo chmod +x /usr/local/bin/nightstalker
```

## 📝 Configuration Files

The launcher can be configured through:

1. **Script variables** - Edit the launcher script directly
2. **Environment variables** - Set `NIGHTSTALKER_HOME`
3. **Command line arguments** - Pass options to the launcher

## 🛡️ Security Considerations

- The launcher script should be owned by root for system-wide installations
- User-specific installations are more secure for development environments
- Always verify the script source before installation
- Consider using a virtual environment for Python dependencies

## 📞 Support

If you encounter issues:

1. Check the troubleshooting section above
2. Verify your NightStalker installation is working
3. Check Python and dependency versions
4. Review the launcher script logs
5. Open an issue on the GitHub repository

## 🎯 Next Steps

After successful installation:

1. **Test the interactive menu**: `nightstalker`
2. **Build your first payload**: `nightstalker stealth build --interactive`
3. **Start a C2 server**: `nightstalker stealth server`
4. **Run the demo**: `nightstalker stealth demo`
5. **Explore other modules**: `nightstalker --help`

---

**Happy Hacking! 🎯**

Remember to always obtain proper authorization before testing any systems, and follow responsible disclosure practices when reporting vulnerabilities. 