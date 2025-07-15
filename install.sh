#!/bin/bash

# NightStalker Framework Installation Script
# This script handles the complete installation and setup of the NightStalker framework

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt-get; then
            echo "debian"
        elif command_exists yum; then
            echo "rhel"
        elif command_exists dnf; then
            echo "fedora"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

# Function to install system dependencies
install_system_deps() {
    local os=$(detect_os)
    print_status "Installing system dependencies for $os..."
    
    case $os in
        "debian")
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip python3-venv git curl wget nmap netcat-openbsd socat
            ;;
        "rhel"|"fedora")
            sudo yum update -y || sudo dnf update -y
            sudo yum install -y python3 python3-pip git curl wget nmap nc socat || sudo dnf install -y python3 python3-pip git curl wget nmap nc socat
            ;;
        "macos")
            if ! command_exists brew; then
                print_status "Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install python3 git curl wget nmap netcat socat
            ;;
        *)
            print_warning "Unknown OS, please install dependencies manually: python3, pip3, git, curl, wget, nmap, netcat, socat"
            ;;
    esac
}

# Function to create virtual environment
setup_python_env() {
    print_status "Setting up Python virtual environment..."
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install Python dependencies
    print_status "Installing Python dependencies..."
    pip install -r requirements.txt 2>/dev/null || {
        print_warning "requirements.txt not found, installing basic dependencies..."
        pip install requests paramiko psutil cryptography colorama rich click dnspython
    }
}

# Function to setup NightStalker home directory
setup_nightstalker_home() {
    print_status "Setting up NightStalker home directory..."
    
    # Create user-specific home directory
    NIGHTSTALKER_HOME="$HOME/.nightstalker"
    
    if [ ! -d "$NIGHTSTALKER_HOME" ]; then
        mkdir -p "$NIGHTSTALKER_HOME"
        print_success "Created NightStalker home directory: $NIGHTSTALKER_HOME"
    fi
    
    # Create subdirectories
    mkdir -p "$NIGHTSTALKER_HOME"/{data,logs,output,config,payloads,results}
    
    # Copy configuration files if they exist
    if [ -f "config/nightstalker_config.yaml" ]; then
        cp config/nightstalker_config.yaml "$NIGHTSTALKER_HOME/config/"
    fi
    
    # Set environment variable
    echo "export NIGHTSTALKER_HOME=$NIGHTSTALKER_HOME" >> "$HOME/.bashrc"
    echo "export NIGHTSTALKER_HOME=$NIGHTSTALKER_HOME" >> "$HOME/.zshrc" 2>/dev/null || true
    
    # Export for current session
    export NIGHTSTALKER_HOME="$NIGHTSTALKER_HOME"
    
    print_success "NightStalker home directory configured: $NIGHTSTALKER_HOME"
}

# Function to create launcher script
create_launcher() {
    print_status "Creating NightStalker launcher..."
    
    # Get the current directory (where the repo is cloned)
    CURRENT_DIR=$(pwd)
    
    # Create launcher script
    cat > /usr/local/bin/nightstalker << EOF
#!/bin/bash

# NightStalker Framework Launcher
# This script launches the NightStalker framework

# Set NightStalker home directory
if [ -z "\$NIGHTSTALKER_HOME" ]; then
    export NIGHTSTALKER_HOME="\$HOME/.nightstalker"
fi

# Set NightStalker directory to current installation
export NIGHTSTALKER_DIR="$CURRENT_DIR"

# Activate virtual environment
if [ -f "$CURRENT_DIR/venv/bin/activate" ]; then
    source "$CURRENT_DIR/venv/bin/activate"
fi

# Add current directory to Python path
export PYTHONPATH="$CURRENT_DIR:\$PYTHONPATH"

# Launch NightStalker
cd "$CURRENT_DIR"
python3 -m nightstalker.cli "\$@"
EOF
    
    # Make launcher executable
    chmod +x /usr/local/bin/nightstalker
    
    print_success "NightStalker launcher created: /usr/local/bin/nightstalker"
}

# Function to install security tools
install_security_tools() {
    print_status "Installing security tools..."
    
    # Create tools directory
    TOOLS_DIR="$HOME/.nightstalker/tools"
    mkdir -p "$TOOLS_DIR"
    
    # Install Nuclei
    if ! command_exists nuclei; then
        print_status "Installing Nuclei..."
        curl -sfL https://raw.githubusercontent.com/projectdiscovery/nuclei/master/v2/cmd/nuclei/install.sh | sh -s -- -b /usr/local/bin
    fi
    
    # Install ffuf
    if ! command_exists ffuf; then
        print_status "Installing ffuf..."
        local os=$(uname -s | tr '[:upper:]' '[:lower:]')
        local arch=$(uname -m)
        if [ "$arch" = "x86_64" ]; then arch="amd64"; fi
        curl -L "https://github.com/ffuf/ffuf/releases/latest/download/ffuf_${os}_${arch}.tar.gz" | tar xz
        sudo mv ffuf /usr/local/bin/
    fi
    
    # Install SQLMap
    if [ ! -d "$TOOLS_DIR/sqlmap" ]; then
        print_status "Installing SQLMap..."
        git clone https://github.com/sqlmapproject/sqlmap.git "$TOOLS_DIR/sqlmap"
        ln -sf "$TOOLS_DIR/sqlmap/sqlmap.py" /usr/local/bin/sqlmap
    fi
    
    # Install Amass
    if ! command_exists amass; then
        print_status "Installing Amass..."
        local os=$(uname -s | tr '[:upper:]' '[:lower:]')
        local arch=$(uname -m)
        if [ "$arch" = "x86_64" ]; then arch="amd64"; fi
        curl -L "https://github.com/owasp-amass/amass/releases/latest/download/amass_${os}_${arch}.zip" -o amass.zip
        unzip -q amass.zip
        sudo mv amass /usr/local/bin/
        rm amass.zip
    fi
    
    print_success "Security tools installation completed"
}

# Function to setup permissions
setup_permissions() {
    print_status "Setting up permissions..."
    
    # Make scripts executable
    chmod +x *.sh
    chmod +x nightstalker/*.py
    chmod +x nightstalker/redteam/*.py
    chmod +x nightstalker/c2/*.py
    chmod +x nightstalker/utils/*.py
    
    # Set proper permissions for home directory
    chmod 700 "$HOME/.nightstalker"
    
    print_success "Permissions configured"
}

# Function to create configuration
create_config() {
    print_status "Creating default configuration..."
    
    CONFIG_DIR="$HOME/.nightstalker/config"
    
    # Create default config if it doesn't exist
    if [ ! -f "$CONFIG_DIR/nightstalker_config.yaml" ]; then
        cat > "$CONFIG_DIR/nightstalker_config.yaml" << EOF
# NightStalker Framework Configuration
# This file contains the default configuration for the NightStalker framework

# Framework settings
framework:
  name: "NightStalker"
  version: "2.0.0"
  debug: false
  log_level: "INFO"
  log_file: "\$NIGHTSTALKER_HOME/logs/framework.log"

# Tool settings
tools:
  nuclei:
    enabled: true
    timeout: 300
    threads: 10
  sqlmap:
    enabled: true
    timeout: 600
  ffuf:
    enabled: true
    wordlist: "/usr/share/wordlists/dirb/common.txt"
  nmap:
    enabled: true
    timeout: 300

# Stealth settings
stealth:
  anti_analysis: true
  process_injection: false
  memory_only: false
  cleanup: true
  jitter: true
  obfuscation: true
  encryption: true

# C2 settings
c2:
  default_channel: "https"
  beacon_interval: 30
  max_payload_size: 512
  retry_count: 3

# Exfiltration settings
exfiltration:
  default_channel: "https"
  chunk_size: 1024
  encryption: true
  compression: false

# Output settings
output:
  format: "json"
  directory: "\$NIGHTSTALKER_HOME/output"
  include_timestamp: true
  include_metadata: true
EOF
        print_success "Default configuration created"
    fi
}

# Function to run post-installation tests
run_tests() {
    print_status "Running post-installation tests..."
    
    # Test Python environment
    if python3 -c "import requests, paramiko, psutil" 2>/dev/null; then
        print_success "Python dependencies test passed"
    else
        print_warning "Some Python dependencies may be missing"
    fi
    
    # Test tool availability
    local tools=("nuclei" "ffuf" "nmap" "sqlmap")
    for tool in "${tools[@]}"; do
        if command_exists "$tool"; then
            print_success "$tool is available"
        else
            print_warning "$tool is not available"
        fi
    done
    
    # Test launcher
    if [ -x "/usr/local/bin/nightstalker" ]; then
        print_success "NightStalker launcher is ready"
    else
        print_error "NightStalker launcher creation failed"
        exit 1
    fi
}

# Function to display installation summary
show_summary() {
    echo
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    🌙 NIGHTSTALKER INSTALLED                  ║"
    echo "║                    Advanced Offensive Security Framework      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo
    print_success "Installation completed successfully!"
    echo
    echo "📁 NightStalker Home: $NIGHTSTALKER_HOME"
    echo "📁 Installation Directory: $(pwd)"
    echo "🐍 Python Environment: $(pwd)/venv"
    echo "🔧 Launcher: /usr/local/bin/nightstalker"
    echo
    echo "🚀 To start NightStalker, simply run:"
    echo "   nightstalker"
    echo
    echo "📚 For help and documentation:"
    echo "   nightstalker --help"
    echo
    echo "⚠️  IMPORTANT: Please restart your terminal or run:"
    echo "   source ~/.bashrc"
    echo "   to ensure environment variables are loaded."
    echo
    print_warning "This framework is for authorized security testing only!"
    echo
}

# Main installation function
main() {
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    🌙 NIGHTSTALKER INSTALLER                  ║"
    echo "║                    Advanced Offensive Security Framework      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo
    
    print_status "Starting NightStalker installation..."
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        print_error "Please do not run this script as root"
        exit 1
    fi
    
    # Check if we're in the NightStalker directory
    if [ ! -f "nightstalker/__init__.py" ]; then
        print_error "Please run this script from the NightStalker directory"
        exit 1
    fi
    
    # Install system dependencies
    install_system_deps
    
    # Setup Python environment
    setup_python_env
    
    # Setup NightStalker home directory
    setup_nightstalker_home
    
    # Install security tools
    install_security_tools
    
    # Create launcher
    create_launcher
    
    # Setup permissions
    setup_permissions
    
    # Create configuration
    create_config
    
    # Run tests
    run_tests
    
    # Show summary
    show_summary
}

# Run main function
main "$@" 