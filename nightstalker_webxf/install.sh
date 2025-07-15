#!/bin/bash

# NightStalker WebXF - Unified Web Exploitation Framework
# Installation Script
# Version: 2.0.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Installation paths
INSTALL_DIR="/usr/local/bin"
SCRIPT_NAME="nightstalker-webxf"
LAUNCHER_SCRIPT="nightstalker-webxf.sh"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_banner() {
    echo -e "${PURPLE}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗ █████╗ ██╗  ██╗ ║
║    ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔══██╗██║ ██╔╝ ║
║    ██╔██╗ ██║██║██║  ███╗███████║   ██║   ███████║█████╔╝  ║
║    ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══██║██╔═██╗  ║
║    ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║  ██║██║  ██╗ ║
║    ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ║
║                                                              ║
║              Web Exploitation Framework                     ║
║                    Unified Edition                          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Python version
check_python_version() {
    if command_exists python3; then
        python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        python_major=$(echo $python_version | cut -d. -f1)
        python_minor=$(echo $python_version | cut -d. -f2)
        
        if [ "$python_major" -eq 3 ] && [ "$python_minor" -ge 8 ]; then
            print_status "Python $python_version found"
            return 0
        else
            print_error "Python 3.8+ required, found $python_version"
            return 1
        fi
    else
        print_error "Python 3 not found"
        return 1
    fi
}

# Function to install Python dependencies
install_python_deps() {
    print_info "Installing Python dependencies..."
    
    # Check if pip3 exists
    if ! command_exists pip3; then
        print_warning "pip3 not found, attempting to install..."
        
        if command_exists apt-get; then
            sudo apt-get update
            sudo apt-get install -y python3-pip
        elif command_exists yum; then
            sudo yum install -y python3-pip
        elif command_exists dnf; then
            sudo dnf install -y python3-pip
        else
            print_error "Could not install pip3 automatically"
            return 1
        fi
    fi
    
    # Upgrade pip
    python3 -m pip install --upgrade pip
    
    # Install requirements
    if [ -f "requirements.txt" ]; then
        python3 -m pip install -r requirements.txt
    else
        print_warning "requirements.txt not found, installing basic dependencies..."
        python3 -m pip install PyYAML requests cryptography click rich colorama
    fi
    
    print_status "Python dependencies installed"
}

# Function to install system dependencies
install_system_deps() {
    print_info "Installing system dependencies..."
    
    if command_exists apt-get; then
        # Debian/Ubuntu
        sudo apt-get update
        sudo apt-get install -y \
            git curl wget unzip \
            nmap masscan \
            sqlmap \
            nikto \
            dirb \
            gobuster \
            subfinder \
            amass \
            nuclei \
            xsstrike \
            metasploit-framework
    elif command_exists yum; then
        # CentOS/RHEL
        sudo yum install -y \
            git curl wget unzip \
            nmap \
            nikto \
            dirb
    elif command_exists dnf; then
        # Fedora
        sudo dnf install -y \
            git curl wget unzip \
            nmap \
            nikto \
            dirb
    else
        print_warning "Unsupported package manager, please install dependencies manually"
    fi
    
    print_status "System dependencies installed"
}

# Function to create launcher script
create_launcher_script() {
    print_info "Creating launcher script..."
    
    cat > "$LAUNCHER_SCRIPT" << 'EOF'
#!/bin/bash

# NightStalker WebXF Launcher Script
# Unified Web Exploitation Framework

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Framework paths
FRAMEWORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$FRAMEWORK_DIR/main.py"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

# Function to check if virtual environment exists
check_venv() {
    if [ -d "$FRAMEWORK_DIR/venv" ]; then
        return 0
    else
        return 1
    fi
}

# Function to activate virtual environment
activate_venv() {
    if check_venv; then
        source "$FRAMEWORK_DIR/venv/bin/activate"
        print_status "Virtual environment activated"
    fi
}

# Function to check Python installation
check_python() {
    if command -v python3 >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Function to check framework installation
check_framework() {
    if [ -f "$PYTHON_SCRIPT" ]; then
        return 0
    else
        return 1
    fi
}

# Function to show help
show_help() {
    echo "NightStalker WebXF - Unified Web Exploitation Framework"
    echo ""
    echo "Usage: $0 [options] [command]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -v, --version  Show version information"
    echo "  --check        Check framework status"
    echo "  --update       Update framework"
    echo ""
    echo "Commands:"
    echo "  recon          Reconnaissance operations"
    echo "  exploit        Exploitation operations"
    echo "  bruteforce     Bruteforce operations"
    echo "  post           Post-exploitation operations"
    echo "  tools          Tool management"
    echo "  report         Report generation"
    echo ""
    echo "Examples:"
    echo "  $0 recon --target example.com --all"
    echo "  $0 exploit sqlmap --target http://example.com/vuln.php?id=1"
    echo "  $0 bruteforce --target http://example.com/login --wordlist users.txt"
    echo "  $0 tools install --all"
}

# Function to show version
show_version() {
    echo "NightStalker WebXF v2.0.0"
    echo "Unified Web Exploitation Framework"
}

# Function to check framework status
check_status() {
    print_info "Checking framework status..."
    
    if ! check_python; then
        print_error "Python 3 not found"
        return 1
    fi
    
    if ! check_framework; then
        print_error "Framework not found at $PYTHON_SCRIPT"
        return 1
    fi
    
    print_status "Framework is ready"
    return 0
}

# Function to update framework
update_framework() {
    print_info "Updating framework..."
    
    if [ -d "$FRAMEWORK_DIR/.git" ]; then
        cd "$FRAMEWORK_DIR"
        git pull origin main
        print_status "Framework updated"
    else
        print_warning "Not a git repository, cannot update"
    fi
}

# Main execution
main() {
    # Check if help is requested
    if [[ "$1" == "-h" || "$1" == "--help" ]]; then
        show_help
        exit 0
    fi
    
    # Check if version is requested
    if [[ "$1" == "-v" || "$1" == "--version" ]]; then
        show_version
        exit 0
    fi
    
    # Check if status check is requested
    if [[ "$1" == "--check" ]]; then
        check_status
        exit $?
    fi
    
    # Check if update is requested
    if [[ "$1" == "--update" ]]; then
        update_framework
        exit 0
    fi
    
    # Check Python installation
    if ! check_python; then
        print_error "Python 3 is required but not installed"
        exit 1
    fi
    
    # Check framework installation
    if ! check_framework; then
        print_error "Framework not found at $PYTHON_SCRIPT"
        exit 1
    fi
    
    # Activate virtual environment if available
    activate_venv
    
    # Execute framework
    cd "$FRAMEWORK_DIR"
    python3 main.py "$@"
}

# Run main function with all arguments
main "$@"
EOF
    
    chmod +x "$LAUNCHER_SCRIPT"
    print_status "Launcher script created: $LAUNCHER_SCRIPT"
}

# Function to install launcher system-wide
install_launcher() {
    print_info "Installing launcher system-wide..."
    
    # Create installation directory if it doesn't exist
    sudo mkdir -p "$INSTALL_DIR"
    
    # Copy launcher script
    sudo cp "$LAUNCHER_SCRIPT" "$INSTALL_DIR/$SCRIPT_NAME"
    sudo chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
    
    print_status "Launcher installed to $INSTALL_DIR/$SCRIPT_NAME"
}

# Function to create virtual environment
create_venv() {
    print_info "Creating virtual environment..."
    
    if command_exists python3; then
        python3 -m venv venv
        source venv/bin/activate
        python3 -m pip install --upgrade pip
        print_status "Virtual environment created"
    else
        print_error "Python 3 not found, cannot create virtual environment"
        return 1
    fi
}

# Function to create configuration
create_config() {
    print_info "Creating configuration files..."
    
    # Create config directory
    mkdir -p config
    
    # Create default configuration
    cat > config/default.yaml << 'EOF'
framework:
  name: "NightStalker WebXF"
  version: "2.0.0"
  debug: false
  stealth_mode: true
  max_threads: 10
  timeout: 300

tools:
  sqlmap:
    path: "/usr/local/bin/sqlmap"
    timeout: 300
    threads: 10
    risk_level: 1
    level: 1
  
  nuclei:
    path: "/usr/local/bin/nuclei"
    templates_path: "~/.local/share/nuclei/templates"
    timeout: 300
    severity: ["low", "medium", "high", "critical"]
    threads: 50
  
  xsstrike:
    path: "/usr/local/bin/xsstrike"
    timeout: 300
    crawl: true
    blind: false

logging:
  level: "INFO"
  file: "logs/framework.log"
  max_size: "10MB"
  backup_count: 5
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  console_output: true
  colored_output: true

output:
  directory: "loot"
  format: "json"
  include_screenshots: true
  include_logs: true
  compress_results: true
  encrypt_sensitive: true
EOF
    
    print_status "Configuration files created"
}

# Function to create directory structure
create_directories() {
    print_info "Creating directory structure..."
    
    mkdir -p {logs,loot,reports,temp,wordlists,config/payloads}
    
    print_status "Directory structure created"
}

# Function to download wordlists
download_wordlists() {
    print_info "Downloading wordlists..."
    
    cd wordlists
    
    # Download common wordlists
    if [ ! -f "rockyou.txt" ]; then
        print_info "Downloading rockyou.txt..."
        wget -q https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt.gz
        gunzip rockyou.txt.gz
    fi
    
    if [ ! -f "common.txt" ]; then
        print_info "Downloading common.txt..."
        wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
    fi
    
    if [ ! -f "subdomains.txt" ]; then
        print_info "Downloading subdomains.txt..."
        wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -O subdomains.txt
    fi
    
    cd ..
    
    print_status "Wordlists downloaded"
}

# Function to test installation
test_installation() {
    print_info "Testing installation..."
    
    # Test Python script
    if python3 -c "import yaml, requests, cryptography" 2>/dev/null; then
        print_status "Python dependencies test passed"
    else
        print_error "Python dependencies test failed"
        return 1
    fi
    
    # Test launcher script
    if [ -f "$LAUNCHER_SCRIPT" ]; then
        if bash "$LAUNCHER_SCRIPT" --check >/dev/null 2>&1; then
            print_status "Launcher script test passed"
        else
            print_error "Launcher script test failed"
            return 1
        fi
    fi
    
    print_status "Installation test completed successfully"
    return 0
}

# Function to show installation summary
show_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    Installation Complete!                    ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Framework Information:${NC}"
    echo -e "  Name: NightStalker WebXF"
    echo -e "  Version: 2.0.0"
    echo -e "  Type: Unified Web Exploitation Framework"
    echo ""
    echo -e "${CYAN}Installation Paths:${NC}"
    echo -e "  Framework: $(pwd)"
    echo -e "  Launcher: $INSTALL_DIR/$SCRIPT_NAME"
    echo -e "  Config: $(pwd)/config/default.yaml"
    echo -e "  Logs: $(pwd)/logs/"
    echo -e "  Output: $(pwd)/loot/"
    echo ""
    echo -e "${CYAN}Usage Examples:${NC}"
    echo -e "  $SCRIPT_NAME --help"
    echo -e "  $SCRIPT_NAME recon --target example.com --all"
    echo -e "  $SCRIPT_NAME exploit sqlmap --target http://example.com/vuln.php?id=1"
    echo -e "  $SCRIPT_NAME bruteforce --target http://example.com/login --wordlist wordlist.txt"
    echo -e "  $SCRIPT_NAME tools install --all"
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo -e "  1. Review configuration: config/default.yaml"
    echo -e "  2. Install additional tools: $SCRIPT_NAME tools install --all"
    echo -e "  3. Run your first scan: $SCRIPT_NAME recon --target example.com"
    echo ""
    echo -e "${GREEN}Happy hacking! (Ethically, of course)${NC}"
    echo ""
}

# Main installation function
main() {
    print_banner
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root - this will install system-wide"
    fi
    
    # Check Python version
    if ! check_python_version; then
        print_error "Python 3.8+ is required"
        exit 1
    fi
    
    # Create directory structure
    create_directories
    
    # Create virtual environment
    create_venv
    
    # Install Python dependencies
    install_python_deps
    
    # Install system dependencies (if root)
    if [ "$EUID" -eq 0 ]; then
        install_system_deps
    else
        print_warning "Skipping system dependencies (run with sudo for full installation)"
    fi
    
    # Create configuration
    create_config
    
    # Download wordlists
    download_wordlists
    
    # Create launcher script
    create_launcher_script
    
    # Install launcher system-wide (if root)
    if [ "$EUID" -eq 0 ]; then
        install_launcher
    else
        print_warning "Skipping system-wide launcher installation (run with sudo)"
    fi
    
    # Test installation
    if test_installation; then
        show_summary
    else
        print_error "Installation test failed"
        exit 1
    fi
}

# Run main function
main "$@" 