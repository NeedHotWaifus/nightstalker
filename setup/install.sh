#!/bin/bash

# NightStalker Framework Installation Script
# Advanced Offensive Security Framework

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. This is not recommended for security reasons."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Check Python version
check_python() {
    print_status "Checking Python version..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_VERSION=$(python -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        PYTHON_CMD="python"
    else
        print_error "Python 3.8+ is required but not installed."
        exit 1
    fi
    
    # Check if version is >= 3.8
    if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" 2>/dev/null; then
        print_success "Python $PYTHON_VERSION found"
    else
        print_error "Python 3.8+ is required. Found version: $PYTHON_VERSION"
        exit 1
    fi
}

# Check system dependencies
check_dependencies() {
    print_status "Checking system dependencies..."
    
    # Check for pip
    if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
        print_error "pip is required but not installed."
        print_status "Installing pip..."
        
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y python3-pip
        elif command -v yum &> /dev/null; then
            sudo yum install -y python3-pip
        elif command -v brew &> /dev/null; then
            brew install python3
        else
            print_error "Could not install pip automatically. Please install pip manually."
            exit 1
        fi
    fi
    
    # Check for git
    if ! command -v git &> /dev/null; then
        print_warning "git is not installed. Installing..."
        
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y git
        elif command -v yum &> /dev/null; then
            sudo yum install -y git
        elif command -v brew &> /dev/null; then
            brew install git
        else
            print_error "Could not install git automatically. Please install git manually."
            exit 1
        fi
    fi
    
    print_success "System dependencies checked"
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    # Upgrade pip
    $PYTHON_CMD -m pip install --upgrade pip
    
    # Install requirements
    if [ -f "requirements.txt" ]; then
        $PYTHON_CMD -m pip install -r requirements.txt
        print_success "Python dependencies installed"
    else
        print_error "requirements.txt not found"
        exit 1
    fi
}

# Install the framework
install_framework() {
    print_status "Installing NightStalker framework..."
    
    # Install in development mode
    $PYTHON_CMD setup.py develop
    
    print_success "NightStalker framework installed"
}

# Create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    
    mkdir -p config
    mkdir -p results
    mkdir -p payloads
    mkdir -p wordlists
    mkdir -p backups
    mkdir -p logs
    
    print_success "Directories created"
}

# Check optional external tools
check_external_tools() {
    print_status "Checking optional external tools..."
    
    tools=("nmap" "amass" "sqlmap" "nuclei" "hydra")
    missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            missing_tools+=($tool)
        else
            print_success "$tool found"
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_warning "Missing optional tools: ${missing_tools[*]}"
        print_status "You can install these tools manually for enhanced functionality"
    fi
}

# Set up environment
setup_environment() {
    print_status "Setting up environment..."
    
    # Create .env file if it doesn't exist
    if [ ! -f ".env" ]; then
        cat > .env << EOF
# NightStalker Environment Configuration
NIGHTSTALKER_HOME=$(pwd)
NIGHTSTALKER_CONFIG=config/campaign.yaml
NIGHTSTALKER_RESULTS=results
NIGHTSTALKER_LOGS=logs
NIGHTSTALKER_ENCRYPTION_KEY=$(openssl rand -hex 32)
EOF
        print_success "Environment file created"
    fi
    
    # Set executable permissions
    chmod +x cli.py
    chmod +x install.sh
    
    print_success "Environment setup completed"
}

# Display installation summary
show_summary() {
    echo
    print_success "NightStalker Framework Installation Complete!"
    echo
    echo "Installation Summary:"
    echo "====================="
    echo "• Framework installed in: $(pwd)"
    echo "• Python version: $PYTHON_VERSION"
    echo "• Configuration: config/campaign.yaml"
    echo "• Results directory: results/"
    echo "• Logs directory: logs/"
    echo
    echo "Usage Examples:"
    echo "==============="
    echo "• Build payload: nightstalker build --os windows --format exe"
    echo "• Run pentest: nightstalker pentest --target 192.168.1.0/24"
    echo "• Genetic fuzzing: nightstalker fuzz --target https://target.com"
    echo "• Environment management: nightstalker env --status"
    echo
    print_warning "IMPORTANT: This framework is for authorized security research only!"
    echo
    print_status "For more information, see README.md"
}

# Main installation function
main() {
    echo "NightStalker Framework Installation"
    echo "==================================="
    echo
    
    check_root
    check_python
    check_dependencies
    install_python_deps
    install_framework
    create_directories
    check_external_tools
    setup_environment
    show_summary
}

# Run main function
main "$@" 