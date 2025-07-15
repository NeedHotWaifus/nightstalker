#!/bin/bash

# NightStalker Launcher Installation Script
# Advanced Offensive Security Framework
# Version: 1.1

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
SCRIPT_NAME="nightstalker"
LAUNCHER_SCRIPT="nightstalker.sh"

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
║                🌙 NIGHTSTALKER INSTALLER                     ║
║                Advanced Offensive Security Framework          ║
║                    Auto-Detection & Setup                    ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Function to check if running as root
check_root() {
    if [ "$EUID" -eq 0 ]; then
        print_status "Running as root - proceeding with system-wide installation"
        return 0
    else
        print_warning "Not running as root. Some installation methods may require sudo."
        return 1
    fi
}

# Function to create necessary directories
create_directories() {
    print_info "Creating necessary directories..."
    
    # Create /usr/local/bin if it doesn't exist
    if [ ! -d "$INSTALL_DIR" ]; then
        print_info "Creating $INSTALL_DIR..."
        sudo mkdir -p "$INSTALL_DIR"
        sudo chmod 755 "$INSTALL_DIR"
    fi
    
    # Create user bin directory if needed
    local user_bin="$HOME/.local/bin"
    if [ ! -d "$user_bin" ]; then
        print_info "Creating $user_bin..."
        mkdir -p "$user_bin"
        chmod 755 "$user_bin"
    fi
    
    print_status "Directories created successfully"
}

# Function to detect NightStalker directory
detect_nightstalker_dir() {
    print_info "Auto-detecting NightStalker installation..." >&2
    
    local possible_paths=(
        "$HOME/nightstalker"
        "$HOME/ai pentest"
        "$HOME/Documents/ai pentest"
        "$HOME/Projects/nightstalker"
        "$HOME/git/nightstalker"
        "$PWD"
        "/opt/nightstalker"
        "/usr/local/nightstalker"
    )
    
    for path in "${possible_paths[@]}"; do
        if [ -d "$path" ] && [ -f "$path/nightstalker/cli.py" ]; then
            print_status "Found NightStalker at: $path" >&2
            echo "$path"
            return 0
        fi
    done
    
    print_warning "Auto-detection failed. Will prompt for manual input." >&2
    return 1
}

# Function to get NightStalker directory from user
get_nightstalker_dir() {
    local detected_dir
    detected_dir=$(detect_nightstalker_dir)
    
    if [ -n "$detected_dir" ]; then
        print_status "Detected NightStalker installation: $detected_dir" >&2
        read -p "Use this directory? (Y/n): " -n 1 -r
        echo >&2
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            echo "$detected_dir"
            return 0
        fi
    fi
    
    while true; do
        read -p "Enter NightStalker installation directory: " nightstalker_dir
        if [ -d "$nightstalker_dir" ] && [ -f "$nightstalker_dir/nightstalker/cli.py" ]; then
            echo "$nightstalker_dir"
            return 0
        else
            print_error "Invalid directory or NightStalker not found in: $nightstalker_dir" >&2
            print_info "Please ensure the directory contains the NightStalker framework" >&2
            print_info "Expected structure: <directory>/nightstalker/cli.py" >&2
        fi
    done
}

# Function to check and install dependencies
check_dependencies() {
    print_info "Checking system dependencies..."
    
    # Check for Python3
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed"
        print_info "Please install Python 3.6+ before continuing"
        return 1
    fi
    
    # Check Python version
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 6 ]); then
        print_error "Python 3.6+ is required. Found: $PYTHON_VERSION"
        return 1
    fi
    
    print_status "Python $PYTHON_VERSION found"
    
    # Check for pip
    if ! command -v pip3 &> /dev/null; then
        print_warning "pip3 not found. Attempting to install..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y python3-pip
        elif command -v yum &> /dev/null; then
            sudo yum install -y python3-pip
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y python3-pip
        else
            print_error "Could not install pip3 automatically. Please install it manually."
            return 1
        fi
    fi
    
    print_status "System dependencies check completed"
    return 0
}

# Function to setup NightStalker environment
setup_nightstalker_env() {
    local nightstalker_dir="$1"
    
    print_info "Setting up NightStalker environment..."
    
    cd "$nightstalker_dir" || return 1
    
    # Check if virtual environment exists
    if [ ! -d "venv" ] && [ ! -d ".venv" ]; then
        print_info "Creating virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment and install dependencies
    if [ -d "venv" ]; then
        print_info "Activating virtual environment and installing dependencies..."
        source venv/bin/activate
        
        # Install requirements if they exist
        if [ -f "requirements.txt" ]; then
            pip install -r requirements.txt
        else
            print_warning "No requirements.txt found. Installing basic dependencies..."
            pip install click colorama
        fi
        
        # Install NightStalker in development mode
        pip install -e .
        
        deactivate
    fi
    
    print_status "NightStalker environment setup completed"
    return 0
}

# Function to create launcher script
create_launcher_script() {
    local nightstalker_dir="$1"
    local temp_script="/tmp/nightstalker_launcher.sh"
    
    cat > "$temp_script" << EOF
#!/bin/bash

# NightStalker CLI Launcher Script
# Advanced Offensive Security Framework
# Version: 1.1

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# NightStalker project directory
NIGHTSTALKER_DIR="$nightstalker_dir"

# Function to print colored output
print_status() {
    echo -e "\${GREEN}[+]\${NC} \$1"
}

print_warning() {
    echo -e "\${YELLOW}[!]\${NC} \$1"
}

print_error() {
    echo -e "\${RED}[-]\${NC} \$1"
}

print_info() {
    echo -e "\${BLUE}[*]\${NC} \$1"
}

print_banner() {
    echo -e "\${PURPLE}"
    cat << "BANNER_EOF"
╔══════════════════════════════════════════════════════════════╗
║                    🌙 NIGHTSTALKER LAUNCHER                  ║
║                    Advanced Offensive Security Framework      ║
╚══════════════════════════════════════════════════════════════╝
BANNER_EOF
    echo -e "\${NC}"
}

# Function to check if directory exists
check_directory() {
    if [ ! -d "\$NIGHTSTALKER_DIR" ]; then
        print_error "NightStalker directory not found: \$NIGHTSTALKER_DIR"
        echo
        print_info "Please update the NIGHTSTALKER_DIR variable in this script"
        print_info "or set the NIGHTSTALKER_HOME environment variable."
        echo
        print_info "Example:"
        print_info "  export NIGHTSTALKER_HOME=/path/to/your/nightstalker"
        print_info "  or edit this script and change NIGHTSTALKER_DIR"
        return 1
    fi
    return 0
}

# Function to check Python installation
check_python() {
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed or not in PATH"
        print_info "Please install Python 3.6+ and try again"
        return 1
    fi
    
    # Check Python version
    PYTHON_VERSION=\$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PYTHON_MAJOR=\$(echo \$PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=\$(echo \$PYTHON_VERSION | cut -d. -f2)
    
    if [ "\$PYTHON_MAJOR" -lt 3 ] || ([ "\$PYTHON_MAJOR" -eq 3 ] && [ "\$PYTHON_MINOR" -lt 6 ]); then
        print_error "Python 3.6+ is required. Found: \$PYTHON_VERSION"
        return 1
    fi
    
    print_status "Python \$PYTHON_VERSION found"
    return 0
}

# Function to activate virtual environment
activate_venv() {
    local venv_paths=(
        "\$NIGHTSTALKER_DIR/venv"
        "\$NIGHTSTALKER_DIR/.venv"
        "\$NIGHTSTALKER_DIR/env"
        "\$NIGHTSTALKER_DIR/.env"
    )
    
    for venv_path in "\${venv_paths[@]}"; do
        if [ -d "\$venv_path" ] && [ -f "\$venv_path/bin/activate" ]; then
            print_info "Activating virtual environment: \$venv_path"
            source "\$venv_path/bin/activate"
            return 0
        fi
    done
    
    print_warning "No virtual environment found. Using system Python."
    return 0
}

# Function to check NightStalker installation
check_nightstalker() {
    cd "\$NIGHTSTALKER_DIR" || return 1
    
    # Check if nightstalker module exists
    if ! python3 -c "import nightstalker" 2>/dev/null; then
        print_error "NightStalker module not found"
        print_info "Please ensure NightStalker is properly installed:"
        print_info "  cd \$NIGHTSTALKER_DIR"
        print_info "  pip install -r requirements.txt"
        return 1
    fi
    
    print_status "NightStalker module found"
    return 0
}

# Function to run NightStalker CLI
run_nightstalker() {
    cd "\$NIGHTSTALKER_DIR" || return 1
    
    print_status "Starting NightStalker CLI..."
    echo
    
    # Run the CLI with all arguments passed to this script
    python3 -m nightstalker.cli "\$@"
    
    local exit_code=\$?
    
    if [ \$exit_code -eq 0 ]; then
        print_status "NightStalker CLI completed successfully"
    else
        print_error "NightStalker CLI exited with code: \$exit_code"
    fi
    
    return \$exit_code
}

# Function to show help
show_help() {
    print_banner
    echo "Usage: nightstalker [OPTIONS] [COMMAND]"
    echo
    echo "Available commands:"
    echo "  stealth build     - Build stealth reverse shell payload"
    echo "  stealth server    - Start C2 server"
    echo "  stealth demo      - Run stealth payload demonstration"
    echo "  payload build     - Build payloads"
    echo "  pentest           - Run penetration testing"
    echo "  redteam           - Red team operations"
    echo "  webred            - Web red teaming"
    echo "  c2                - Command & Control operations"
    echo "  help              - Show detailed help"
    echo
    echo "Examples:"
    echo "  nightstalker                    # Interactive menu"
    echo "  nightstalker stealth build      # Build stealth payload"
    echo "  nightstalker stealth server     # Start C2 server"
    echo "  nightstalker --help             # Show help"
    echo
    echo "For more information, visit the NightStalker documentation."
}

# Function to check for updates
check_updates() {
    if [ -d "\$NIGHTSTALKER_DIR/.git" ]; then
        cd "\$NIGHTSTALKER_DIR" || return 1
        
        # Check if there are updates available
        git fetch --quiet 2>/dev/null
        if [ \$? -eq 0 ]; then
            LOCAL=\$(git rev-parse HEAD)
            REMOTE=\$(git rev-parse origin/main 2>/dev/null || git rev-parse origin/master 2>/dev/null)
            
            if [ "\$LOCAL" != "\$REMOTE" ] && [ -n "\$REMOTE" ]; then
                print_warning "Updates available for NightStalker"
                print_info "Run 'cd \$NIGHTSTALKER_DIR && git pull' to update"
                echo
            fi
        fi
    fi
}

# Main function
main() {
    # Check for help flag
    if [[ "\$1" == "--help" ]] || [[ "\$1" == "-h" ]]; then
        show_help
        exit 0
    fi
    
    # Check for version flag
    if [[ "\$1" == "--version" ]] || [[ "\$1" == "-v" ]]; then
        print_banner
        echo "NightStalker CLI Launcher v1.1"
        echo "Advanced Offensive Security Framework"
        exit 0
    fi
    
    # Use NIGHTSTALKER_HOME environment variable if set
    if [ -n "\$NIGHTSTALKER_HOME" ]; then
        NIGHTSTALKER_DIR="\$NIGHTSTALKER_HOME"
    fi
    
    # Show banner
    print_banner
    
    # Check prerequisites
    print_info "Checking prerequisites..."
    
    if ! check_directory; then
        exit 1
    fi
    
    if ! check_python; then
        exit 1
    fi
    
    # Check for updates (non-blocking)
    check_updates
    
    # Activate virtual environment
    activate_venv
    
    # Check NightStalker installation
    if ! check_nightstalker; then
        exit 1
    fi
    
    # Run NightStalker CLI
    run_nightstalker "\$@"
    exit \$?
}

# Trap to handle script interruption
trap 'echo -e "\n\${YELLOW}[!]\${NC} NightStalker launcher interrupted"; exit 130' INT

# Run main function with all arguments
main "\$@"
EOF

    echo "$temp_script"
}

# Function to install launcher
install_launcher() {
    local nightstalker_dir="$1"
    local install_method="$2"
    
    if [ "$install_method" = "system" ]; then
        # System-wide installation
        if [ ! -w "$INSTALL_DIR" ] && [ "$EUID" -ne 0 ]; then
            print_error "Cannot write to $INSTALL_DIR. Try running with sudo."
            return 1
        fi
        
        local launcher_script=$(create_launcher_script "$nightstalker_dir")
        if [ "$EUID" -eq 0 ]; then
            cp "$launcher_script" "$INSTALL_DIR/$SCRIPT_NAME"
            chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
        else
            sudo cp "$launcher_script" "$INSTALL_DIR/$SCRIPT_NAME"
            sudo chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
        fi
        rm "$launcher_script"
        
        print_status "Installed system-wide: $INSTALL_DIR/$SCRIPT_NAME"
        
    elif [ "$install_method" = "user" ]; then
        # User-specific installation
        local user_bin="$HOME/.local/bin"
        mkdir -p "$user_bin"
        
        local launcher_script=$(create_launcher_script "$nightstalker_dir")
        cp "$launcher_script" "$user_bin/$SCRIPT_NAME"
        chmod +x "$user_bin/$SCRIPT_NAME"
        rm "$launcher_script"
        
        print_status "Installed for user: $user_bin/$SCRIPT_NAME"
        
        # Add to PATH if not already there
        if [[ ":$PATH:" != *":$user_bin:"* ]]; then
            print_info "Adding $user_bin to PATH..."
            echo "export PATH=\"\$PATH:$user_bin\"" >> "$HOME/.bashrc"
            print_info "Please restart your terminal or run: source ~/.bashrc"
        fi
        
    elif [ "$install_method" = "alias" ]; then
        # Alias installation
        local alias_line="alias nightstalker='cd \"$nightstalker_dir\" && python3 -m nightstalker.cli'"
        
        if ! grep -q "alias nightstalker=" "$HOME/.bashrc" 2>/dev/null; then
            echo "" >> "$HOME/.bashrc"
            echo "# NightStalker CLI Alias" >> "$HOME/.bashrc"
            echo "$alias_line" >> "$HOME/.bashrc"
            print_status "Added alias to ~/.bashrc"
        else
            print_warning "Alias already exists in ~/.bashrc"
        fi
        
        print_info "Please restart your terminal or run: source ~/.bashrc"
    fi
}

# Function to show installation options
show_installation_options() {
    echo
    print_info "Choose installation method:"
    echo "  1. System-wide installation (requires sudo, recommended)"
    echo "  2. User-specific installation (~/.local/bin)"
    echo "  3. Bash alias (adds to ~/.bashrc)"
    echo "  4. Cancel installation"
    echo
}

# Function to test installation
test_installation() {
    print_info "Testing installation..."
    
    if command -v nightstalker &> /dev/null; then
        print_status "NightStalker launcher found in PATH"
        
        # Test basic functionality
        if nightstalker --version &> /dev/null; then
            print_status "Installation test successful!"
            return 0
        else
            print_error "Installation test failed"
            return 1
        fi
    else
        print_error "NightStalker launcher not found in PATH"
        return 1
    fi
}

# Function to show post-installation instructions
show_post_install_instructions() {
    echo
    print_status "Installation completed successfully!"
    echo
    print_info "Usage examples:"
    echo "  nightstalker                    # Interactive menu"
    echo "  nightstalker stealth build      # Build stealth payload"
    echo "  nightstalker stealth server     # Start C2 server"
    echo "  nightstalker --help             # Show help"
    echo "  nightstalker --version          # Show version"
    echo
    print_info "For more information, visit the NightStalker documentation."
    echo
}

# Main installation function
main() {
    print_banner
    
    # Check if running as root
    local is_root=false
    if check_root; then
        is_root=true
    fi
    
    # Create necessary directories
    create_directories
    
    # Check dependencies
    if ! check_dependencies; then
        print_error "Dependency check failed. Please install required dependencies."
        exit 1
    fi
    
    # Get NightStalker directory
    print_info "Detecting NightStalker installation..."
    local nightstalker_dir=$(get_nightstalker_dir)
    
    if [ -z "$nightstalker_dir" ]; then
        print_error "Failed to get NightStalker directory"
        exit 1
    fi
    
    print_status "Using NightStalker directory: $nightstalker_dir"
    
    # Setup NightStalker environment
    if ! setup_nightstalker_env "$nightstalker_dir"; then
        print_error "Failed to setup NightStalker environment"
        exit 1
    fi
    
    # If running as root, automatically do system-wide installation
    if [ "$is_root" = true ]; then
        print_info "Running as root - performing system-wide installation..."
        install_launcher "$nightstalker_dir" "system"
    else
        # Show installation options for non-root users
        show_installation_options
        
        while true; do
            read -p "Select option (1-4): " choice
            case $choice in
                1)
                    print_info "Installing system-wide..."
                    install_launcher "$nightstalker_dir" "system"
                    break
                    ;;
                2)
                    print_info "Installing for current user..."
                    install_launcher "$nightstalker_dir" "user"
                    break
                    ;;
                3)
                    print_info "Creating bash alias..."
                    install_launcher "$nightstalker_dir" "alias"
                    break
                    ;;
                4)
                    print_info "Installation cancelled."
                    exit 0
                    ;;
                *)
                    print_error "Invalid option. Please select 1-4."
                    ;;
            esac
        done
    fi
    
    # Test installation
    if test_installation; then
        show_post_install_instructions
    else
        print_warning "Installation may not be working correctly."
        print_info "Please check the installation and try again."
    fi
}

# Run main function
main "$@"