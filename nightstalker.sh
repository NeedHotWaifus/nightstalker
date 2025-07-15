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

# Auto-detect NightStalker directory
# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if we're in the NightStalker project root (has nightstalker/ subdirectory)
if [ -d "$SCRIPT_DIR/nightstalker" ]; then
    NIGHTSTALKER_DIR="$SCRIPT_DIR"
elif [ -d "$SCRIPT_DIR/../nightstalker" ]; then
    # Script might be in a subdirectory
    NIGHTSTALKER_DIR="$(dirname "$SCRIPT_DIR")"
else
    # Fallback to environment variable or default
    NIGHTSTALKER_DIR="${NIGHTSTALKER_HOME:-$HOME/path/to/nightstalker}"
fi

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
║                    🌙 NIGHTSTALKER LAUNCHER                  ║
║                    Advanced Offensive Security Framework      ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Function to check if directory exists
check_directory() {
    if [ ! -d "$NIGHTSTALKER_DIR" ]; then
        print_error "NightStalker directory not found: $NIGHTSTALKER_DIR"
        echo
        print_info "Auto-detection failed. Please set the NIGHTSTALKER_HOME environment variable:"
        print_info "  export NIGHTSTALKER_HOME=/path/to/your/nightstalker"
        print_info "  or run this script from the NightStalker project root directory"
        echo
        print_info "Current script location: $SCRIPT_DIR"
        print_info "Looking for nightstalker/ subdirectory in:"
        print_info "  - $SCRIPT_DIR"
        print_info "  - $(dirname "$SCRIPT_DIR")"
        return 1
    fi
    
    # Verify it's actually a NightStalker project
    if [ ! -d "$NIGHTSTALKER_DIR/nightstalker" ]; then
        print_error "Invalid NightStalker directory: $NIGHTSTALKER_DIR"
        print_info "Directory does not contain nightstalker/ subdirectory"
        return 1
    fi
    
    print_status "NightStalker directory found: $NIGHTSTALKER_DIR"
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
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 6 ]); then
        print_error "Python 3.6+ is required. Found: $PYTHON_VERSION"
        return 1
    fi
    
    print_status "Python $PYTHON_VERSION found"
    return 0
}

# Function to activate virtual environment
activate_venv() {
    local venv_paths=(
        "$NIGHTSTALKER_DIR/venv"
        "$NIGHTSTALKER_DIR/.venv"
        "$NIGHTSTALKER_DIR/env"
        "$NIGHTSTALKER_DIR/.env"
    )
    
    for venv_path in "${venv_paths[@]}"; do
        if [ -d "$venv_path" ] && [ -f "$venv_path/bin/activate" ]; then
            print_info "Activating virtual environment: $venv_path"
            source "$venv_path/bin/activate"
            return 0
        fi
    done
    
    print_warning "No virtual environment found. Using system Python."
    return 0
}

# Function to check NightStalker installation
check_nightstalker() {
    cd "$NIGHTSTALKER_DIR" || return 1
    
    # Check if nightstalker module exists
    if ! python3 -c "import nightstalker" 2>/dev/null; then
        print_error "NightStalker module not found"
        print_info "Please ensure NightStalker is properly installed:"
        print_info "  cd $NIGHTSTALKER_DIR"
        print_info "  pip install -r requirements.txt"
        return 1
    fi
    
    print_status "NightStalker module found"
    return 0
}

# Function to run NightStalker CLI
run_nightstalker() {
    cd "$NIGHTSTALKER_DIR" || return 1
    
    print_status "Starting NightStalker CLI..."
    echo
    
    # Run the CLI with all arguments passed to this script
    python3 -m nightstalker.cli "$@"
    
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        print_status "NightStalker CLI completed successfully"
    else
        print_error "NightStalker CLI exited with code: $exit_code"
    fi
    
    return $exit_code
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
    if [ -d "$NIGHTSTALKER_DIR/.git" ]; then
        cd "$NIGHTSTALKER_DIR" || return 1
        
        # Check if there are updates available
        git fetch --quiet 2>/dev/null
        if [ $? -eq 0 ]; then
            LOCAL=$(git rev-parse HEAD)
            REMOTE=$(git rev-parse origin/main 2>/dev/null || git rev-parse origin/master 2>/dev/null)
            
            if [ "$LOCAL" != "$REMOTE" ] && [ -n "$REMOTE" ]; then
                print_warning "Updates available for NightStalker"
                print_info "Run 'cd $NIGHTSTALKER_DIR && git pull' to update"
                echo
            fi
        fi
    fi
}

# Main function
main() {
    # Check for help flag
    if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
        show_help
        exit 0
    fi
    
    # Check for version flag
    if [[ "$1" == "--version" ]] || [[ "$1" == "-v" ]]; then
        print_banner
        echo "NightStalker CLI Launcher v1.0"
        echo "Advanced Offensive Security Framework"
        exit 0
    fi
    
    # Use NIGHTSTALKER_HOME environment variable if set
    if [ -n "$NIGHTSTALKER_HOME" ]; then
        NIGHTSTALKER_DIR="$NIGHTSTALKER_HOME"
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
    run_nightstalker "$@"
    exit $?
}

# Trap to handle script interruption
trap 'echo -e "\n${YELLOW}[!]${NC} NightStalker launcher interrupted"; exit 130' INT

# Run main function with all arguments
main "$@" 