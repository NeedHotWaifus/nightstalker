#!/bin/bash

# NightStalker Framework Uninstaller
# This script removes NightStalker from your system

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

# Function to confirm uninstallation
confirm_uninstall() {
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    🌙 NIGHTSTALKER UNINSTALLER                ║"
    echo "║                    Advanced Offensive Security Framework      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo
    print_warning "This will remove NightStalker from your system."
    echo
    echo "The following will be removed:"
    echo "  • NightStalker launcher (/usr/local/bin/nightstalker)"
    echo "  • NightStalker home directory (~/.nightstalker)"
    echo "  • Virtual environment (venv/)"
    echo "  • Environment variables from shell profiles"
    echo
    read -p "Are you sure you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Uninstallation cancelled."
        exit 0
    fi
}

# Function to remove launcher
remove_launcher() {
    print_status "Removing NightStalker launcher..."
    
    if [ -f "/usr/local/bin/nightstalker" ]; then
        sudo rm -f /usr/local/bin/nightstalker
        print_success "Launcher removed"
    else
        print_warning "Launcher not found"
    fi
}

# Function to remove home directory
remove_home_directory() {
    print_status "Removing NightStalker home directory..."
    
    NIGHTSTALKER_HOME="${NIGHTSTALKER_HOME:-$HOME/.nightstalker}"
    
    if [ -d "$NIGHTSTALKER_HOME" ]; then
        print_warning "Removing $NIGHTSTALKER_HOME"
        rm -rf "$NIGHTSTALKER_HOME"
        print_success "Home directory removed"
    else
        print_warning "Home directory not found"
    fi
}

# Function to remove virtual environment
remove_venv() {
    print_status "Removing virtual environment..."
    
    if [ -d "venv" ]; then
        rm -rf venv
        print_success "Virtual environment removed"
    else
        print_warning "Virtual environment not found"
    fi
}

# Function to remove environment variables
remove_env_vars() {
    print_status "Removing environment variables from shell profiles..."
    
    # Remove from bashrc
    if [ -f "$HOME/.bashrc" ]; then
        sed -i '/export NIGHTSTALKER_HOME/d' "$HOME/.bashrc"
        sed -i '/export NIGHTSTALKER_DIR/d' "$HOME/.bashrc"
        print_success "Removed from .bashrc"
    fi
    
    # Remove from zshrc
    if [ -f "$HOME/.zshrc" ]; then
        sed -i '/export NIGHTSTALKER_HOME/d' "$HOME/.zshrc"
        sed -i '/export NIGHTSTALKER_DIR/d' "$HOME/.zshrc"
        print_success "Removed from .zshrc"
    fi
    
    # Remove from profile
    if [ -f "$HOME/.profile" ]; then
        sed -i '/export NIGHTSTALKER_HOME/d' "$HOME/.profile"
        sed -i '/export NIGHTSTALKER_DIR/d' "$HOME/.profile"
        print_success "Removed from .profile"
    fi
}

# Function to clean up current session
cleanup_session() {
    print_status "Cleaning up current session..."
    
    # Unset environment variables
    unset NIGHTSTALKER_HOME
    unset NIGHTSTALKER_DIR
    
    print_success "Session cleaned up"
}

# Function to show uninstall summary
show_summary() {
    echo
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    🌙 NIGHTSTALKER UNINSTALLED                ║"
    echo "║                    Advanced Offensive Security Framework      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo
    print_success "NightStalker has been successfully uninstalled!"
    echo
    echo "The following were removed:"
    echo "  ✓ NightStalker launcher"
    echo "  ✓ NightStalker home directory"
    echo "  ✓ Virtual environment"
    echo "  ✓ Environment variables"
    echo
    print_warning "Note: The installation directory still exists."
    print_warning "To completely remove NightStalker, delete this directory:"
    echo "  $(pwd)"
    echo
    print_warning "To reinstall NightStalker, run: ./install.sh"
    echo
}

# Function to check if running as root
check_root() {
    if [ "$EUID" -eq 0 ]; then
        print_error "Please do not run this script as root"
        exit 1
    fi
}

# Main uninstallation function
main() {
    # Check if not running as root
    check_root
    
    # Confirm uninstallation
    confirm_uninstall
    
    # Remove components
    remove_launcher
    remove_home_directory
    remove_venv
    remove_env_vars
    cleanup_session
    
    # Show summary
    show_summary
}

# Run main function
main "$@" 