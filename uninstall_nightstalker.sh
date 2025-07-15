#!/bin/bash

# NightStalker Launcher Uninstall Script
# Advanced Offensive Security Framework
# Version: 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Installation paths to check
INSTALL_PATHS=(
    "/usr/local/bin/nightstalker"
    "$HOME/.local/bin/nightstalker"
    "/usr/bin/nightstalker"
)

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
║              🌙 NIGHTSTALKER UNINSTALLER                     ║
║              Advanced Offensive Security Framework            ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Function to find installed launcher
find_launcher() {
    local found_paths=()
    
    for path in "${INSTALL_PATHS[@]}"; do
        if [ -f "$path" ]; then
            found_paths+=("$path")
        fi
    done
    
    echo "${found_paths[@]}"
}

# Function to remove launcher file
remove_launcher_file() {
    local file_path="$1"
    
    if [ -f "$file_path" ]; then
        if [[ "$file_path" == /usr* ]] && [ "$EUID" -ne 0 ]; then
            print_info "Removing system-wide installation: $file_path"
            sudo rm "$file_path"
        else
            print_info "Removing user installation: $file_path"
            rm "$file_path"
        fi
        
        if [ $? -eq 0 ]; then
            print_status "Successfully removed: $file_path"
            return 0
        else
            print_error "Failed to remove: $file_path"
            return 1
        fi
    fi
    
    return 0
}

# Function to remove bash alias
remove_bash_alias() {
    local bashrc_file="$HOME/.bashrc"
    local temp_file="/tmp/bashrc_temp"
    
    if [ -f "$bashrc_file" ]; then
        print_info "Checking for NightStalker aliases in $bashrc_file"
        
        # Create backup
        cp "$bashrc_file" "$bashrc_file.backup.$(date +%Y%m%d_%H%M%S)"
        
        # Remove alias lines
        grep -v "alias nightstalker=" "$bashrc_file" > "$temp_file"
        
        if [ $? -eq 0 ]; then
            mv "$temp_file" "$bashrc_file"
            print_status "Removed NightStalker aliases from $bashrc_file"
            print_info "Backup created: $bashrc_file.backup.*"
            return 0
        else
            print_error "Failed to remove aliases from $bashrc_file"
            rm -f "$temp_file"
            return 1
        fi
    fi
    
    return 0
}

# Function to check for environment variables
check_env_vars() {
    local env_vars=("NIGHTSTALKER_HOME")
    local found_vars=()
    
    for var in "${env_vars[@]}"; do
        if [ -n "${!var}" ]; then
            found_vars+=("$var")
        fi
    done
    
    if [ ${#found_vars[@]} -gt 0 ]; then
        print_warning "Found environment variables:"
        for var in "${found_vars[@]}"; do
            print_info "  $var=${!var}"
        done
        
        echo
        read -p "Remove these from shell profiles? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            remove_env_vars "${found_vars[@]}"
        fi
    fi
}

# Function to remove environment variables
remove_env_vars() {
    local vars=("$@")
    local shell_profiles=("$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zshrc")
    
    for profile in "${shell_profiles[@]}"; do
        if [ -f "$profile" ]; then
            local temp_file="/tmp/profile_temp"
            local modified=false
            
            cp "$profile" "$profile.backup.$(date +%Y%m%d_%H%M%S)"
            
            # Start with original file
            cp "$profile" "$temp_file"
            
            # Remove each variable
            for var in "${vars[@]}"; do
                if grep -q "export $var=" "$temp_file"; then
                    grep -v "export $var=" "$temp_file" > "${temp_file}.new"
                    mv "${temp_file}.new" "$temp_file"
                    modified=true
                fi
            done
            
            if [ "$modified" = true ]; then
                mv "$temp_file" "$profile"
                print_status "Removed environment variables from $profile"
                print_info "Backup created: $profile.backup.*"
            else
                rm -f "$temp_file"
            fi
        fi
    done
}

# Function to show uninstall summary
show_summary() {
    echo
    print_status "Uninstallation Summary:"
    echo "  - Launcher files removed: $1"
    echo "  - Bash aliases removed: $2"
    echo "  - Environment variables checked: $3"
    echo
    print_info "To complete the uninstallation:"
    print_info "  1. Restart your terminal or run: source ~/.bashrc"
    print_info "  2. Remove any remaining NightStalker directories manually"
    print_info "  3. Remove Python packages if desired: pip uninstall nightstalker"
    echo
}

# Function to show help
show_help() {
    print_banner
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  --help, -h     Show this help message"
    echo "  --force, -f    Force removal without confirmation"
    echo "  --all, -a      Remove all traces (files, aliases, env vars)"
    echo
    echo "This script will remove the NightStalker launcher from your system."
    echo "It will detect and remove:"
    echo "  - Launcher files from common installation locations"
    echo "  - Bash aliases from ~/.bashrc"
    echo "  - Environment variables (with confirmation)"
    echo
}

# Main uninstall function
main() {
    local force=false
    local remove_all=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_help
                exit 0
                ;;
            --force|-f)
                force=true
                shift
                ;;
            --all|-a)
                remove_all=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    print_banner
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root. This will remove system-wide installations."
    fi
    
    # Find installed launchers
    print_info "Searching for NightStalker launcher installations..."
    local found_launchers=($(find_launcher))
    
    if [ ${#found_launchers[@]} -eq 0 ]; then
        print_warning "No NightStalker launcher found in common locations."
        print_info "Checking PATH for any nightstalker command..."
        
        if command -v nightstalker &> /dev/null; then
            local launcher_path=$(which nightstalker)
            print_info "Found launcher at: $launcher_path"
            found_launchers=("$launcher_path")
        else
            print_info "No nightstalker command found in PATH."
        fi
    fi
    
    # Show what will be removed
    if [ ${#found_launchers[@]} -gt 0 ]; then
        echo
        print_info "Found launcher installations:"
        for launcher in "${found_launchers[@]}"; do
            echo "  - $launcher"
        done
    fi
    
    # Confirm uninstallation
    if [ "$force" != true ]; then
        echo
        read -p "Continue with uninstallation? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Uninstallation cancelled."
            exit 0
        fi
    fi
    
    # Remove launcher files
    local files_removed=0
    for launcher in "${found_launchers[@]}"; do
        if remove_launcher_file "$launcher"; then
            ((files_removed++))
        fi
    done
    
    # Remove bash aliases
    local aliases_removed=false
    if remove_bash_alias; then
        aliases_removed=true
    fi
    
    # Check environment variables
    local env_checked=false
    if [ "$remove_all" = true ]; then
        check_env_vars
        env_checked=true
    fi
    
    # Show summary
    show_summary "$files_removed" "$aliases_removed" "$env_checked"
    
    print_status "Uninstallation completed!"
    print_info "Please restart your terminal for changes to take effect."
}

# Trap to handle script interruption
trap 'echo -e "\n${YELLOW}[!]${NC} Uninstallation interrupted"; exit 130' INT

# Run main function
main "$@" 