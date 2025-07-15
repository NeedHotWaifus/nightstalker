#!/usr/bin/env python3
"""
NightStalker Configuration Manager
Interactive configuration management tool
"""

import sys
import os
import argparse
from config_loader import NightStalkerConfig, load_config

def print_banner():
    """Print NightStalker banner"""
    print("""
🌙 NightStalker Configuration Manager
=====================================
Advanced Offensive Security Framework
    """)

def show_config(config: NightStalkerConfig):
    """Display current configuration"""
    print("\n📋 Current Configuration:")
    print("=" * 40)
    
    # Framework info
    framework_name = config.get('framework.name', 'Unknown')
    framework_version = config.get('framework.version', 'Unknown')
    mode = config.get('framework.mode', 'Unknown')
    print(f"Framework: {framework_name} v{framework_version}")
    print(f"Mode: {mode}")
    
    # Exfiltration methods
    print("\n🚀 Exfiltration Methods:")
    primary_method = config.get_primary_exfiltration_method()
    enabled_methods = config.get_exfiltration_methods()
    print(f"Primary: {primary_method}")
    print(f"Enabled: {', '.join(enabled_methods) if enabled_methods else 'None'}")
    
    # Payload settings
    print("\n🔧 Payload Builder:")
    default_format = config.get('payload_builder.default_format', 'Unknown')
    compression = config.get('payload_builder.compression_enabled', False)
    encryption = config.get('payload_builder.encryption_enabled', False)
    print(f"Default format: {default_format}")
    print(f"Compression: {'Enabled' if compression else 'Disabled'}")
    print(f"Encryption: {'Enabled' if encryption else 'Disabled'}")
    
    # Stealth settings
    print("\n🕵️ Stealth Settings:")
    traffic_blending = config.get('stealth.traffic_blending.enabled', False)
    rate_limiting = config.get('stealth.rate_limiting.enabled', False)
    print(f"Traffic blending: {'Enabled' if traffic_blending else 'Disabled'}")
    print(f"Rate limiting: {'Enabled' if rate_limiting else 'Disabled'}")

def edit_exfiltration_config(config: NightStalkerConfig):
    """Edit exfiltration configuration"""
    print("\n🚀 Exfiltration Configuration Editor:")
    print("=" * 40)
    
    # Show current settings
    print("Current settings:")
    dns_enabled = config.is_exfiltration_enabled('dns')
    dns_domain = config.get('exfiltration.dns.domain', 'attacker.com')
    https_enabled = config.is_exfiltration_enabled('https')
    https_url = config.get('exfiltration.https.target_url', 'https://httpbin.org/post')
    
    print(f"DNS: {'Enabled' if dns_enabled else 'Disabled'} (Domain: {dns_domain})")
    print(f"HTTPS: {'Enabled' if https_enabled else 'Disabled'} (URL: {https_url})")
    
    # Get user input
    print("\nEnter new settings (press Enter to keep current):")
    
    new_dns_enabled = input(f"Enable DNS exfiltration? (y/n) [{('y' if dns_enabled else 'n')}]: ").lower()
    if new_dns_enabled in ['y', 'yes']:
        config.set('exfiltration.dns.enabled', True)
        new_domain = input(f"DNS domain [{dns_domain}]: ").strip()
        if new_domain:
            config.set('exfiltration.dns.domain', new_domain)
    elif new_dns_enabled in ['n', 'no']:
        config.set('exfiltration.dns.enabled', False)
    
    new_https_enabled = input(f"Enable HTTPS exfiltration? (y/n) [{('y' if https_enabled else 'n')}]: ").lower()
    if new_https_enabled in ['y', 'yes']:
        config.set('exfiltration.https.enabled', True)
        new_url = input(f"HTTPS URL [{https_url}]: ").strip()
        if new_url:
            config.set('exfiltration.https.target_url', new_url)
    elif new_https_enabled in ['n', 'no']:
        config.set('exfiltration.https.enabled', False)
    
    # Set primary method
    enabled_methods = config.get_exfiltration_methods()
    if enabled_methods:
        print(f"\nAvailable methods: {', '.join(enabled_methods)}")
        primary = input(f"Primary method [{config.get_primary_exfiltration_method()}]: ").strip()
        if primary in enabled_methods:
            config.set('exfiltration.primary_method', primary)
    
    # Save configuration
    if config.save_config():
        print("✅ Configuration saved successfully!")
    else:
        print("❌ Failed to save configuration")

def edit_payload_config(config: NightStalkerConfig):
    """Edit payload builder configuration"""
    print("\n🔧 Payload Builder Configuration Editor:")
    print("=" * 40)
    
    # Show current settings
    print("Current settings:")
    default_format = config.get('payload_builder.default_format', 'python')
    compression = config.get('payload_builder.compression_enabled', False)
    encryption = config.get('payload_builder.encryption_enabled', False)
    obfuscation = config.get('payload_builder.obfuscation_enabled', False)
    
    print(f"Default format: {default_format}")
    print(f"Compression: {'Enabled' if compression else 'Disabled'}")
    print(f"Encryption: {'Enabled' if encryption else 'Disabled'}")
    print(f"Obfuscation: {'Enabled' if obfuscation else 'Disabled'}")
    
    # Get user input
    print("\nEnter new settings (press Enter to keep current):")
    
    formats = ['python', 'powershell', 'bash', 'exe', 'dll']
    new_format = input(f"Default format [{default_format}]: ").strip()
    if new_format in formats:
        config.set('payload_builder.default_format', new_format)
    
    new_compression = input(f"Enable compression? (y/n) [{('y' if compression else 'n')}]: ").lower()
    if new_compression in ['y', 'yes']:
        config.set('payload_builder.compression_enabled', True)
    elif new_compression in ['n', 'no']:
        config.set('payload_builder.compression_enabled', False)
    
    new_encryption = input(f"Enable encryption? (y/n) [{('y' if encryption else 'n')}]: ").lower()
    if new_encryption in ['y', 'yes']:
        config.set('payload_builder.encryption_enabled', True)
    elif new_encryption in ['n', 'no']:
        config.set('payload_builder.encryption_enabled', False)
    
    new_obfuscation = input(f"Enable obfuscation? (y/n) [{('y' if obfuscation else 'n')}]: ").lower()
    if new_obfuscation in ['y', 'yes']:
        config.set('payload_builder.obfuscation_enabled', True)
    elif new_obfuscation in ['n', 'no']:
        config.set('payload_builder.obfuscation_enabled', False)
    
    # Save configuration
    if config.save_config():
        print("✅ Configuration saved successfully!")
    else:
        print("❌ Failed to save configuration")

def apply_profile(config: NightStalkerConfig, profile_name: str):
    """Apply a configuration profile"""
    print(f"\n🎯 Applying profile: {profile_name}")
    print("=" * 40)
    
    if config.apply_profile(profile_name):
        print("✅ Profile applied successfully!")
        show_config(config)
        
        save = input("\nSave configuration? (y/n): ").lower()
        if save in ['y', 'yes']:
            if config.save_config():
                print("✅ Configuration saved!")
            else:
                print("❌ Failed to save configuration")
    else:
        print(f"❌ Failed to apply profile: {profile_name}")

def list_profiles(config: NightStalkerConfig):
    """List available profiles"""
    profiles = config.config.get('profiles', {})
    
    if not profiles:
        print("❌ No profiles found in configuration")
        return
    
    print("\n📋 Available Profiles:")
    print("=" * 40)
    
    for name, profile in profiles.items():
        description = profile.get('description', 'No description')
        print(f"• {name}: {description}")

def validate_config(config: NightStalkerConfig):
    """Validate configuration"""
    print("\n🔍 Validating Configuration:")
    print("=" * 40)
    
    if config.validate_config():
        print("✅ Configuration is valid")
        
        # Check for common issues
        enabled_methods = config.get_exfiltration_methods()
        if not enabled_methods:
            print("⚠️  Warning: No exfiltration methods enabled")
        
        primary_method = config.get_primary_exfiltration_method()
        if primary_method not in enabled_methods:
            print(f"⚠️  Warning: Primary method '{primary_method}' is not enabled")
            
    else:
        print("❌ Configuration has errors")

def export_config(config: NightStalkerConfig, format: str = 'yaml'):
    """Export configuration"""
    print(f"\n📤 Exporting Configuration ({format.upper()}):")
    print("=" * 40)
    
    exported = config.export_config(format)
    if exported:
        print(exported)
        
        save_file = input(f"\nSave to file? (y/n): ").lower()
        if save_file in ['y', 'yes']:
            filename = input("Filename: ").strip()
            if filename:
                try:
                    with open(filename, 'w') as f:
                        f.write(exported)
                    print(f"✅ Configuration exported to {filename}")
                except Exception as e:
                    print(f"❌ Failed to export: {e}")
    else:
        print("❌ Failed to export configuration")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='NightStalker Configuration Manager')
    parser.add_argument('--config', default='config/nightstalker_config.yaml', 
                       help='Configuration file path')
    parser.add_argument('--show', action='store_true', help='Show current configuration')
    parser.add_argument('--edit-exfil', action='store_true', help='Edit exfiltration settings')
    parser.add_argument('--edit-payload', action='store_true', help='Edit payload settings')
    parser.add_argument('--profile', help='Apply configuration profile')
    parser.add_argument('--list-profiles', action='store_true', help='List available profiles')
    parser.add_argument('--validate', action='store_true', help='Validate configuration')
    parser.add_argument('--export', choices=['yaml', 'json'], help='Export configuration')
    
    args = parser.parse_args()
    
    # Load configuration
    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"❌ Failed to load configuration: {e}")
        return 1
    
    # Handle command line arguments
    if args.show:
        print_banner()
        show_config(config)
    elif args.edit_exfil:
        print_banner()
        edit_exfiltration_config(config)
    elif args.edit_payload:
        print_banner()
        edit_payload_config(config)
    elif args.profile:
        print_banner()
        apply_profile(config, args.profile)
    elif args.list_profiles:
        print_banner()
        list_profiles(config)
    elif args.validate:
        print_banner()
        validate_config(config)
    elif args.export:
        print_banner()
        export_config(config, args.export)
    else:
        # Interactive mode
        print_banner()
        
        while True:
            print("\n📋 Configuration Manager Menu:")
            print("1. Show current configuration")
            print("2. Edit exfiltration settings")
            print("3. Edit payload settings")
            print("4. Apply profile")
            print("5. List profiles")
            print("6. Validate configuration")
            print("7. Export configuration")
            print("8. Exit")
            
            choice = input("\nSelect option (1-8): ").strip()
            
            if choice == '1':
                show_config(config)
            elif choice == '2':
                edit_exfiltration_config(config)
            elif choice == '3':
                edit_payload_config(config)
            elif choice == '4':
                list_profiles(config)
                profile_name = input("Enter profile name: ").strip()
                if profile_name:
                    apply_profile(config, profile_name)
            elif choice == '5':
                list_profiles(config)
            elif choice == '6':
                validate_config(config)
            elif choice == '7':
                format_choice = input("Export format (yaml/json): ").strip().lower()
                if format_choice in ['yaml', 'json']:
                    export_config(config, format_choice)
                else:
                    print("❌ Invalid format")
            elif choice == '8':
                print("👋 Goodbye!")
                break
            else:
                print("❌ Invalid option")

if __name__ == "__main__":
    sys.exit(main()) 