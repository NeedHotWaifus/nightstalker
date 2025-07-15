#!/usr/bin/env python3
"""
NightStalker WebXF CLI - Unified Web Exploitation Framework
Combines the best features of NightStalker Web and WebXF
"""

import argparse
import sys
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
import traceback

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import core modules
from core.config import init_config, get_config
from core.logging import setup_logging, get_logger, log_scan_start, log_scan_complete, log_error
from core.utils import SystemUtils, NetworkUtils, get_timestamp

# Import tool modules
try:
    from modules.exploit.sqlmap_wrapper import SQLMapWrapper
    SQLMAP_AVAILABLE = True
except ImportError:
    SQLMAP_AVAILABLE = False
    SQLMapWrapper = None

try:
    from modules.exploit.nuclei_wrapper import NucleiWrapper
    NUCLEI_AVAILABLE = True
except ImportError:
    NUCLEI_AVAILABLE = False
    NucleiWrapper = None

try:
    from modules.exploit.xsstrike_wrapper import XSStrikeWrapper
    XSSTRIKE_AVAILABLE = True
except ImportError:
    XSSTRIKE_AVAILABLE = False
    XSStrikeWrapper = None

try:
    from modules.exploit.msf_wrapper import MetasploitWrapper
    MSF_AVAILABLE = True
except ImportError:
    MSF_AVAILABLE = False
    MetasploitWrapper = None

# Import other modules
try:
    from modules.recon import ReconManager
    RECON_AVAILABLE = True
except ImportError:
    RECON_AVAILABLE = False
    ReconManager = None

try:
    from modules.bruteforce import BruteforceManager
    BRUTEFORCE_AVAILABLE = True
except ImportError:
    BRUTEFORCE_AVAILABLE = False
    BruteforceManager = None

try:
    from modules.post import PostExploitManager
    POST_AVAILABLE = True
except ImportError:
    POST_AVAILABLE = False
    PostExploitManager = None

class NightStalkerWebXFCLI:
    """Unified CLI for NightStalker WebXF Framework"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize CLI with configuration"""
        self.config = init_config(config_path)
        self.logger = setup_logging(config_path)
        self.main_logger = get_logger("cli")
        
        # Initialize tool managers
        self.tools = self._initialize_tools()
        
        # Setup argument parser
        self.parser = self._setup_argument_parser()
    
    def _initialize_tools(self) -> Dict[str, Any]:
        """Initialize available tools"""
        tools = {}
        
        if SQLMAP_AVAILABLE:
            try:
                tools['sqlmap'] = SQLMapWrapper()
                self.main_logger.info("SQLMap wrapper initialized")
            except Exception as e:
                self.main_logger.error(f"Failed to initialize SQLMap: {e}")
        
        if NUCLEI_AVAILABLE:
            try:
                tools['nuclei'] = NucleiWrapper()
                self.main_logger.info("Nuclei wrapper initialized")
            except Exception as e:
                self.main_logger.error(f"Failed to initialize Nuclei: {e}")
        
        if XSSTRIKE_AVAILABLE:
            try:
                tools['xsstrike'] = XSStrikeWrapper()
                self.main_logger.info("XSStrike wrapper initialized")
            except Exception as e:
                self.main_logger.error(f"Failed to initialize XSStrike: {e}")
        
        if MSF_AVAILABLE:
            try:
                tools['metasploit'] = MetasploitWrapper()
                self.main_logger.info("Metasploit wrapper initialized")
            except Exception as e:
                self.main_logger.error(f"Failed to initialize Metasploit: {e}")
        
        return tools
    
    def _setup_argument_parser(self) -> argparse.ArgumentParser:
        """Setup argument parser with comprehensive options"""
        parser = argparse.ArgumentParser(
            description="NightStalker WebXF - Unified Web Exploitation Framework",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Run interactive menu
  nightstalker-webxf

  # Reconnaissance
  nightstalker-webxf recon --target example.com --all
  nightstalker-webxf recon --target example.com --subdomain --port --dir

  # Exploitation
  nightstalker-webxf exploit sqlmap --target http://example.com/vuln.php?id=1
  nightstalker-webxf exploit xsstrike --target http://example.com/search.php
  nightstalker-webxf exploit nuclei --target http://example.com
  nightstalker-webxf exploit msf --target 192.168.1.100 --exploit exploit/multi/handler
  nightstalker-webxf exploit all --target http://example.com --automated

  # Bruteforce
  nightstalker-webxf bruteforce --target http://example.com/login --wordlist users.txt --type http
  nightstalker-webxf bruteforce --target 192.168.1.100 --wordlist passwords.txt --type ssh

  # Tool management
  nightstalker-webxf tools install --all
  nightstalker-webxf tools update --all
  nightstalker-webxf tools list

  # Report generation
  nightstalker-webxf report --target example.com --format html --output report.html
            """
        )

        # Global options
        parser.add_argument('--config', help='Configuration file path')
        parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
        parser.add_argument('--quiet', '-q', action='store_true', help='Suppress output')
        parser.add_argument('--log-file', help='Log file path')
        parser.add_argument('--headless', action='store_true', help='Run in headless mode')
        parser.add_argument('--output', help='Output file for headless mode')
        parser.add_argument('--check-updates', action='store_true', help='Check for framework updates')
        parser.add_argument('--update', action='store_true', help='Update framework')
        parser.add_argument('--version', action='version', version='NightStalker WebXF 2.0.0')

        # Create subparsers
        subparsers = parser.add_subparsers(dest='command', help='Available commands')

        # Reconnaissance commands
        if RECON_AVAILABLE:
            self._setup_recon_parser(subparsers)
        
        # Exploitation commands
        self._setup_exploit_parser(subparsers)
        
        # Bruteforce commands
        if BRUTEFORCE_AVAILABLE:
            self._setup_bruteforce_parser(subparsers)
        
        # Post-exploitation commands
        if POST_AVAILABLE:
            self._setup_post_parser(subparsers)
        
        # Tool management commands
        self._setup_tools_parser(subparsers)
        
        # Report commands
        self._setup_report_parser(subparsers)

        return parser
    
    def _setup_recon_parser(self, subparsers: argparse._SubParsersAction) -> None:
        """Setup reconnaissance command parser"""
        recon_parser = subparsers.add_parser('recon', help='Reconnaissance operations')
        recon_parser.add_argument('--target', required=True, help='Target domain/IP')
        recon_parser.add_argument('--all', action='store_true', help='Run all reconnaissance tools')
        recon_parser.add_argument('--subdomain', action='store_true', help='Subdomain enumeration')
        recon_parser.add_argument('--port', action='store_true', help='Port scanning')
        recon_parser.add_argument('--dir', action='store_true', help='Directory enumeration')
        recon_parser.add_argument('--vuln', action='store_true', help='Vulnerability scanning')
        recon_parser.add_argument('--output-dir', help='Output directory')
        recon_parser.add_argument('--threads', type=int, default=10, help='Number of threads')
    
    def _setup_exploit_parser(self, subparsers: argparse._SubParsersAction) -> None:
        """Setup exploitation command parser"""
        exploit_parser = subparsers.add_parser('exploit', help='Exploitation operations')
        exploit_subparsers = exploit_parser.add_subparsers(dest='exploit_type', help='Exploitation types')

        # SQLMap exploitation
        if SQLMAP_AVAILABLE:
            sqlmap_parser = exploit_subparsers.add_parser('sqlmap', help='SQL injection exploitation')
            sqlmap_parser.add_argument('--target', required=True, help='Target URL')
            sqlmap_parser.add_argument('--parameter', help='Specific parameter to test')
            sqlmap_parser.add_argument('--dump', action='store_true', help='Dump databases')
            sqlmap_parser.add_argument('--risk', type=int, default=1, help='Risk level (1-3)')
            sqlmap_parser.add_argument('--output-dir', help='Output directory')

        # XSStrike exploitation
        if XSSTRIKE_AVAILABLE:
            xsstrike_parser = exploit_subparsers.add_parser('xsstrike', help='XSS detection and exploitation')
            xsstrike_parser.add_argument('--target', required=True, help='Target URL')
            xsstrike_parser.add_argument('--parameter', help='Specific parameter to test')
            xsstrike_parser.add_argument('--crawl', action='store_true', help='Crawl for XSS')
            xsstrike_parser.add_argument('--blind', action='store_true', help='Blind XSS detection')
            xsstrike_parser.add_argument('--output-dir', help='Output directory')

        # Nuclei exploitation
        if NUCLEI_AVAILABLE:
            nuclei_parser = exploit_subparsers.add_parser('nuclei', help='Template-based vulnerability scanning')
            nuclei_parser.add_argument('--target', required=True, help='Target URL/IP')
            nuclei_parser.add_argument('--severity', default='low,medium,high,critical', help='Severity levels')
            nuclei_parser.add_argument('--templates', help='Specific templates to use')
            nuclei_parser.add_argument('--update', action='store_true', help='Update templates')
            nuclei_parser.add_argument('--output-dir', help='Output directory')

        # Metasploit exploitation
        if MSF_AVAILABLE:
            msf_parser = exploit_subparsers.add_parser('msf', help='Metasploit exploitation')
            msf_parser.add_argument('--target', required=True, help='Target IP')
            msf_parser.add_argument('--exploit', help='Specific exploit to use')
            msf_parser.add_argument('--payload', help='Payload to use')
            msf_parser.add_argument('--lhost', help='Local host for reverse shell')
            msf_parser.add_argument('--lport', type=int, help='Local port for reverse shell')
            msf_parser.add_argument('--output-dir', help='Output directory')

        # Nmap exploitation
        nmap_parser = exploit_subparsers.add_parser('nmap', help='Network scanning and enumeration')
        nmap_parser.add_argument('--target', required=True, help='Target IP/range')
        nmap_parser.add_argument('--ports', help='Port range (e.g., 1-1000)')
        nmap_parser.add_argument('--scripts', help='NSE scripts to run')
        nmap_parser.add_argument('--output-dir', help='Output directory')

        # Comprehensive exploitation
        all_parser = exploit_subparsers.add_parser('all', help='Comprehensive exploitation')
        all_parser.add_argument('--target', required=True, help='Target URL/IP')
        all_parser.add_argument('--tools', help='Specific tools to use (comma-separated)')
        all_parser.add_argument('--automated', action='store_true', help='Run automated exploitation chain')
        all_parser.add_argument('--output-dir', help='Output directory')
    
    def _setup_bruteforce_parser(self, subparsers: argparse._SubParsersAction) -> None:
        """Setup bruteforce command parser"""
        bruteforce_parser = subparsers.add_parser('bruteforce', help='Bruteforce operations')
        bruteforce_parser.add_argument('--target', required=True, help='Target URL/IP')
        bruteforce_parser.add_argument('--wordlist', required=True, help='Wordlist file')
        bruteforce_parser.add_argument('--username', help='Username to test')
        bruteforce_parser.add_argument('--type', choices=['http', 'ssh', 'ftp', 'smtp'], default='http', help='Bruteforce type')
        bruteforce_parser.add_argument('--output-dir', help='Output directory')
        bruteforce_parser.add_argument('--threads', type=int, default=10, help='Number of threads')
    
    def _setup_post_parser(self, subparsers: argparse._SubParsersAction) -> None:
        """Setup post-exploitation command parser"""
        post_parser = subparsers.add_parser('post', help='Post-exploitation operations')
        post_parser.add_argument('--target', required=True, help='Target IP')
        post_parser.add_argument('--session', help='Session ID')
        post_parser.add_argument('--persistence', action='store_true', help='Establish persistence')
        post_parser.add_argument('--lateral', action='store_true', help='Lateral movement')
        post_parser.add_argument('--cleanup', action='store_true', help='Clean up traces')
        post_parser.add_argument('--output-dir', help='Output directory')
    
    def _setup_tools_parser(self, subparsers: argparse._SubParsersAction) -> None:
        """Setup tool management command parser"""
        tools_parser = subparsers.add_parser('tools', help='Tool management')
        tools_subparsers = tools_parser.add_subparsers(dest='tool_action', help='Tool actions')

        install_parser = tools_subparsers.add_parser('install', help='Install tools')
        install_parser.add_argument('--all', action='store_true', help='Install all tools')
        install_parser.add_argument('--tool', help='Specific tool to install')

        update_parser = tools_subparsers.add_parser('update', help='Update tools')
        update_parser.add_argument('--all', action='store_true', help='Update all tools')
        update_parser.add_argument('--tool', help='Specific tool to update')

        list_parser = tools_subparsers.add_parser('list', help='List available tools')
        list_parser.add_argument('--category', help='Filter by category')

        check_parser = tools_subparsers.add_parser('check', help='Check tool status')
        check_parser.add_argument('--all', action='store_true', help='Check all tools')
        check_parser.add_argument('--tool', help='Specific tool to check')
    
    def _setup_report_parser(self, subparsers: argparse._SubParsersAction) -> None:
        """Setup report command parser"""
        report_parser = subparsers.add_parser('report', help='Generate reports')
        report_parser.add_argument('--target', required=True, help='Target name')
        report_parser.add_argument('--format', choices=['html', 'pdf', 'json'], default='html', help='Report format')
        report_parser.add_argument('--output', help='Output file path')
    
    def run(self, args: Optional[List[str]] = None) -> int:
        """Run the CLI"""
        try:
            # Parse arguments
            parsed_args = self.parser.parse_args(args)
            
            # Handle global options
            if parsed_args.check_updates:
                return self._check_updates()
            
            if parsed_args.update:
                return self._update_framework()
            
            # Handle commands
            if not parsed_args.command:
                # No command specified, show interactive menu
                return self._show_interactive_menu()
            
            # Log scan start
            log_scan_start(parsed_args.command, parsed_args)
            
            # Route to appropriate handler
            if parsed_args.command == 'recon':
                result = self._handle_recon(parsed_args)
            elif parsed_args.command == 'exploit':
                result = self._handle_exploit(parsed_args)
            elif parsed_args.command == 'bruteforce':
                result = self._handle_bruteforce(parsed_args)
            elif parsed_args.command == 'post':
                result = self._handle_post(parsed_args)
            elif parsed_args.command == 'tools':
                result = self._handle_tools(parsed_args)
            elif parsed_args.command == 'report':
                result = self._handle_report(parsed_args)
            else:
                self.parser.print_help()
                result = 1
            
            # Log scan completion
            log_scan_complete(parsed_args.command, result == 0)
            
            return result
        
        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
            return 1
        except Exception as e:
            log_error("CLI execution failed", e)
            if self.config.get('debug', False):
                traceback.print_exc()
            return 1
    
    def _show_interactive_menu(self) -> int:
        """Show interactive menu"""
        try:
            print("\n=== NightStalker WebXF - Interactive Menu ===")
            print("1. Reconnaissance")
            print("2. Exploitation")
            print("3. Bruteforce")
            print("4. Post-Exploitation")
            print("5. Tool Management")
            print("6. Report Generation")
            print("7. Exit")
            
            while True:
                try:
                    choice = input("\nSelect option (1-7): ").strip()
                    
                    if choice == '1':
                        self._interactive_recon()
                    elif choice == '2':
                        self._interactive_exploit()
                    elif choice == '3':
                        self._interactive_bruteforce()
                    elif choice == '4':
                        self._interactive_post()
                    elif choice == '5':
                        self._interactive_tools()
                    elif choice == '6':
                        self._interactive_report()
                    elif choice == '7':
                        print("Goodbye!")
                        break
                    else:
                        print("Invalid choice. Please select 1-7.")
                
                except KeyboardInterrupt:
                    print("\nReturning to main menu...")
                    break
                except Exception as e:
                    print(f"Error: {e}")
            
            return 0
        
        except Exception as e:
            print(f"Interactive menu error: {e}")
            return 1
    
    def _interactive_recon(self) -> None:
        """Interactive reconnaissance menu"""
        print("\n=== Reconnaissance ===")
        target = input("Enter target (domain/IP): ").strip()
        if not target:
            return
        
        print("\nReconnaissance options:")
        print("1. All reconnaissance")
        print("2. Subdomain enumeration")
        print("3. Port scanning")
        print("4. Directory enumeration")
        print("5. Vulnerability scanning")
        
        choice = input("Select option (1-5): ").strip()
        
        # Create args object
        class Args:
            pass
        
        args = Args()
        args.target = target
        args.all = choice == '1'
        args.subdomain = choice in ['1', '2']
        args.port = choice in ['1', '3']
        args.dir = choice in ['1', '4']
        args.vuln = choice in ['1', '5']
        args.output_dir = None
        args.threads = 10
        
        self._handle_recon(args)
    
    def _interactive_exploit(self) -> None:
        """Interactive exploitation menu"""
        print("\n=== Exploitation ===")
        target = input("Enter target URL/IP: ").strip()
        if not target:
            return
        
        print("\nExploitation options:")
        print("1. SQLMap (SQL injection)")
        print("2. XSStrike (XSS detection)")
        print("3. Nuclei (vulnerability scanning)")
        print("4. Metasploit")
        print("5. Nmap")
        print("6. All tools")
        
        choice = input("Select option (1-6): ").strip()
        
        # Create args object
        class Args:
            pass
        
        args = Args()
        args.target = target
        args.exploit_type = {
            '1': 'sqlmap',
            '2': 'xsstrike',
            '3': 'nuclei',
            '4': 'msf',
            '5': 'nmap',
            '6': 'all'
        }.get(choice)
        
        if args.exploit_type:
            self._handle_exploit(args)
    
    def _interactive_bruteforce(self) -> None:
        """Interactive bruteforce menu"""
        print("\n=== Bruteforce ===")
        target = input("Enter target URL/IP: ").strip()
        if not target:
            return
        
        wordlist = input("Enter wordlist path: ").strip()
        if not wordlist:
            return
        
        print("\nBruteforce types:")
        print("1. HTTP authentication")
        print("2. SSH")
        print("3. FTP")
        print("4. SMTP")
        
        choice = input("Select type (1-4): ").strip()
        
        # Create args object
        class Args:
            pass
        
        args = Args()
        args.target = target
        args.wordlist = wordlist
        args.type = {
            '1': 'http',
            '2': 'ssh',
            '3': 'ftp',
            '4': 'smtp'
        }.get(choice, 'http')
        
        self._handle_bruteforce(args)
    
    def _interactive_tools(self) -> None:
        """Interactive tool management menu"""
        print("\n=== Tool Management ===")
        print("1. Install all tools")
        print("2. Update all tools")
        print("3. List tools")
        print("4. Check tool status")
        
        choice = input("Select option (1-4): ").strip()
        
        # Create args object
        class Args:
            pass
        
        args = Args()
        args.tool_action = {
            '1': 'install',
            '2': 'update',
            '3': 'list',
            '4': 'check'
        }.get(choice)
        args.all = choice in ['1', '2', '4']
        
        if args.tool_action:
            self._handle_tools(args)
    
    def _interactive_report(self) -> None:
        """Interactive report generation menu"""
        print("\n=== Report Generation ===")
        target = input("Enter target name: ").strip()
        if not target:
            return
        
        print("\nReport formats:")
        print("1. HTML")
        print("2. PDF")
        print("3. JSON")
        
        choice = input("Select format (1-3): ").strip()
        
        # Create args object
        class Args:
            pass
        
        args = Args()
        args.target = target
        args.format = {
            '1': 'html',
            '2': 'pdf',
            '3': 'json'
        }.get(choice, 'html')
        args.output = None
        
        self._handle_report(args)
    
    def _handle_recon(self, args: argparse.Namespace) -> int:
        """Handle reconnaissance operations"""
        try:
            if RECON_AVAILABLE:
                return self._run_recon(args.target, **vars(args))
            else:
                print("Reconnaissance module not available")
                return 1
        except Exception as e:
            log_error("Reconnaissance failed", e)
            return 1
    
    def _handle_exploit(self, args: argparse.Namespace) -> int:
        """Handle exploitation operations"""
        try:
            return self._run_exploit(args.target, args.exploit_type, **vars(args))
        except Exception as e:
            log_error("Exploitation failed", e)
            return 1
    
    def _handle_bruteforce(self, args: argparse.Namespace) -> int:
        """Handle bruteforce operations"""
        try:
            if BRUTEFORCE_AVAILABLE:
                return self._run_bruteforce(args.target, args.wordlist, **vars(args))
            else:
                print("Bruteforce module not available")
                return 1
        except Exception as e:
            log_error("Bruteforce failed", e)
            return 1
    
    def _handle_post(self, args: argparse.Namespace) -> int:
        """Handle post-exploitation operations"""
        try:
            if POST_AVAILABLE:
                return self._run_post(args.target, **vars(args))
            else:
                print("Post-exploitation module not available")
                return 1
        except Exception as e:
            log_error("Post-exploitation failed", e)
            return 1
    
    def _handle_tools(self, args: argparse.Namespace) -> int:
        """Handle tool management operations"""
        try:
            if args.tool_action == 'install':
                return self._run_tools_install(args.all, getattr(args, 'tool', None))
            elif args.tool_action == 'update':
                return self._run_tools_update(args.all, getattr(args, 'tool', None))
            elif args.tool_action == 'list':
                return self._run_tools_list(getattr(args, 'category', None))
            elif args.tool_action == 'check':
                return self._run_tools_check(args.all, getattr(args, 'tool', None))
            else:
                print("Invalid tool action")
                return 1
        except Exception as e:
            log_error("Tool management failed", e)
            return 1
    
    def _handle_report(self, args: argparse.Namespace) -> int:
        """Handle report generation"""
        try:
            return self._run_report(args.target, args.format, args.output)
        except Exception as e:
            log_error("Report generation failed", e)
            return 1
    
    def _run_recon(self, target: str, **kwargs) -> int:
        """Run reconnaissance operations"""
        print(f"Running reconnaissance on {target}")
        # Implementation would go here
        return 0
    
    def _run_exploit(self, target: str, exploit_type: str, **kwargs) -> int:
        """Run exploitation operations"""
        print(f"Running {exploit_type} exploitation on {target}")
        # Implementation would go here
        return 0
    
    def _run_bruteforce(self, target: str, wordlist: str, **kwargs) -> int:
        """Run bruteforce operations"""
        print(f"Running bruteforce on {target} with {wordlist}")
        # Implementation would go here
        return 0
    
    def _run_post(self, target: str, **kwargs) -> int:
        """Run post-exploitation operations"""
        print(f"Running post-exploitation on {target}")
        # Implementation would go here
        return 0
    
    def _run_tools_install(self, all_tools: bool = False, tool: str = None) -> int:
        """Install tools"""
        if all_tools:
            print("Installing all tools...")
        elif tool:
            print(f"Installing {tool}...")
        else:
            print("Please specify --all or --tool")
            return 1
        return 0
    
    def _run_tools_update(self, all_tools: bool = False, tool: str = None) -> int:
        """Update tools"""
        if all_tools:
            print("Updating all tools...")
        elif tool:
            print(f"Updating {tool}...")
        else:
            print("Please specify --all or --tool")
            return 1
        return 0
    
    def _run_tools_list(self, category: str = None) -> int:
        """List tools"""
        print("Available tools:")
        print("- SQLMap")
        print("- Nuclei")
        print("- XSStrike")
        print("- Metasploit")
        print("- Nmap")
        return 0
    
    def _run_tools_check(self, all_tools: bool = False, tool: str = None) -> int:
        """Check tool status"""
        if all_tools:
            print("Checking all tools...")
        elif tool:
            print(f"Checking {tool}...")
        else:
            print("Please specify --all or --tool")
            return 1
        return 0
    
    def _run_report(self, target: str, format: str = 'html', output: str = None) -> int:
        """Generate report"""
        print(f"Generating {format} report for {target}")
        if output:
            print(f"Output: {output}")
        return 0
    
    def _check_updates(self) -> int:
        """Check for framework updates"""
        print("Checking for framework updates...")
        return 0
    
    def _update_framework(self) -> int:
        """Update framework"""
        print("Updating framework...")
        return 0

def main():
    """Main entry point"""
    try:
        cli = NightStalkerWebXFCLI()
        sys.exit(cli.run())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 