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

logger = logging.getLogger(__name__)

class WebRedTeam:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = {}
        self.target_info = {}
        
    def scan(self, url: str, modules: List[str] = None) -> Dict[str, Any]:
        """Comprehensive web reconnaissance and enumeration"""
        print(f"[WebRed] Starting comprehensive scan of {url}")
        
        if modules is None or 'all' in modules:
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
    
    def exploit(self, url: str, exploit_type: str, payload: str = None) -> Dict[str, Any]:
        """Execute web exploits with post-exploitation"""
        print(f"[WebRed] Executing {exploit_type} exploit on {url}")
        
        exploit_results = {
            'url': url,
            'exploit_type': exploit_type,
            'timestamp': time.time(),
            'success': False,
            'post_exploitation': {}
        }
        
        try:
            if exploit_type == 'sqlmap':
                exploit_results.update(self._sqlmap_exploit(url, payload))
            elif exploit_type == 'xss':
                exploit_results.update(self._xss_exploit(url, payload))
            elif exploit_type == 'lfi':
                exploit_results.update(self._lfi_exploit(url, payload))
            elif exploit_type == 'rfi':
                exploit_results.update(self._rfi_exploit(url, payload))
            elif exploit_type == 'upload':
                exploit_results.update(self._upload_exploit(url, payload))
            else:
                exploit_results['error'] = f"Unknown exploit type: {exploit_type}"
                
        except Exception as e:
            exploit_results['error'] = str(e)
        
        return exploit_results
    
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
    def _sqlmap_exploit(self, url: str, payload: str = None) -> Dict[str, Any]:
        """Execute SQLMap exploitation"""
        return {'method': 'sqlmap', 'status': 'placeholder'}
    
    def _xss_exploit(self, url: str, payload: str = None) -> Dict[str, Any]:
        """Execute XSS exploitation"""
        return {'method': 'xss', 'status': 'placeholder'}
    
    def _lfi_exploit(self, url: str, payload: str = None) -> Dict[str, Any]:
        """Execute LFI exploitation"""
        return {'method': 'lfi', 'status': 'placeholder'}
    
    def _rfi_exploit(self, url: str, payload: str = None) -> Dict[str, Any]:
        """Execute RFI exploitation"""
        return {'method': 'rfi', 'status': 'placeholder'}
    
    def _upload_exploit(self, url: str, payload: str = None) -> Dict[str, Any]:
        """Execute file upload exploitation"""
        return {'method': 'upload', 'status': 'placeholder'}
    
    # Placeholder methods for vulnerability testing
    def _check_sql_injection(self, url: str) -> Dict[str, Any]:
        return {'vulnerable': False, 'method': 'placeholder'}
    
    def _check_xss(self, url: str) -> Dict[str, Any]:
        return {'vulnerable': False, 'method': 'placeholder'}
    
    def _check_lfi(self, url: str) -> Dict[str, Any]:
        return {'vulnerable': False, 'method': 'placeholder'}
    
    def _check_rfi(self, url: str) -> Dict[str, Any]:
        return {'vulnerable': False, 'method': 'placeholder'}
    
    def _check_open_redirect(self, url: str) -> Dict[str, Any]:
        return {'vulnerable': False, 'method': 'placeholder'}
    
    def _check_ssrf(self, url: str) -> Dict[str, Any]:
        return {'vulnerable': False, 'method': 'placeholder'}
    
    def _check_csrf(self, url: str) -> Dict[str, Any]:
        return {'vulnerable': False, 'method': 'placeholder'}
    
    # Placeholder methods for advanced enumeration
    def _find_endpoints(self, url: str) -> Dict[str, Any]:
        return {'endpoints': [], 'method': 'placeholder'}
    
    def _find_parameters(self, url: str) -> Dict[str, Any]:
        return {'parameters': [], 'method': 'placeholder'}
    
    def _find_backup_files(self, url: str) -> Dict[str, Any]:
        return {'backup_files': [], 'method': 'placeholder'}
    
    def _find_version_info(self, url: str) -> Dict[str, Any]:
        return {'version_info': {}, 'method': 'placeholder'}
    
    def _analyze_error_pages(self, url: str) -> Dict[str, Any]:
        return {'error_pages': [], 'method': 'placeholder'}
    
    # Placeholder methods for post-exploitation
    def _check_sudo_privileges(self) -> Dict[str, Any]:
        return {'sudo_access': False, 'method': 'placeholder'}
    
    def _find_suid_binaries(self) -> Dict[str, Any]:
        return {'suid_binaries': [], 'method': 'placeholder'}
    
    def _check_capabilities(self) -> Dict[str, Any]:
        return {'capabilities': [], 'method': 'placeholder'}
    
    def _check_kernel_vulnerabilities(self) -> Dict[str, Any]:
        return {'kernel_vulns': [], 'method': 'placeholder'}
    
    def _check_cron_jobs(self) -> Dict[str, Any]:
        return {'cron_jobs': [], 'method': 'placeholder'}
    
    def _check_env_variables(self) -> Dict[str, Any]:
        return {'env_vars': {}, 'method': 'placeholder'}
    
    def _lateral_movement(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        return {'movement': 'placeholder'}
    
    def _data_exfiltration(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        return {'exfiltration': 'placeholder'}
    
    def _establish_persistence(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        return {'persistence': 'placeholder'}
    
    # Placeholder methods for root access
    def _try_kernel_exploits(self) -> Dict[str, Any]:
        return {'kernel_exploits': 'placeholder'}
    
    def _try_sudo_exploitation(self) -> Dict[str, Any]:
        return {'sudo_exploitation': 'placeholder'}
    
    def _try_suid_exploitation(self) -> Dict[str, Any]:
        return {'suid_exploitation': 'placeholder'}
    
    def _try_capability_exploitation(self) -> Dict[str, Any]:
        return {'capability_exploitation': 'placeholder'}
    
    def _try_cron_exploitation(self) -> Dict[str, Any]:
        return {'cron_exploitation': 'placeholder'}
    
    def _try_service_exploitation(self) -> Dict[str, Any]:
        return {'service_exploitation': 'placeholder'}
    
    # Placeholder methods for trace clearing
    def _clear_arp_cache(self) -> Dict[str, Any]:
        return {'arp_cache': 'cleared'}
    
    def _clear_connection_history(self) -> Dict[str, Any]:
        return {'connection_history': 'cleared'}
    
    def _clear_dns_cache(self) -> Dict[str, Any]:
        return {'dns_cache': 'cleared'}
    
    # Additional detection methods
    def _detect_frameworks(self, response) -> List[str]:
        return []
    
    def _detect_cms(self, response) -> List[str]:
        return []
    
    def _detect_languages(self, response) -> List[str]:
        return []
    
    def _detect_databases(self, response) -> List[str]:
        return []
    
    def _detect_web_servers(self, response) -> List[str]:
        return []
    
    def _check_security_headers(self, response) -> Dict[str, Any]:
        return {}
    
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