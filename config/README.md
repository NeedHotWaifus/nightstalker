# NightStalker Configuration System

The NightStalker framework uses a comprehensive YAML-based configuration system that allows you to customize all aspects of the framework's behavior.

## Quick Start

1. **Copy the example configuration:**
   ```bash
   cp nightstalker_config.example.yaml nightstalker_config.yaml
   ```

2. **Edit the configuration:**
   ```bash
   python manage_config.py
   ```

3. **Or use command-line options:**
   ```bash
   python manage_config.py --show                    # View current config
   python manage_config.py --edit-exfil             # Edit exfiltration settings
   python manage_config.py --edit-payload           # Edit payload settings
   python manage_config.py --profile stealth        # Apply stealth profile
   python manage_config.py --validate               # Validate configuration
   ```

## Configuration Structure

### Framework Settings
```yaml
framework:
  name: "NightStalker"
  version: "1.0.0"
  mode: "stealth"  # stealth, aggressive, research
  log_level: "INFO"  # DEBUG, INFO, WARNING, ERROR
```

### Exfiltration Configuration
The framework supports multiple exfiltration methods:

#### DNS Exfiltration (No server required)
```yaml
exfiltration:
  primary_method: "dns"
  dns:
    enabled: true
    domain: "your-domain.com"  # Replace with your domain
    chunk_size: 50
    delay_between_chunks: 1.0
```

#### HTTPS Exfiltration
```yaml
exfiltration:
  https:
    enabled: true
    target_url: "https://httpbin.org/post"  # Test endpoint
    headers:
      User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

#### GitHub Gist Exfiltration
```yaml
exfiltration:
  github_gist:
    enabled: true
    gist_id: "your-gist-id"  # Your private gist ID
    token: "your-github-token"  # Your GitHub personal access token
```

#### Telegram Bot Exfiltration
```yaml
exfiltration:
  telegram:
    enabled: true
    bot_token: "your-bot-token"  # From @BotFather
    chat_id: "your-chat-id"  # Your chat ID
```

### Payload Builder Configuration
```yaml
payload_builder:
  default_format: "python"  # python, powershell, bash, exe, dll
  compression_enabled: false
  encryption_enabled: false
  obfuscation_enabled: false
```

### Stealth Configuration
```yaml
stealth:
  traffic_blending:
    enabled: true
    user_agents:
      - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  rate_limiting:
    enabled: true
    requests_per_minute: 10
    delay_between_requests: 1.0
```

## Configuration Profiles

The framework includes pre-configured profiles for different scenarios:

### Stealth Profile
```yaml
profiles:
  stealth:
    exfiltration:
      primary_method: "dns"
      dns:
        enabled: true
      https:
        enabled: false
    stealth:
      traffic_blending:
        enabled: true
      rate_limiting:
        enabled: true
        requests_per_minute: 5
```

### Aggressive Profile
```yaml
profiles:
  aggressive:
    exfiltration:
      primary_method: "https"
      https:
        enabled: true
      dns:
        enabled: true
    stealth:
      rate_limiting:
        enabled: false
```

## Using the Configuration Manager

### Interactive Mode
Run the configuration manager without arguments for interactive mode:
```bash
python manage_config.py
```

### Command-Line Options
- `--show`: Display current configuration
- `--edit-exfil`: Edit exfiltration settings
- `--edit-payload`: Edit payload builder settings
- `--profile <name>`: Apply a configuration profile
- `--list-profiles`: List available profiles
- `--validate`: Validate configuration
- `--export <format>`: Export configuration (yaml/json)

### Examples

**View current configuration:**
```bash
python manage_config.py --show
```

**Edit exfiltration settings:**
```bash
python manage_config.py --edit-exfil
```

**Apply stealth profile:**
```bash
python manage_config.py --profile stealth
```

**Validate configuration:**
```bash
python manage_config.py --validate
```

**Export configuration:**
```bash
python manage_config.py --export yaml
```

## Configuration API

You can also use the configuration system programmatically:

```python
from config_loader import load_config

# Load configuration
config = load_config()

# Get specific values
domain = config.get('exfiltration.dns.domain', 'default.com')
enabled_methods = config.get_exfiltration_methods()

# Set values
config.set('exfiltration.dns.domain', 'new-domain.com')
config.save_config()

# Apply profiles
config.apply_profile('stealth')

# Validate configuration
if config.validate_config():
    print("Configuration is valid")
```

## Exfiltration Setup Guide

### DNS Exfiltration (Recommended for beginners)
1. Register a domain (e.g., `your-domain.com`)
2. Set up DNS logging on your domain provider
3. Configure the domain in your config:
   ```yaml
   exfiltration:
     dns:
       domain: "your-domain.com"
   ```

### HTTPS Exfiltration
1. Use a test endpoint like `https://httpbin.org/post`
2. Or set up your own server
3. Configure in your config:
   ```yaml
   exfiltration:
     https:
       target_url: "https://your-server.com/collect"
   ```

### GitHub Gist Exfiltration
1. Create a GitHub personal access token
2. Create a private gist
3. Configure in your config:
   ```yaml
   exfiltration:
     github_gist:
       gist_id: "your-gist-id"
       token: "your-github-token"
   ```

### Telegram Bot Exfiltration
1. Create a bot with @BotFather
2. Get your chat ID
3. Configure in your config:
   ```yaml
   exfiltration:
     telegram:
       bot_token: "your-bot-token"
       chat_id: "your-chat-id"
   ```

## Security Considerations

1. **Never commit sensitive configuration to version control**
2. **Use environment variables for sensitive data**
3. **Rotate tokens and credentials regularly**
4. **Use different domains/endpoints for different operations**
5. **Enable stealth features for production use**

## Troubleshooting

### Configuration not found
If you get "Configuration file not found", copy the example:
```bash
cp nightstalker_config.example.yaml nightstalker_config.yaml
```

### Validation errors
Run validation to check for issues:
```bash
python manage_config.py --validate
```

### Import errors
Make sure you have the required dependencies:
```bash
pip install pyyaml
```

## File Structure

```
config/
├── nightstalker_config.yaml          # Main configuration file
├── nightstalker_config.example.yaml  # Example configuration
├── config_loader.py                  # Configuration loader
├── manage_config.py                  # Configuration manager
└── README.md                         # This file
```

## Advanced Configuration

For advanced users, the configuration system supports:

- **Custom payload templates**
- **Multiple exfiltration channels**
- **Stealth profiles**
- **Rate limiting and traffic blending**
- **Custom user agents**
- **Encryption and obfuscation settings**

See the full configuration file for all available options. 