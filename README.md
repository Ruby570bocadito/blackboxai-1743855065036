# Cybersecurity Tool for Kali Linux

## Features
- **Port Scanner**: Scan TCP ports on target IPs (`--port-scan`)
- **Ping Sweep**: Discover active hosts in a subnet (`--ping-sweep`) 
- **HTTP Header Analyzer**:
  - Full header inspection
  - Security header analysis with color coding
  - Automatic security scoring (0-100%)
- **Banner Grabbing**: Service identification from open ports (`--banner-grab`)

## Installation
```bash
git clone [repository_url]
cd [repository_directory]
python3 -m pip install requests
```

## Usage Examples
```bash
# Interactive menu
python3 cybersecurity_tool.py

# Command-line mode examples:
# Scan ports 20-100 on localhost
python3 cybersecurity_tool.py --port-scan 127.0.0.1 20-100

# Check website security headers
python3 cybersecurity_tool.py --http-headers https://example.com

# Ping sweep a /24 subnet
python3 cybersecurity_tool.py --ping-sweep 192.168.1
```

## Requirements
- Python 3.6+
- Kali Linux (recommended)
- Internet connection (for HTTP checks)

## Legal Notice
⚠️ Use only on networks you own or have explicit permission to test. Unauthorized scanning may violate laws.