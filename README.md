# MCP Recon

A comprehensive Model Context Protocol (MCP) server for web security reconnaissance and analysis. This toolkit provides cybersecurity professionals with essential reconnaissance capabilities through Python-native implementations, following the standard cybersecurity reconnaissance methodology.

## 🚀 Features

### 📊 **1. Information Gathering (Passive Reconnaissance)**
- **WHOIS Information**: Domain registration and ownership details
- **Domain History**: Reputation and historical data analysis

### 🔍 **2. DNS Analysis (Infrastructure Discovery)**
- **DNS Records Lookup**: Comprehensive DNS enumeration (A, AAAA, MX, NS, TXT, SPF, DMARC)
- **Reverse DNS Lookup**: IP to hostname resolution
- **Passive Subdomain Enumeration**: Certificate Transparency logs discovery via crt.sh (stealth)
- **Active Subdomain Enumeration**: DNS brute-force discovery using wordlist from subdomains.txt

### 🌐 **3. Network Reconnaissance (Active Scanning)**
- **IP Information**: Geolocation, ISP, and network details
- **Alive Check**: HTTP/HTTPS connectivity testing with response analysis
- **Port Scanning**: Advanced Nmap integration with multiple scan modes

### 🔒 **4. Web Application Analysis (Application Layer)**
- **TLS Certificate Analysis**: SSL/TLS certificate inspection and validation
- **HTTP Headers Analysis**: Security headers assessment and information disclosure detection
- **Technology Detection**: Web framework and technology fingerprinting
- **URL Extraction**: Web crawling and link discovery

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

## 🛠 Installation

### Prerequisites

- **Python 3.10+**
- **UV Package Manager** (automatically installed by script)
- **Nmap** (automatically installed by script)

### Quick Installation

#### Windows (PowerShell)
```powershell
.\install.ps1
```

#### Linux/macOS
```bash
chmod +x install.sh
./install.sh
```

### Claude Desktop Configuration

Add this configuration to your Claude Desktop settings to connect the MCP Web Reconnaissance Server:

#### Windows Configuration
```json
{
  "mcpServers": {
    "recon": {
      "command": "C:\\Users\\YOUR_USERNAME\\.local\\bin\\uv.exe",
      "args": [
        "--directory",
        "C:\\Users\\YOUR_USERNAME\\path\\to\\MCP_Recon",
        "run",
        "python",
        "main.py"
      ]
    }
  }
}
```

#### Linux/macOS Configuration
```json
{
  "mcpServers": {
    "recon": {
      "command": "/home/YOUR_USERNAME/.local/bin/uv",
      "args": [
        "--directory",
        "/home/YOUR_USERNAME/path/to/MCP_Recon",
        "run",
        "python",
        "main.py"
      ]
    }
  }
}
```

**Replace the following placeholders:**
- `YOUR_USERNAME` with your actual username
- `path/to/MCP_Recon` with the actual path to your cloned repository

**Configuration file locations:**
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json` 

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

## 🚀 Usage

### Available Tools (Following Reconnaissance Methodology)

#### 1. Information Gathering (Passive Reconnaissance)
- `whois_info` - Get WHOIS information
- `domain_history` - Check domain reputation and history

#### 2. DNS Analysis (Infrastructure Discovery)
- `dns_records` - Get all DNS records for a domain
- `reverse_dns` - Perform reverse DNS lookup
- `subdomain_enum_passive` - Passive subdomain discovery via Certificate Transparency (crt.sh)
- `subdomain_enum_active` - Active subdomain enumeration using DNS brute force

#### 3. Network Reconnaissance (Active Scanning)
- `ip_information` - Get comprehensive IP information
- `check_alive` - Check if hosts respond via HTTP/HTTPS
- `port_scan` - Advanced port scanning with Nmap

#### 4. Web Application Analysis (Application Layer)
- `tls_certificate` - Analyze TLS certificates
- `http_headers` - Analyze HTTP security headers
- `detect_technologies` - Detect web technologies
- `extract_urls` - Extract URLs from web pages

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

## 🔧 Wordlists

### Subdomain Wordlist Customization

You can customize subdomain enumeration in two ways:

#### 1. Edit the wordlist file
Modify the `subdomains.txt` file in the project root to add/remove subdomains:
```
www
api
admin
test
dev
staging
# Add your custom subdomains here
```

#### 2. Provide custom wordlist in Claude Desktop chat



### Port Scanning Options

The port scanner supports various modes optimized for different scenarios:
- `"common"`: Common services (21,22,23,25,53,80,443,etc.)
- `"top100"`: Top 100 most common ports (recommended for initial reconnaissance)
- `"top1000"`: Top 1000 ports (comprehensive discovery)
- `"80,443,8080"`: Specific ports (targeted scanning)
- `"1-1000"`: Port range (internal network scanning)

## 🏗 Architecture

### Project Structure
```
mcp-recon/
├── main.py                 # MCP server entry point with organized tool categories
├── subdomains.txt          # Default subdomain wordlist (customizable)
├── tools/
│   ├── info_tools.py       # Information gathering utilities (WHOIS, domain history)
│   ├── dns_tools.py        # DNS and domain reconnaissance
│   ├── network_tools.py    # Network scanning and analysis
│   └── web_tools.py        # Web application analysis
├── install.ps1            # Windows installation script
├── install.sh             # Linux/macOS installation script
├── pyproject.toml          # Python project configuration
└── README.md              # This documentation
```

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

## ⚠️ Disclaimer

This tool is intended for legitimate security research, penetration testing, and bug bounty activities only. Users are responsible for ensuring they have proper authorization before scanning or testing any networks, systems, or applications. The authors are not responsible for any misuse of this tool.

**Always follow responsible disclosure practices and respect scope limitations in bug bounty programs.**

