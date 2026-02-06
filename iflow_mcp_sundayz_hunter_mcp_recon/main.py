"""
MCP Server for Web Reconnaissance
A comprehensive toolkit for web security reconnaissance and analysis using Python-native tools
Following the standard cybersecurity reconnaissance methodology
"""

from mcp.server.fastmcp import FastMCP
from typing import List

# Import all tool modules
from tools.info_tools import (
    whois_lookup,
    domain_history_check
)
from tools.dns_tools import (
    dns_lookup,
    subdomain_enum_active as subdomain_enum_active_impl,
    subdomain_enum_passive as subdomain_enum_passive_impl,
    reverse_dns_lookup
)
from tools.network_tools import (
    port_scan_nmap,
    ip_info,
    check_alive_httpx
)
from tools.web_tools import (
    web_headers,
    tls_certificate_check,
    extract_urls_katana,
    technology_detection
)

# Initialize MCP server
mcp = FastMCP("Web Recon Server")


# ============================================================================
# 1. INFORMATION GATHERING (Passive Reconnaissance)
# ============================================================================

@mcp.tool()
def whois_info(domain: str) -> str:
    """
    Get comprehensive WHOIS information for a domain
    Example: whois_info("example.com")
    """
    return whois_lookup(domain)


@mcp.tool()
def domain_history(domain: str) -> str:
    """
    Check domain history and reputation indicators
    Example: domain_history("example.com")
    """
    return domain_history_check(domain)


# ============================================================================
# 2. DNS ANALYSIS (Infrastructure Discovery)
# ============================================================================

@mcp.tool()
def dns_records(domain: str) -> str:
    """
    Perform comprehensive DNS lookups for all record types
    Example: dns_records("example.com")
    """
    return dns_lookup(domain)


@mcp.tool()
def reverse_dns(ip: str) -> str:
    """
    Perform reverse DNS lookup on IP address
    Example: reverse_dns("8.8.8.8")
    """
    return reverse_dns_lookup(ip)


@mcp.tool()
def subdomain_enum_active(domain: str, wordlist: List[str] = None) -> str:
    """
    Enumerate subdomains using DNS brute force (active reconnaissance)
    Can use default wordlist from subdomains.txt file or custom wordlist provided
    Example: subdomain_enum_active("example.com") or subdomain_enum_active("example.com", ["www", "api", "admin"])
    """
    return subdomain_enum_active_impl(domain, wordlist)


@mcp.tool()
def subdomain_enum_passive(domain: str) -> str:
    """
    Passive subdomain enumeration using Certificate Transparency logs
    Non-intrusive reconnaissance that doesn't generate logs on target servers
    Example: subdomain_enum_passive("example.com")
    """
    return subdomain_enum_passive_impl(domain)


# ============================================================================
# 3. NETWORK RECONNAISSANCE (Active Scanning)
# ============================================================================

@mcp.tool()
def ip_information(target: str) -> str:
    """
    Get comprehensive IP information including geolocation
    Example: ip_information("example.com") or ip_information("1.1.1.1")
    """
    return ip_info(target)


@mcp.tool()
def check_alive(targets: List[str]) -> str:
    """
    Check if targets are alive using Python httpx
    Example: check_alive(["example.com", "test.com"])
    """
    return check_alive_httpx(targets)


@mcp.tool()
def port_scan(target: str, ports: str = "top100") -> str:
    """
    Advanced port scan using nmap
    Ports options: "common", "top100", "top1000", "80,443,8080", "1-1000"
    Example: port_scan("example.com", "top100")
    """
    return port_scan_nmap(target, ports)


# ============================================================================
# 4. WEB APPLICATION ANALYSIS (Application Layer)
# ============================================================================

@mcp.tool()
def tls_certificate(domain: str) -> str:
    """
    Check TLS certificate details and security using Python SSL
    Example: tls_certificate("example.com")
    """
    return tls_certificate_check(domain)


@mcp.tool()
def http_headers(url: str) -> str:
    """
    Analyze HTTP headers for security and information disclosure
    Example: http_headers("https://example.com")
    """
    return web_headers(url)


@mcp.tool()
def detect_technologies(url: str) -> str:
    """
    Detect technologies, frameworks, and libraries used by a website
    Example: detect_technologies("https://example.com")
    """
    return technology_detection(url)


@mcp.tool()
def extract_urls(url: str) -> str:
    """
    Extract all URLs from a website using Python web crawler
    Example: extract_urls("https://example.com")
    """
    return extract_urls_katana(url)


def main():
    mcp.run()

if __name__ == "__main__":
    main()