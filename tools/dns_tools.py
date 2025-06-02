"""
DNS reconnaissance tools
"""

import json
import socket
import dns.resolver
import httpx
from typing import List


def dns_lookup(domain: str) -> str:
    """
    Perform comprehensive DNS lookups for various record types
    """
    try:
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV', 'SPF', 'DMARC']

        for record_type in record_types:
            try:
                # Handle special TXT records
                if record_type == 'SPF':
                    answers = dns.resolver.resolve(domain, 'TXT')
                    spf_records = [str(rdata) for rdata in answers if 'v=spf1' in str(rdata)]
                    records[record_type] = spf_records
                elif record_type == 'DMARC':
                    answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                    records[record_type] = [str(rdata) for rdata in answers]
                else:
                    answers = dns.resolver.resolve(domain, record_type)
                    records[record_type] = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                records[record_type] = []

        return json.dumps({
            "domain": domain,
            "records": records
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


def reverse_dns_lookup(ip: str) -> str:
    """
    Perform reverse DNS lookup on IP address
    """
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)

        return json.dumps({
            "ip": ip,
            "hostname": hostname,
            "aliases": aliases,
            "addresses": addresses
        }, indent=2)
    except socket.herror:
        return json.dumps({
            "ip": ip,
            "hostname": None,
            "error": "No reverse DNS record found"
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


def crtsh_subdomains(domain: str) -> List[str]:
    """
    Passive subdomain enumeration using Certificate Transparency logs via crt.sh
    """
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"

        with httpx.Client(timeout=15.0) as client:
            response = client.get(url)

        if response.status_code == 200:
            entries = response.json()
            # Extract and clean subdomain names
            subdomains = set()
            for entry in entries:
                name_value = entry.get('name_value', '')
                # Handle multiple domains in one certificate (separated by newlines)
                for subdomain in name_value.split('\n'):
                    subdomain = subdomain.strip()
                    # Remove wildcards and clean the subdomain
                    if subdomain.startswith('*.'):
                        subdomain = subdomain[2:]
                    # Only include subdomains of the target domain
                    if subdomain.endswith(f'.{domain}') or subdomain == domain:
                        subdomains.add(subdomain.lower())

            return sorted(list(subdomains))
        else:
            return []
    except Exception:
        return []  # Return empty list on any error


def subdomain_enum_passive(domain: str) -> str:
    """
    Passive subdomain enumeration using Certificate Transparency logs
    Returns subdomains found in CT logs WITHOUT DNS resolution (true passive)
    """
    try:
        subdomains = crtsh_subdomains(domain)

        return json.dumps({
            "domain": domain,
            "method": "certificate_transparency_passive",
            "subdomains": subdomains,
            "total_found": len(subdomains),
            "passive_discovery": True,
            "note": "No DNS resolution performed - pure passive reconnaissance"
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


def subdomain_enum_active(domain: str, wordlist: list = None) -> str:
    """
    Active subdomain enumeration using DNS brute force
    Tests if subdomains exist without retrieving IP addresses
    """
    try:
        import dns.resolver
        import concurrent.futures
        import os

        # Load wordlist from file or use provided list or use default
        if wordlist is None:
            # Try to load from subdomains.txt file
            wordlist_file = "subdomains.txt"
            if os.path.exists(wordlist_file):
                try:
                    with open(wordlist_file, 'r', encoding='utf-8') as f:
                        wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                except Exception:
                    # Fallback to default list if file read fails
                    wordlist = _get_default_wordlist()
            else:
                # Use default embedded wordlist
                wordlist = _get_default_wordlist()

        found_subdomains = []

        def check_subdomain(sub):
            subdomain = f"{sub}.{domain}"
            try:
                # Just check if subdomain exists (any DNS record type)
                dns.resolver.resolve(subdomain, 'A')
                return subdomain
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                return None
            except Exception:
                return None

        # Use ThreadPoolExecutor for concurrent DNS lookups
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in wordlist]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found_subdomains.append(result)

        return json.dumps({
            "domain": domain,
            "method": "dns_bruteforce_active",
            "subdomains": sorted(found_subdomains),
            "total_found": len(found_subdomains),
            "wordlist_size": len(wordlist),
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


def _get_default_wordlist():
    """Get default wordlist if file is not available"""
    return [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
        'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'm', 'imap', 'test', 'ns',
        'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns4', 'email',
        'winmail', 'com', 'mail2', 'cv', 'sql', 'mysql', 'web', 'direct-connect-mail',
        'api', 'cdn', 'support', 'store', 'app', 'mobile', 'secure', 'portal',
        'beta', 'stage', 'staging', 'demo', 'old', 'new', 'legacy', 'shop', 'home'
    ]
