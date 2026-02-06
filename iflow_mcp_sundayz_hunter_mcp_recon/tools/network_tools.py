"""
Network reconnaissance tools
"""

import platform
import json
import socket
import ipaddress
import nmap
import os
import httpx
import time
from typing import List


def ip_info(target: str) -> str:
    """
    Get comprehensive IP information
    """
    try:
        # Resolve domain to IP if needed
        if not target.replace('.', '').isdigit():
            try:
                ip = socket.gethostbyname(target)
            except:
                return json.dumps({"error": f"Cannot resolve {target}"})
        else:
            ip = target

        # Get reverse DNS
        try:
            reverse_dns = socket.gethostbyaddr(ip)[0]
        except:
            reverse_dns = None

        # Check IP type
        ip_obj = ipaddress.ip_address(ip)

        info = {
            "target": target,
            "ip_address": ip,
            "reverse_dns": reverse_dns,
            "ip_version": ip_obj.version,
            "is_private": ip_obj.is_private,
            "is_global": ip_obj.is_global,
            "is_multicast": ip_obj.is_multicast,
            "is_loopback": ip_obj.is_loopback
        }

        # Get additional info using external API (optional)
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(f"http://ip-api.com/json/{ip}")
                if response.status_code == 200:
                    api_data = response.json()
                    if api_data.get('status') == 'success':
                        info.update({
                            "country": api_data.get('country'),
                            "region": api_data.get('regionName'),
                            "city": api_data.get('city'),
                            "isp": api_data.get('isp'),
                            "org": api_data.get('org'),
                            "as": api_data.get('as'),
                            "lat": api_data.get('lat'),
                            "lon": api_data.get('lon')
                        })
        except:
            pass  # External API is optional

        return json.dumps(info, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


def check_alive_httpx(targets: List[str]) -> str:
    """
    Check if targets are alive using Python httpx
    Simple connectivity test without HTML parsing
    """
    try:
        alive_hosts = []

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        for target in targets:
            # Ensure target has protocol
            if not target.startswith(('http://', 'https://')):
                test_urls = [f'https://{target}', f'http://{target}']
            else:
                test_urls = [target]

            for url in test_urls:
                try:
                    start_time = time.time()

                    with httpx.Client(timeout=10.0, follow_redirects=True, verify=False) as client:
                        response = client.get(url, headers=headers)

                    response_time = f"{(time.time() - start_time) * 1000:.1f}ms"

                    alive_hosts.append({
                        "url": str(response.url),
                        "status_code": response.status_code,
                        "server": response.headers.get('server'),
                        "content_length": response.headers.get('content-length'),
                        "response_time": response_time
                    })
                    break  # Success, no need to try http if https worked

                except httpx.ConnectError:
                    continue  # Try next URL variant
                except httpx.TimeoutException:
                    continue
                except Exception:
                    continue

        return json.dumps({
            "total_targets": len(targets),
            "alive_hosts": alive_hosts,
            "alive_count": len(alive_hosts)
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


def port_scan_nmap(target: str, ports: str = "top100") -> str:
    """
    Advanced port scan using nmap
    """
    try:
        # Handle Windows nmap path issue
        if platform.system() == "Windows":
            # Common Windows installation paths
            potential_paths = [
                "C:\\Program Files (x86)\\Nmap\\nmap.exe",
                "C:\\Program Files\\Nmap\\nmap.exe"
            ]
            nmap_path = None
            for path in potential_paths:
                if os.path.exists(path):
                    nmap_path = path
                    break

            if nmap_path:
                nm = nmap.PortScanner(nmap_search_path=[nmap_path])
            else:
                nm = nmap.PortScanner()
        else:
            nm = nmap.PortScanner()

        # Determine scan arguments and port specification
        if ports == "common":
            port_range = "21,22,23,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,5900,8080,8443"
            scan_args = "-sV -sC -Pn"  # Service version, default scripts, no ping
        elif ports == "top100":
            # Use -F flag for fast scan (top 100 ports)
            port_range = None
            scan_args = "-F -sV -sC -Pn"
        elif ports == "top1000":
            # Use --top-ports 1000
            port_range = None
            scan_args = "--top-ports 1000 -sV -sC -Pn"
        elif "-" in ports or "," in ports:
            # Custom port range or list
            port_range = ports
            scan_args = "-sV -sC -Pn"
        else:
            # Single port check
            port_range = ports
            scan_args = "-sV -sC -Pn"

        # Run nmap scan
        if port_range:
            nm.scan(hosts=target, ports=port_range, arguments=scan_args)
        else:
            # For -F and --top-ports, don't specify ports parameter
            nm.scan(hosts=target, arguments=scan_args)

        results = {
            "target": target,
            "scan_info": nm.scaninfo(),
            "hosts": []
        }

        for host in nm.all_hosts():
            host_info = {
                "ip": host,
                "hostname": nm[host].hostname(),
                "state": nm[host].state(),
                "ports": []
            }

            for proto in nm[host].all_protocols():
                ports_list = nm[host][proto].keys()
                for port in sorted(ports_list):
                    port_info = nm[host][proto][port]
                    host_info["ports"].append({
                        "port": port,
                        "state": port_info['state'],
                        "service": port_info['name'],
                        "product": port_info.get('product', ''),
                        "version": port_info.get('version', ''),
                        "extrainfo": port_info.get('extrainfo', ''),
                        "cpe": port_info.get('cpe', '')
                    })

            results["hosts"].append(host_info)

        return json.dumps(results, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})
