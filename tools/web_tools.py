"""
Web reconnaissance tools
"""

import json
import httpx
from bs4 import BeautifulSoup
import ssl
import socket
from datetime import datetime
import hashlib


def tls_certificate_check(domain: str) -> str:
    """
    Check TLS certificate using Python ssl module
    """
    try:
        # Connect to domain on port 443
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_pem = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)

                # Extract subject alternative names
                san_list = []
                if cert_pem.get('subjectAltName'):
                    san_list = [name[1] for name in cert_pem.get('subjectAltName', [])]

                # Extract subject and issuer info
                subject_dict = dict(x[0] for x in cert_pem.get('subject', []))
                issuer_dict = dict(x[0] for x in cert_pem.get('issuer', []))

                # Get certificate details
                cert_info = {
                    "timestamp": datetime.now().isoformat(),
                    "host": domain,
                    "port": "443",
                    "probe_status": True,
                    "tls_version": ssock.version(),
                    "cipher": ssock.cipher()[0] if ssock.cipher() else None,
                    "not_before": cert_pem.get('notBefore'),
                    "not_after": cert_pem.get('notAfter'),
                    "subject_dn": f"CN={subject_dict.get('commonName', '')}",
                    "subject_cn": subject_dict.get('commonName'),
                    "subject_an": san_list,
                    "serial": cert_pem.get('serialNumber'),
                    "issuer_dn": f"CN={issuer_dict.get('commonName', '')}, O={issuer_dict.get('organizationName', '')}, C={issuer_dict.get('countryName', '')}",
                    "issuer_cn": issuer_dict.get('commonName'),
                    "issuer_org": [issuer_dict.get('organizationName')] if issuer_dict.get('organizationName') else [],
                    "fingerprint_hash": {
                        "md5": hashlib.md5(cert_der).hexdigest(),
                        "sha1": hashlib.sha1(cert_der).hexdigest(),
                        "sha256": hashlib.sha256(cert_der).hexdigest()
                    },
                    "wildcard_certificate": any('*' in name for name in san_list) or '*' in subject_dict.get(
                        'commonName', ''),
                    "tls_connection": "native_python"
                }

                return json.dumps({
                    "domain": domain,
                    "certificates": [cert_info]
                }, indent=2)

    except socket.timeout:
        return json.dumps({"error": "Connection timeout"})
    except socket.gaierror:
        return json.dumps({"error": "DNS resolution failed"})
    except ssl.SSLError as e:
        return json.dumps({"error": f"SSL error: {str(e)}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


def web_headers(url: str) -> str:
    """
    Analyze HTTP headers for security and information disclosure
    """
    try:
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        # Create httpx client with timeout and redirects
        with httpx.Client(timeout=10.0, follow_redirects=True, verify=False) as client:
            response = client.get(url, headers=headers)

        # Security headers to check
        security_headers = {
            'X-Frame-Options': response.headers.get('X-Frame-Options'),
            'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
            'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
            'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
            'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
            'X-Powered-By': response.headers.get('X-Powered-By'),
            'Server': response.headers.get('Server'),
            'Set-Cookie': 'Present' if 'Set-Cookie' in response.headers else None,
            'Referrer-Policy': response.headers.get('Referrer-Policy'),
            'Permissions-Policy': response.headers.get('Permissions-Policy'),
            'X-Permitted-Cross-Domain-Policies': response.headers.get('X-Permitted-Cross-Domain-Policies')
        }

        # Check for missing security headers
        missing_headers = []
        recommended_headers = [
            'X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security',
            'Content-Security-Policy', 'Referrer-Policy', 'Permissions-Policy'
        ]

        for header in recommended_headers:
            if not response.headers.get(header):
                missing_headers.append(header)

        # Information disclosure headers
        info_headers = {
            'X-AspNet-Version': response.headers.get('X-AspNet-Version'),
            'X-AspNetMvc-Version': response.headers.get('X-AspNetMvc-Version'),
            'X-Powered-By': response.headers.get('X-Powered-By'),
            'X-Generator': response.headers.get('X-Generator'),
            'X-Drupal-Cache': response.headers.get('X-Drupal-Cache'),
            'X-Drupal-Dynamic-Cache': response.headers.get('X-Drupal-Dynamic-Cache'),
            'X-Varnish': response.headers.get('X-Varnish'),
            'Via': response.headers.get('Via'),
            'X-Served-By': response.headers.get('X-Served-By')
        }

        # Remove None values
        security_headers = {k: v for k, v in security_headers.items() if v is not None}
        info_headers = {k: v for k, v in info_headers.items() if v is not None}

        # Check cookies for security flags
        cookies_info = []
        for cookie in response.cookies:
            cookies_info.append({
                "name": cookie.name,
                "value": cookie.value[:20] + "..." if len(cookie.value) > 20 else cookie.value,  # Truncate for security
                "domain": getattr(cookie, 'domain', None),
                "path": getattr(cookie, 'path', None),
                "secure": getattr(cookie, 'secure', False),
                "httponly": getattr(cookie, 'httponly', False),
            })

        return json.dumps({
            "url": url,
            "final_url": str(response.url),
            "status_code": response.status_code,
            "security_headers": security_headers,
            "missing_security_headers": missing_headers,
            "information_disclosure": info_headers,
            "cookies": cookies_info,
            "content_type": response.headers.get('Content-Type'),
            "content_length": response.headers.get('Content-Length')
        }, indent=2)

    except httpx.ConnectError:
        return json.dumps({"error": "Connection failed", "hint": "Target may be unreachable"})
    except httpx.TimeoutException:
        return json.dumps({"error": "Request timeout", "hint": "Target took too long to respond"})
    except httpx.HTTPStatusError as e:
        return json.dumps({"error": f"HTTP error: {e.response.status_code}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


def technology_detection(url: str) -> str:
    """
    Detect technologies used by a website
    """
    try:
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        with httpx.Client(timeout=10.0, verify=False) as client:
            response = client.get(url, headers=headers)

        soup = BeautifulSoup(response.content, 'html.parser')

        technologies = {
            "cms": [],
            "javascript_libraries": [],
            "css_frameworks": [],
            "web_servers": [],
            "analytics": [],
            "cdn": [],
            "security": []
        }

        # Check headers for server info
        server = response.headers.get('Server', '').lower()
        powered_by = response.headers.get('X-Powered-By', '').lower()

        if server:
            technologies["web_servers"].append(server)
        if powered_by:
            technologies["web_servers"].append(powered_by)

        # Check for common CMS signatures
        cms_signatures = {
            "wordpress": ["wp-content", "wp-includes", "wp-json"],
            "drupal": ["sites/all", "sites/default", "node/"],
            "joomla": ["index.php/component/", "joomla"],
            "magento": ["skin/frontend/", "mage/"],
            "shopify": ["cdn.shopify.com", "shopify"],
            "wix": ["wix.com", "parastorage.com"],
            "squarespace": ["squarespace.com", "sqsp.net"]
        }

        page_content = str(soup)
        for cms, signatures in cms_signatures.items():
            for sig in signatures:
                if sig in page_content:
                    technologies["cms"].append(cms)
                    break

        # Check for JavaScript libraries
        js_libs = {
            "jquery": ["jquery", "jQuery"],
            "react": ["react", "React"],
            "vue": ["vue", "Vue"],
            "angular": ["angular", "Angular"],
            "bootstrap": ["bootstrap"],
            "tailwind": ["tailwind"]
        }

        for lib, signatures in js_libs.items():
            for sig in signatures:
                if sig in page_content:
                    technologies["javascript_libraries"].append(lib)
                    break

        # Check for analytics
        analytics_signatures = {
            "google_analytics": ["google-analytics.com", "ga.js", "gtag"],
            "google_tag_manager": ["googletagmanager.com"],
            "facebook_pixel": ["facebook.com/tr"],
            "hotjar": ["hotjar.com"],
            "mixpanel": ["mixpanel.com"]
        }

        for analytics, signatures in analytics_signatures.items():
            for sig in signatures:
                if sig in page_content:
                    technologies["analytics"].append(analytics)
                    break

        # Check meta tags
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator:
            content = generator.get('content', '').lower()
            if content:
                technologies["cms"].append(content)

        # Remove duplicates
        for key in technologies:
            technologies[key] = list(set(technologies[key]))

        return json.dumps({
            "url": url,
            "technologies": technologies,
            "response_headers": dict(response.headers)
        }, indent=2)

    except httpx.ConnectError:
        return json.dumps({"error": "Connection failed", "hint": "Target may be unreachable"})
    except httpx.TimeoutException:
        return json.dumps({"error": "Request timeout", "hint": "Target took too long to respond"})
    except Exception as e:
        return json.dumps({"error": str(e)})


def extract_urls_katana(url: str, depth: int = 2) -> str:
    """
    URL extraction using Python requests and BeautifulSoup
    """
    try:
        import httpx
        from bs4 import BeautifulSoup
        from urllib.parse import urljoin, urlparse
        import time

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        visited_urls = set()
        found_urls = []
        to_crawl = [(url, 0)]  # (url, current_depth)
        base_domain = urlparse(url).netloc

        with httpx.Client(timeout=10.0, follow_redirects=True, headers=headers, verify=False) as client:
            while to_crawl and len(visited_urls) < 50:  # Limit to prevent infinite crawling
                current_url, current_depth = to_crawl.pop(0)

                if current_url in visited_urls or current_depth >= depth:
                    continue

                visited_urls.add(current_url)

                try:
                    response = client.get(current_url)
                    if response.status_code == 200 and 'text/html' in response.headers.get('content-type', ''):
                        soup = BeautifulSoup(response.content, 'html.parser')

                        # Extract all links
                        for link in soup.find_all(['a', 'link'], href=True):
                            href = link.get('href')
                            if href:
                                absolute_url = urljoin(current_url, href)
                                parsed = urlparse(absolute_url)

                                # Only HTTP/HTTPS URLs
                                if parsed.scheme in ['http', 'https'] and absolute_url not in visited_urls:
                                    found_urls.append({
                                        "url": absolute_url,
                                        "method": "GET",
                                        "status": response.status_code,
                                        "source_url": current_url,
                                        "depth": current_depth
                                    })

                                    # Add to crawl queue if same domain and not too deep
                                    if current_depth + 1 < depth and base_domain in parsed.netloc:
                                        to_crawl.append((absolute_url, current_depth + 1))

                        # Extract form actions
                        for form in soup.find_all('form', action=True):
                            action = form.get('action')
                            if action:
                                absolute_url = urljoin(current_url, action)
                                method = form.get('method', 'GET').upper()
                                found_urls.append({
                                    "url": absolute_url,
                                    "method": method,
                                    "status": 0,
                                    "source_url": current_url,
                                    "depth": current_depth,
                                    "type": "form"
                                })

                except Exception:
                    continue

                # Small delay to be respectful
                time.sleep(0.1)

        # Categorize URLs
        internal_urls = []
        external_urls = []

        for url_info in found_urls:
            parsed = urlparse(url_info['url'])
            if base_domain in parsed.netloc:
                internal_urls.append(url_info)
            else:
                external_urls.append(url_info)

        return json.dumps({
            "target": url,
            "method": "python_crawler",
            "internal_urls": internal_urls,
            "external_urls": external_urls,
            "total_internal": len(internal_urls),
            "total_external": len(external_urls),
            "total_urls": len(found_urls),
            "crawl_depth": depth
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})
