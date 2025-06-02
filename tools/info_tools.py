"""
Information gathering tools
"""

import json
import whois
from datetime import datetime
from typing import Dict, Any, Optional


def whois_lookup(domain: str) -> str:
    """
    Comprehensive WHOIS lookup with enhanced parsing
    """
    try:
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc

        # Perform WHOIS lookup
        w = whois.whois(domain)

        # Parse dates properly
        def parse_date(date_value):
            if not date_value:
                return None
            if isinstance(date_value, list):
                date_value = date_value[0]
            if isinstance(date_value, datetime):
                return date_value.isoformat()
            return str(date_value)

        # Extract all available information
        whois_data = {
            "domain": domain,
            "registrar": str(w.registrar) if w.registrar else None,
            "whois_server": str(w.whois_server) if hasattr(w, 'whois_server') and w.whois_server else None,
            "creation_date": parse_date(w.creation_date),
            "expiration_date": parse_date(w.expiration_date),
            "updated_date": parse_date(w.updated_date) if hasattr(w, 'updated_date') else None,
            "status": w.status if w.status else [],
            "name_servers": [ns.lower() for ns in w.name_servers] if w.name_servers else [],
            "dnssec": w.dnssec if hasattr(w, 'dnssec') else None,
            "organization": str(w.org) if hasattr(w, 'org') and w.org else None,
            "country": str(w.country) if hasattr(w, 'country') and w.country else None,
            "state": str(w.state) if hasattr(w, 'state') and w.state else None,
            "city": str(w.city) if hasattr(w, 'city') and w.city else None,
            "emails": []
        }

        # Extract emails
        if hasattr(w, 'emails'):
            if isinstance(w.emails, list):
                whois_data["emails"] = w.emails
            elif w.emails:
                whois_data["emails"] = [str(w.emails)]

        # Calculate domain age
        if w.creation_date:
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if isinstance(creation, datetime):
                age_days = (datetime.now() - creation).days
                whois_data["domain_age_days"] = age_days
                whois_data["domain_age_years"] = round(age_days / 365, 1)

        # Calculate expiration
        if w.expiration_date:
            expiration = w.expiration_date
            if isinstance(expiration, list):
                expiration = expiration[0]
            if isinstance(expiration, datetime):
                days_until_expiry = (expiration - datetime.now()).days
                whois_data["days_until_expiry"] = days_until_expiry
                whois_data["is_expiring_soon"] = days_until_expiry < 30

        # Clean up None values
        whois_data = {k: v for k, v in whois_data.items() if v is not None}

        return json.dumps(whois_data, indent=2)

    except whois.parser.PywhoisError:
        return json.dumps({
            "error": "WHOIS lookup failed",
            "domain": domain,
            "hint": "Domain may not exist or WHOIS server is unavailable"
        })
    except Exception as e:
        return json.dumps({"error": str(e), "domain": domain})


def domain_history_check(domain: str) -> str:
    """
    Check domain history and reputation
    """
    try:
        whois_info = json.loads(whois_lookup(domain))

        if "error" in whois_info:
            return json.dumps(whois_info)

        history = {
            "domain": domain,
            "whois_info": whois_info,
            "reputation_check": {
                "is_new_domain": whois_info.get("domain_age_days", 0) < 30,
                "is_expiring_soon": whois_info.get("is_expiring_soon", False),
                "has_privacy_protection": "privacy" in str(whois_info.get("organization", "")).lower()
            }
        }

        # Check common suspicious patterns
        suspicious_indicators = []

        if history["reputation_check"]["is_new_domain"]:
            suspicious_indicators.append("Domain registered less than 30 days ago")

        if history["reputation_check"]["is_expiring_soon"]:
            suspicious_indicators.append("Domain expiring soon")

        if history["reputation_check"]["has_privacy_protection"]:
            suspicious_indicators.append("WHOIS privacy protection enabled")

        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.loan']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            suspicious_indicators.append("Suspicious TLD")

        history["suspicious_indicators"] = suspicious_indicators

        return json.dumps(history, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e), "domain": domain})
