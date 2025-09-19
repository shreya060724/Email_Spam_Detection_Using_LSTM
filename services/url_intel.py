import re
from urllib.parse import urlparse
from typing import List, Dict


def extract_urls(text: str) -> List[str]:
    url_regex = r"(https?://[\w\-\.\:/%\?&#=~+;,@!$'\(\)\*]+)"
    return re.findall(url_regex, text or '', flags=re.IGNORECASE)


def analyze_urls(urls: List[str]) -> List[Dict]:
    findings = []
    suspicious_tlds = {"zip", "mov", "click", "work", "xyz", "top", "casa"}
    for url in urls[:25]:
        parsed = urlparse(url)
        host = (parsed.netloc or '').lower()
        is_punycode = 'xn--' in host
        tld = host.split('.')[-1] if '.' in host else ''
        is_suspicious_tld = tld in suspicious_tlds
        has_ip_host = re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host.split(':')[0] if host else '') is not None
        path_depth = len([p for p in (parsed.path or '').split('/') if p])
        long_query = len(parsed.query or '') > 80
        findings.append({
            'url': url,
            'host': host,
            'is_punycode': is_punycode,
            'is_suspicious_tld': is_suspicious_tld,
            'has_ip_host': has_ip_host,
            'path_depth': path_depth,
            'long_query': long_query
        })
    return findings


def compute_url_risk(findings: List[Dict]) -> float:
    if not findings:
        return 0.0
    risk = 0.0
    for f in findings:
        risk += 0.15 if f.get('is_suspicious_tld') else 0.0
        risk += 0.10 if f.get('has_ip_host') else 0.0
        risk += 0.05 if f.get('is_punycode') else 0.0
        risk += 0.05 if (f.get('path_depth', 0) or 0) > 4 else 0.0
        risk += 0.05 if f.get('long_query') else 0.0
    risk = min(1.0, risk)
    return float(risk)


