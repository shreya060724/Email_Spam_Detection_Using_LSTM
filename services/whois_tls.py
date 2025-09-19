import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Optional, Any

try:
    import whois  # python-whois
except Exception:  # optional dependency
    whois = None

try:
    import tldextract
except Exception:
    tldextract = None

try:
    from dateutil import parser as date_parser
except Exception:
    date_parser = None

# Simple in-memory cache to reduce latency and rate-limit issues
_WHOIS_CACHE: Dict[str, Dict[str, Any]] = {}


def _registrable_domain(host: str) -> Optional[str]:
    host = (host or '').split(':')[0].strip().lower()
    if not host:
        return None
    if tldextract is None:
        # Fallback heuristic: last two labels
        parts = host.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return host
    ext = tldextract.extract(host)
    if not ext.domain or not ext.suffix:
        return host
    return f"{ext.domain}.{ext.suffix}"


def _normalize_creation_date(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, list) or isinstance(value, tuple):
        # choose the earliest date
        dates = [d for d in value if d]
        parsed = [_normalize_creation_date(d) for d in dates]
        parsed = [d for d in parsed if d]
        return min(parsed) if parsed else None
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    # Strings or other
    if isinstance(value, (str, bytes)):
        s = value.decode() if isinstance(value, bytes) else value
        if date_parser is not None:
            try:
                dt = date_parser.parse(s)
                return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
            except Exception:
                return None
        # Fallback: common formats
        for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%Y.%m.%d", "%Y/%m/%d"):
            try:
                dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
                return dt
            except Exception:
                continue
    return None


def get_domain_age_days(host_or_domain: str) -> Optional[int]:
    if whois is None:
        return None
    registrable = _registrable_domain(host_or_domain)
    if not registrable:
        return None
    if registrable in _WHOIS_CACHE:
        cached = _WHOIS_CACHE[registrable]
        return cached.get('age_days')
    try:
        data = whois.whois(registrable)
        created = _normalize_creation_date(getattr(data, 'creation_date', None))
        if not created:
            _WHOIS_CACHE[registrable] = {'age_days': None}
            return None
        age = (datetime.now(timezone.utc) - created).days
        age_days = int(age)
        _WHOIS_CACHE[registrable] = {'age_days': age_days}
        return age_days
    except Exception:
        _WHOIS_CACHE[registrable] = {'age_days': None}
        return None


def fetch_tls_cn(host: str, port: int = 443) -> Optional[str]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert.get('subject', []))
                return subject.get('commonName')
    except Exception:
        return None


def assess_whois_tls(host: str) -> Dict:
    domain = (host or '').split(':')[0]
    age_days = get_domain_age_days(domain)
    tls_cn = fetch_tls_cn(domain)

    # Simple heuristic risk from age
    age_risk = 0.0
    if age_days is not None:
        if age_days < 30:
            age_risk = 0.4
        elif age_days < 180:
            age_risk = 0.2

    tls_mismatch = None
    if tls_cn:
        tls_mismatch = (tls_cn.lower() != domain.lower() and not tls_cn.lower().endswith('.' + domain.lower()))

    tls_risk = 0.2 if tls_mismatch else 0.0

    return {
        'domain': domain,
        'age_days': age_days,
        'tls_common_name': tls_cn,
        'tls_cn_mismatch': tls_mismatch,
        'whois_tls_risk': float(min(1.0, age_risk + tls_risk))
    }


