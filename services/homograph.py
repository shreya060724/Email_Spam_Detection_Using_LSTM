import idna
from typing import Dict


def detect_homograph(host: str) -> Dict:
    host = (host or '').lower()
    is_punycode = host.startswith('xn--') or '.xn--' in host
    decoded = None
    try:
        decoded = idna.decode(host)
    except Exception:
        decoded = None

    looks_like = None
    if decoded and decoded != host:
        # Simple check for mixed-script or confusable characters
        mixed_script = any(ord(ch) > 127 for ch in decoded)
        looks_like = 'mixed-script' if mixed_script else None

    homograph_risk = 0.15 if is_punycode or looks_like else 0.0

    return {
        'host': host,
        'idn_decoded': decoded,
        'punycode': is_punycode,
        'looks_like': looks_like,
        'homograph_risk': float(homograph_risk)
    }


