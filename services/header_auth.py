from typing import Dict, List
import re


def _unfold_headers(headers_text: str) -> List[str]:
    # Join folded header lines (continuation lines start with space or tab)
    lines = headers_text.splitlines()
    unfolded: List[str] = []
    current = ''
    for line in lines:
        if line.startswith((' ', '\t')) and unfolded:
            unfolded[-1] = unfolded[-1] + ' ' + line.strip()
        else:
            unfolded.append(line.rstrip())
    return unfolded


def parse_auth_headers(headers_text: str) -> Dict:
    if not headers_text:
        return {
            'present': False,
            'spf': 'unknown',
            'dkim': 'unknown',
            'dmarc': 'unknown',
            'from_domain': None
        }

    # Unfold and index headers by key
    lines = _unfold_headers(headers_text)
    headers: Dict[str, List[str]] = {}
    for line in lines:
        if ':' in line:
            key, val = line.split(':', 1)
            headers.setdefault(key.strip().lower(), []).append(val.strip())

    # Prefer Authentication-Results when available (include ARC as well)
    auth_results_text = ' '.join(headers.get('authentication-results', []))
    auth_results_text += ' ' + ' '.join(headers.get('arc-authentication-results', []))

    # Extract spf/dkim/dmarc statuses via regex
    def extract_auth_result(name: str) -> str:
        # e.g., spf=pass, dkim=fail, dmarc=pass
        m = re.search(rf"{name}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|bestguesspass)", auth_results_text, re.IGNORECASE)
        if m:
            value = m.group(1).lower()
            if value in {'pass', 'bestguesspass'}:
                return 'pass'
            if value in {'fail', 'permerror'}:
                return 'fail'
            return 'unknown'
        return 'unknown'

    spf_status = extract_auth_result('spf')
    dkim_status = extract_auth_result('dkim')
    dmarc_status = extract_auth_result('dmarc')

    # Fallback to Received-SPF if SPF is unknown
    if spf_status == 'unknown' and 'received-spf' in headers:
        combined = ' '.join(headers['received-spf']).lower()
        if ' pass ' in f' {combined} ':
            spf_status = 'pass'
        elif ' fail ' in f' {combined} ':
            spf_status = 'fail'

    # Last-resort: scan all headers text for tokens if still unknown
    if any(x == 'unknown' for x in (spf_status, dkim_status, dmarc_status)):
        flat = ' '.join([f"{k}: {' '.join(v)}" for k, v in headers.items()]).lower()
        if spf_status == 'unknown':
            if 'spf=pass' in flat:
                spf_status = 'pass'
            elif 'spf=fail' in flat:
                spf_status = 'fail'
        if dkim_status == 'unknown':
            if 'dkim=pass' in flat:
                dkim_status = 'pass'
            elif 'dkim=fail' in flat:
                dkim_status = 'fail'
        if dmarc_status == 'unknown':
            if 'dmarc=pass' in flat:
                dmarc_status = 'pass'
            elif 'dmarc=fail' in flat:
                dmarc_status = 'fail'

    # Extract From domain
    from_domain = None
    if 'from' in headers:
        joined = ' '.join(headers['from'])
        m = re.search(r"@([\w.-]+)", joined)
        if m:
            from_domain = m.group(1).lower()

    return {
        'present': True,
        'spf': spf_status,
        'dkim': dkim_status,
        'dmarc': dmarc_status,
        'from_domain': from_domain
    }


