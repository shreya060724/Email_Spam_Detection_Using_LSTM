import re
from typing import Dict, Optional


_PHISH_PATTERNS = [
    r"verify your account",
    r"confirm your (?:identity|account)",
    r"update (?:your )?payment",
    r"urgent (?:action|update)",
    r"unusual (?:sign|login) activity",
    r"your (?:mailbox|account) will be (?:closed|suspended)",
    r"reset your password",
    r"billing (?:problem|issue)",
    r"win(?:ner|) [\$€£]?\d+",
    r"gift card",
]

_PHISH_REGEX = re.compile("|".join(_PHISH_PATTERNS), re.IGNORECASE)


def phishing_phrase_score(text: str) -> float:
    if not text:
        return 0.0
    matches = _PHISH_REGEX.findall(text)
    # Cap influence; more matches → higher score up to 1.0
    return float(min(1.0, 0.25 * len(matches)))


def display_name_domain_mismatch(headers_text: str) -> float:
    """
    If From display name suggests a known brand (e.g., Microsoft, PayPal) but the domain is unrelated, raise risk.
    """
    if not headers_text:
        return 0.0
    brand_keywords = [
        'microsoft', 'office365', 'google', 'gmail', 'apple', 'amazon', 'paypal', 'bank', 'netflix', 'meta', 'facebook'
    ]
    # naive From parsing
    m = re.search(r"From:\s*\"?([^\"<]+)\"?\s*<[^>]*@([^>]+)>", headers_text, re.IGNORECASE)
    if not m:
        return 0.0
    display = m.group(1).strip().lower()
    domain = m.group(2).strip().lower()
    for brand in brand_keywords:
        if brand in display and brand not in domain:
            return 0.6
    return 0.0


ALLOWLIST_DOMAINS = set([
    'google.com','gmail.com','apple.com','amazon.com','microsoft.com','outlook.com','live.com','paypal.com','netflix.com',
])


def apply_allowlist(spam_score: float, headers_text: Optional[str]) -> float:
    if not headers_text:
        return spam_score
    m = re.search(r"From:\s*[^<]*<[^@>]+@([^>]+)>", headers_text, re.IGNORECASE)
    if not m:
        return spam_score
    domain = m.group(1).strip().lower()
    if any(domain == d or domain.endswith('.' + d) for d in ALLOWLIST_DOMAINS):
        # reduce small boosts to avoid false positives on well-known brands
        return float(max(0.0, spam_score - 0.1))
    return spam_score


