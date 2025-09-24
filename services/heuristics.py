import re
from typing import Dict, Optional, List
from urllib.parse import urlparse


# Enhanced phishing patterns for better content-only detection
_PHISH_PATTERNS = [
    # Account/security related
    r"verify your account",
    r"confirm your (?:identity|account)",
    r"update (?:your )?payment",
    r"urgent (?:action|update)",
    r"unusual (?:sign|login) activity",
    r"your (?:mailbox|account) will be (?:closed|suspended)",
    r"reset your password",
    r"billing (?:problem|issue)",
    r"security alert",
    r"unusual activity detected",
    r"temporarily suspended",
    r"restore access",
    r"verify your identity",
    r"account will be permanently closed",
    
    # Prize/lottery related
    r"win(?:ner|) [\$€£]?\d+",
    r"gift card",
    r"lottery promotion",
    r"selected as a winner",
    r"prize of [\$€£]\d+",
    r"claim your prize",
    r"congratulations",
    r"lucky winner",
    r"millions online lottery",
    r"annual.*lottery",
    r"reference number",
    r"claims agent",
    
    # Urgency and time pressure
    r"within \d+ hours",
    r"limited time",
    r"act now",
    r"click now",
    r"verify now",
    r"immediately",
    r"asap",
    r"emergency",
    r"critical",
    r"expire",
    r"expired",
    r"expiring",
    r"deadline",
    
    # Suspicious domains and actions
    r"secure-payment-login",
    r"verify-now\.net",
    r"euro-claims-dept",
    r"claims\.dept",
    r"restore\?session=",
    r"w1nner-form",  # Common typo in spam
]

_PHISH_REGEX = re.compile("|".join(_PHISH_PATTERNS), re.IGNORECASE)

# Suspicious domain patterns
_SUSPICIOUS_DOMAIN_PATTERNS = [
    r"verify-now",
    r"secure-payment",
    r"claims-dept",
    r"euro-claims",
    r"restore.*session",
    r"w1nner",  # Common typo
    r"\.online$",
    r"\.net$",
    r"\.tk$",
    r"\.ml$",
    r"\.ga$",
    r"\.cf$",
]

_SUSPICIOUS_DOMAIN_REGEX = re.compile("|".join(_SUSPICIOUS_DOMAIN_PATTERNS), re.IGNORECASE)


def phishing_phrase_score(text: str) -> float:
    if not text:
        return 0.0
    matches = _PHISH_REGEX.findall(text)
    # Cap influence; more matches → higher score up to 1.0
    return float(min(1.0, 0.25 * len(matches)))


def analyze_url_suspiciousness(text: str) -> float:
    """
    Analyze URLs in the text for suspicious patterns.
    Returns a score from 0.0 to 1.0 indicating suspiciousness.
    """
    if not text:
        return 0.0
    
    url_pattern = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
    urls = url_pattern.findall(text)
    
    if not urls:
        return 0.0
    
    suspicious_score = 0.0
    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Check for suspicious domain patterns
            if _SUSPICIOUS_DOMAIN_REGEX.search(domain + path):
                suspicious_score += 0.4
            
            # Check for suspicious TLDs
            if domain.endswith(('.tk', '.ml', '.ga', '.cf', '.online')):
                suspicious_score += 0.3
            
            # Check for IP addresses in domain
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                suspicious_score += 0.5
            
            # Check for long, random-looking domains
            if len(domain) > 20 and re.search(r'[a-z]{10,}', domain):
                suspicious_score += 0.2
                
        except Exception:
            # If URL parsing fails, consider it suspicious
            suspicious_score += 0.3
    
    return float(min(suspicious_score, 1.0))


def analyze_content_structure(text: str) -> float:
    """
    Analyze the structural characteristics of the email content.
    Returns a score indicating how spam-like the structure is.
    """
    if not text:
        return 0.0
    
    score = 0.0
    
    # Check for excessive HTML
    html_tags = re.findall(r'<[^>]+>', text)
    if len(html_tags) > 10:
        score += 0.3
    
    # Check for excessive capitalization
    caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    if caps_ratio > 0.3:
        score += 0.2
    
    # Check for excessive exclamation marks
    exclamation_count = text.count('!')
    if exclamation_count > 3:
        score += 0.2
    
    # Check for suspicious formatting patterns
    if re.search(r'[A-Z]{3,}', text):  # Multiple consecutive caps
        score += 0.1
    
    # Check for suspicious punctuation patterns
    if re.search(r'[!]{2,}', text):  # Multiple exclamation marks
        score += 0.1
    
    # Check for suspicious spacing patterns
    if re.search(r'\s{3,}', text):  # Multiple spaces
        score += 0.1
    
    return float(min(score, 1.0))


def analyze_urgency_indicators(text: str) -> float:
    """
    Analyze text for urgency indicators commonly used in spam/phishing.
    """
    if not text:
        return 0.0
    
    urgency_patterns = [
        r'\b(urgent|immediate|asap|emergency|critical)\b',
        r'\b(expire|expired|expiring|deadline)\b',
        r'\b(limited time|act now|click now|verify now)\b',
        r'\b(within \d+ hours?)\b',
        r'\b(24 hours?|48 hours?)\b',
        r'\b(permanently closed|suspended|blocked)\b',
    ]
    
    urgency_score = 0.0
    for pattern in urgency_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        urgency_score += len(matches) * 0.2
    
    return float(min(urgency_score, 1.0))


def analyze_prize_lottery_indicators(text: str) -> float:
    """
    Analyze text for prize/lottery indicators commonly used in spam.
    """
    if not text:
        return 0.0
    
    prize_patterns = [
        r'\b(winner|won|prize|reward|lottery|jackpot)\b',
        r'\b(million|billion|thousand)\b',
        r'\b(free|gift|bonus)\b',
        r'\b(selected|chosen|lucky)\b',
        r'\b(congratulations|congrats)\b',
        r'\b(claim|collect|redeem)\b',
        r'\b(reference number|claim code)\b',
        r'\b(claims agent|promotions manager)\b',
    ]
    
    prize_score = 0.0
    for pattern in prize_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        prize_score += len(matches) * 0.15
    
    return float(min(prize_score, 1.0))


def comprehensive_content_analysis(text: str) -> Dict[str, float]:
    """
    Perform comprehensive content analysis and return all feature scores.
    """
    return {
        'phishing_phrases': phishing_phrase_score(text),
        'url_suspiciousness': analyze_url_suspiciousness(text),
        'content_structure': analyze_content_structure(text),
        'urgency_indicators': analyze_urgency_indicators(text),
        'prize_lottery_indicators': analyze_prize_lottery_indicators(text),
    }


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


