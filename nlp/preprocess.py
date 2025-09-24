import re
import html
from typing import List, Dict, Tuple

from nltk.stem import PorterStemmer


# Ensure NLTK resources are available at runtime
# No corpus downloads; use lightweight stemming and a static stopword list


_url_pattern = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
_email_pattern = re.compile(r"[\w\.-]+@[\w\.-]+", re.IGNORECASE)
_html_tag_pattern = re.compile(r"<[^>]+>")
_token_pattern = re.compile(r"[a-z]{2,}")
_phone_pattern = re.compile(r"[\+]?[1-9]?[0-9]{7,15}")
_currency_pattern = re.compile(r"[\$€£¥]\s*[\d,]+\.?\d*")
_urgent_pattern = re.compile(r"\b(urgent|immediate|asap|emergency|critical|expire|expired|expiring|deadline|limited time|act now|click now|verify now)\b", re.IGNORECASE)
_winner_pattern = re.compile(r"\b(winner|won|prize|reward|lottery|jackpot|million|billion|free|gift|bonus)\b", re.IGNORECASE)
_suspicious_domain_pattern = re.compile(r"\b(verify|secure|update|confirm|restore|login|account|payment|billing|support|service|security|alert|warning)\b", re.IGNORECASE)

# Static English stopwords (subset for performance, no download needed)
STOP_WORDS = {
    'a','an','the','and','or','but','if','while','with','to','from','in','on','at','by','for','of','off','out','up','down','over','under',
    'is','am','are','was','were','be','been','being','do','does','did','doing','have','has','had','having','can','could','should','would','may','might','must','will',
    'i','me','my','myself','we','our','ours','ourselves','you','your','yours','yourself','yourselves','he','him','his','himself','she','her','hers','herself','it','its','itself',
    'they','them','their','theirs','themselves','what','which','who','whom','this','that','these','those',
    'as','because','until','than','too','very','not','no','nor','so','such','both','each','few','more','most','other','some','any','only','own','same','then','once',
    'about','again','further','here','there','when','where','why','how','all'
}
STEMMER = PorterStemmer()


def clean_text(raw_text: str) -> str:
    """
    Perform robust NLP preprocessing for email content.
    Steps:
    - HTML unescape and strip tags
    - Preserve URLs and emails as special tokens for spam detection
    - Lowercase and remove non-alphabetic chars
    - Tokenize, remove stopwords
    - Lemmatize tokens and re-join
    """
    if not raw_text:
        return ""

    # Decode HTML entities and strip tags
    text = html.unescape(raw_text)
    text = _html_tag_pattern.sub(" ", text)

    # Preserve URLs and emails as special tokens instead of removing them
    # This helps the model learn from these important spam indicators
    text = _url_pattern.sub(" URL_TOKEN ", text)
    text = _email_pattern.sub(" EMAIL_TOKEN ", text)
    text = _phone_pattern.sub(" PHONE_TOKEN ", text)
    text = _currency_pattern.sub(" CURRENCY_TOKEN ", text)

    # Lowercase then fast regex tokenization (faster than Punkt)
    text = text.lower()
    tokens: List[str] = _token_pattern.findall(text)

    # Stopword removal and stemming (fast, no corpora)
    processed = []
    for token in tokens:
        if token in STOP_WORDS:
            continue
        stem = STEMMER.stem(token)
        processed.append(stem)

    return " ".join(processed)


def extract_content_features(raw_text: str) -> Dict[str, float]:
    """
    Extract content-based features that are strong indicators of spam/phishing.
    Returns a dictionary of feature scores (0.0 to 1.0).
    """
    if not raw_text:
        return {}
    
    features = {}
    text_lower = raw_text.lower()
    
    # URL-related features
    urls = _url_pattern.findall(raw_text)
    features['url_count'] = min(len(urls) / 5.0, 1.0)  # Normalize to 0-1
    features['has_url'] = 1.0 if urls else 0.0
    
    # Email-related features
    emails = _email_pattern.findall(raw_text)
    features['email_count'] = min(len(emails) / 3.0, 1.0)
    features['has_email'] = 1.0 if emails else 0.0
    
    # Phone number features
    phones = _phone_pattern.findall(raw_text)
    features['phone_count'] = min(len(phones) / 2.0, 1.0)
    features['has_phone'] = 1.0 if phones else 0.0
    
    # Currency/money features
    currencies = _currency_pattern.findall(raw_text)
    features['currency_count'] = min(len(currencies) / 3.0, 1.0)
    features['has_currency'] = 1.0 if currencies else 0.0
    
    # Urgency indicators
    urgent_matches = _urgent_pattern.findall(text_lower)
    features['urgency_score'] = min(len(urgent_matches) / 3.0, 1.0)
    
    # Winner/prize indicators
    winner_matches = _winner_pattern.findall(text_lower)
    features['winner_score'] = min(len(winner_matches) / 3.0, 1.0)
    
    # Suspicious domain/action words
    suspicious_matches = _suspicious_domain_pattern.findall(text_lower)
    features['suspicious_action_score'] = min(len(suspicious_matches) / 5.0, 1.0)
    
    # HTML content features
    html_tags = _html_tag_pattern.findall(raw_text)
    features['html_complexity'] = min(len(html_tags) / 20.0, 1.0)
    features['has_html'] = 1.0 if html_tags else 0.0
    
    # Text length features
    text_length = len(raw_text)
    features['text_length_score'] = min(text_length / 2000.0, 1.0)
    
    # Capitalization features (common in spam)
    caps_ratio = sum(1 for c in raw_text if c.isupper()) / max(len(raw_text), 1)
    features['caps_ratio'] = min(caps_ratio * 2, 1.0)  # Amplify for detection
    
    # Exclamation marks (common in spam)
    exclamation_count = raw_text.count('!')
    features['exclamation_score'] = min(exclamation_count / 5.0, 1.0)
    
    return features


def enhanced_clean_text(raw_text: str) -> Tuple[str, Dict[str, float]]:
    """
    Enhanced preprocessing that returns both cleaned text and content features.
    This allows the model to use both textual patterns and structured features.
    """
    cleaned = clean_text(raw_text)
    features = extract_content_features(raw_text)
    return cleaned, features


