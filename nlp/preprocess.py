import re
import html
from typing import List

from nltk.stem import PorterStemmer


# Ensure NLTK resources are available at runtime
# No corpus downloads; use lightweight stemming and a static stopword list


_url_pattern = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
_email_pattern = re.compile(r"[\w\.-]+@[\w\.-]+", re.IGNORECASE)
_html_tag_pattern = re.compile(r"<[^>]+>")
_token_pattern = re.compile(r"[a-z]{2,}")

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
    - Remove URLs and email addresses
    - Lowercase and remove non-alphabetic chars
    - Tokenize, remove stopwords
    - Lemmatize tokens and re-join
    """
    if not raw_text:
        return ""

    # Decode HTML entities and strip tags
    text = html.unescape(raw_text)
    text = _html_tag_pattern.sub(" ", text)

    # Remove URLs and emails early to reduce noise
    text = _url_pattern.sub(" ", text)
    text = _email_pattern.sub(" ", text)

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


