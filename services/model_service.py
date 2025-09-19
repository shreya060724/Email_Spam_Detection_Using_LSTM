import os
import pickle
from typing import Tuple, Dict

import numpy as np
from keras.models import load_model
from keras.preprocessing.sequence import pad_sequences
from typing import Optional


class LSTMService:
    """
    Wraps the trained LSTM model and tokenizer to produce:
    - Binary spam probability
    - Multi-class category distribution (if provided by model)
    """

    def __init__(self, model_path: str, tokenizer_path: str, max_len: int = 100):
        self.model = load_model(model_path)
        with open(tokenizer_path, 'rb') as f:
            self.tokenizer = pickle.load(f)
        self.max_len = max_len
        # Warm up the model once to initialize graph/kernels
        try:
            _ = self.model.predict(pad_sequences([[0]], maxlen=self.max_len), verbose=0)
        except Exception:
            pass

    def predict(self, text: str) -> Tuple[float, np.ndarray]:
        seq = self.tokenizer.texts_to_sequences([text])
        padded = pad_sequences(seq, maxlen=self.max_len)
        preds = self.model.predict(padded, verbose=0)
        if isinstance(preds, list) or isinstance(preds, tuple):
            spam_prob = float(preds[0][0][0])
            category_probs = np.array(preds[1][0])
        else:
            spam_prob = float(preds[0][0])
            category_probs = np.array([])
        return spam_prob, category_probs


class EnsembleService:
    """
    Optional soft-voting ensemble that blends the LSTM spam score with
    additional heuristics (e.g., URL risk) for improved robustness.
    """

    def __init__(self, lstm_service: LSTMService, url_weight: float = 0.25, header_weight: float = 0.35, phrase_weight: float = 0.15, display_weight: float = 0.10):
        self.lstm = lstm_service
        self.url_weight = url_weight
        self.header_weight = header_weight
        self.phrase_weight = phrase_weight
        self.display_weight = display_weight

    def blend(self, cleaned_text: str, url_risk_score: float, header_findings: Optional[Dict] = None, phrase_score: float = 0.0, display_mismatch: float = 0.0) -> Dict[str, float]:
        spam_prob, category_probs = self.lstm.predict(cleaned_text)

        # Header-based risk: penalize fail signals; unknown contributes little
        header_risk = 0.0
        if header_findings and header_findings.get('present'):
            spf = header_findings.get('spf', 'unknown')
            dkim = header_findings.get('dkim', 'unknown')
            dmarc = header_findings.get('dmarc', 'unknown')
            header_risk += 0.4 if spf == 'fail' else (0.05 if spf == 'unknown' else 0.0)
            header_risk += 0.35 if dkim == 'fail' else (0.05 if dkim == 'unknown' else 0.0)
            header_risk += 0.5 if dmarc == 'fail' else (0.05 if dmarc == 'unknown' else 0.0)
            header_risk = float(np.clip(header_risk, 0.0, 1.0))

        # Soft-vote: weighted average between LSTM, URL heuristic, and SBERT heuristic
        base_weight = 1.0 - self.url_weight - self.header_weight - self.phrase_weight - self.display_weight
        base_weight = max(0.0, base_weight)
        blended_spam = (
            base_weight * spam_prob
            + self.url_weight * url_risk_score
            + self.header_weight * header_risk
            + self.phrase_weight * float(np.clip(phrase_score, 0.0, 1.0))
            + self.display_weight * float(np.clip(display_mismatch, 0.0, 1.0))
        )
        blended_spam = float(np.clip(blended_spam, 0.0, 1.0))

        return {
            'spam_prob': blended_spam,
            'raw_spam_prob': float(spam_prob),
            'category_probs': category_probs.tolist() if category_probs.size else []
        }


