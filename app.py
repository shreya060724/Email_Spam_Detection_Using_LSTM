from flask import Flask, render_template, request
import numpy as np
from datetime import datetime
import sqlite3
import os
from flask_moment import Moment

# Modular services for NLP and inference
from nlp.preprocess import clean_text
from services.model_service import LSTMService, EnsembleService
from services.url_intel import extract_urls, analyze_urls, compute_url_risk
from services.header_auth import parse_auth_headers
from services.homograph import detect_homograph
from services.heuristics import phishing_phrase_score, display_name_domain_mismatch, apply_allowlist
import pickle


app = Flask(__name__)
moment = Moment(app)


# 🔹 Model path
DB_PATH = os.path.join("model", "predictions.db")
os.makedirs("model", exist_ok=True)

# 🔹 Create DB table if not exists
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
c.execute('''
    CREATE TABLE IF NOT EXISTS predictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT,
        prediction TEXT,
        category TEXT,
        spam_score REAL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
''')
conn.commit()
conn.close()

# 🔹 Load ML artifacts
# LSTM model service wraps the Keras model and tokenizer for prediction
lstm_service = LSTMService(
    model_path='model/lstm_model.h5',
    tokenizer_path='model/tokenizer.pkl',
    max_len=100
)

# Optional: soft-voting ensemble to blend URL risk with LSTM score
ensemble = EnsembleService(lstm_service=lstm_service, url_weight=0.15)

# Multi-class label encoder for threat category
with open('model/category_encoder.pkl', 'rb') as f:
    category_encoder = pickle.load(f)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    message = request.form['message']
    raw_headers = request.form.get('headers', '').strip()

    # ---------- NLP Preprocessing (robust) ----------
    # Clean the raw email text using NLTK: remove URLs/emails, tokenize, stopwords, lemmatize
    cleaned_text = clean_text(message)

    # ---------- URL/Domain Intelligence ----------
    urls_in_message = extract_urls(message)
    url_findings = analyze_urls(urls_in_message)
    url_risk_score = compute_url_risk(url_findings)

    # Homograph intel for the first URL host (if any)
    homograph_info = None
    if urls_in_message:
        from urllib.parse import urlparse as _urlparse
        first_host = _urlparse(urls_in_message[0]).netloc
        homograph_info = detect_homograph(first_host)
        # Fold homograph into URL risk lightly
        extra_risk = (homograph_info.get('homograph_risk', 0.0) if homograph_info else 0.0)
        url_risk_score = float(np.clip(url_risk_score + extra_risk, 0.0, 1.0))

    # ---------- LSTM Prediction (+ optional ensemble) ----------
    # Use LSTM for spam probability and category distribution; blend with URL, headers, SBERT
    # Parse headers before blending to incorporate header risk
    header_findings = parse_auth_headers(raw_headers)
    # Heuristic boosters
    phrase_score = phishing_phrase_score(message)
    display_mismatch = display_name_domain_mismatch(raw_headers)

    blended = ensemble.blend(cleaned_text=cleaned_text,
                             url_risk_score=url_risk_score,
                             header_findings=header_findings,
                             phrase_score=phrase_score,
                             display_mismatch=display_mismatch)
    spam_prob = blended['spam_prob']
    category_probs = np.array(blended['category_probs']) if blended['category_probs'] else np.array([])

    # ---------- Rule-based safety overrides ----------
    has_risky_url = any([
        (u.get('is_suspicious_tld') or u.get('has_ip_host') or (u.get('path_depth', 0) or 0) > 4 or u.get('long_query'))
        for u in (url_findings or [])
    ])
    header_fail = False
    if header_findings and header_findings.get('present'):
        spf = header_findings.get('spf')
        dkim = header_findings.get('dkim')
        dmarc = header_findings.get('dmarc')
        header_fail = (dmarc == 'fail') or ((spf == 'fail') and (dkim == 'fail'))

    if header_fail and has_risky_url:
        spam_prob = max(spam_prob, 0.90)
    elif header_fail or (has_risky_url and url_risk_score > 0.40):
        spam_prob = max(spam_prob, 0.75)

    # Apply allowlist attenuation then final threshold
    spam_prob = apply_allowlist(spam_prob, raw_headers)
    prediction = "Spam" if spam_prob > 0.45 else "Not Spam"
    spam_pct = round(spam_prob * 100, 2)
    notspam_pct = round((1 - spam_prob) * 100, 2)

    # Classify spam type if model provides category distribution
    if category_probs.size:
        predicted_category_index = int(np.argmax(category_probs))
        predicted_category = category_encoder.inverse_transform([predicted_category_index])[0]
    else:
        predicted_category = 'General'

    # Store in DB
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO predictions (message, prediction, category, spam_score) VALUES (?, ?, ?, ?)",
              (message, prediction, predicted_category, spam_pct))
    conn.commit()
    conn.close()

    # ⏰ Add current UTC time for moment.js
    current_time = datetime.utcnow()
    # header_findings already computed above

    return render_template("index.html",
                           prediction=prediction,
                           category=predicted_category,
                           message=message,
                           spam=spam_pct,
                           notspam=notspam_pct,
                           current_time=current_time,
                           url_findings=url_findings,
                           header_findings=header_findings,
                           first_malicious_url=(urls_in_message[0] if urls_in_message else None),
                           homograph_info=homograph_info)


@app.route('/history')
def history():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT message, prediction, category, spam_score, timestamp FROM predictions ORDER BY id DESC LIMIT 10")
    rows = c.fetchall()
    conn.close()
    return render_template("history.html", predictions=rows)

if __name__ == '__main__':
    app.run(debug=True)
