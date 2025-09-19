# 📧 Email Spam Detection (LSTM + Cyber Defense)

An end-to-end web app that detects spam and phishing emails using a Deep Learning LSTM model, enhanced with practical cyber defense heuristics (URL intelligence and email authentication checks). Built with Flask, modular services, and a clean UI for clear, explainable results. 🚀

---

## ✨ Features
- 🧠 Deep Learning LSTM classifier (Keras/TensorFlow) for email content
- 🔤 Robust NLP preprocessing: HTML clean, URL/email removal, regex tokenization, stopword removal, stemming
- 🔗 URL Intelligence: suspicious TLDs, raw IP hosts, deep paths, long queries, punycode
- 🛡️ Email authentication parsing: SPF, DKIM, DMARC from `Authentication-Results` / `Received-SPF`
- 🧩 Ensemble scoring: LSTM + URL risk + header risk
- ⚖️ Rule-based overrides to raise recall on obvious phishing patterns
- 📊 Rich UI: status indicators, charts, risk meter, analyzed content
- 🧾 History logging (SQLite): message, prediction, category, score, timestamp
- 🧱 Modular code structure for easy extension

---

## 🧰 Tech Stack
- Backend: Python, Flask
- DL/NLP: TensorFlow/Keras, NumPy, scikit‑learn, NLTK (regex tokenizer + PorterStemmer), Keras `Tokenizer`
- Frontend: Bootstrap 5, Chart.js, Moment.js, custom CSS
- Storage: SQLite for predictions history

---

## 🗂️ Project Structure
```
email-spam-detector/
  app.py                     # Flask routes and inference flow
  requirements.txt          # Python dependencies
  spam.csv                  # Dataset
  model/
    lstm_model.h5           # Trained LSTM model
    tokenizer.pkl           # Fitted Keras Tokenizer
    category_encoder.pkl    # Optional category encoder
    predictions.db          # SQLite history (auto-created)
  nlp/
    preprocess.py           # Robust NLP cleaner
  services/
    model_service.py        # LSTM wrapper + ensemble blend
    url_intel.py            # URL extraction + risk features
    header_auth.py          # SPF/DKIM/DMARC parser
    homograph.py            # IDN/punycode detection
  templates/
    index.html              # Main UI
    history.html            # History page
  static/
    style.css               # Styling
  train_model.ipynb         # Model training notebook
  README.md
```

---

## ⚙️ Setup & Installation
1) Clone and enter the project
```bash
git clone https://github.com/<your-username>/email-spam-detector.git
cd email-spam-detector
```

2) Create and activate a virtual environment (Windows PowerShell)
```bash
python -m venv venv
venv\Scripts\activate
```

3) Install dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

4) Place model artifacts
- Ensure these files exist under `model/`:
  - `lstm_model.h5`
  - `tokenizer.pkl`
  - `category_encoder.pkl` (optional; app falls back gracefully)

5) Run the app
```bash
python app.py
```
Then open your browser at `http://127.0.0.1:5000/`.

---

## 🧪 How to Use
1) Paste email text in the "Email Content Analysis" box.
2) (Optional) Paste full Raw Email Headers to enable SPF/DKIM/DMARC parsing.
3) Click "Initiate Deep Analysis".
4) Review the report: prediction, confidence, URL intelligence, and header checks.
5) View recent results in the History page.

Tip: For accurate auth results, include complete `Authentication-Results` and `Received-SPF` headers.

---

## 🔬 Deep Learning (Model & Methodology)
- Tokenization: Keras `Tokenizer` → integer sequences
- Sequence length: 100 tokens (model input)
- Architecture: Embedding → LSTM → Dense head(s)
  - Binary head: Spam vs Not Spam
  - Optional category head: Spam category probabilities
- Loss: Binary cross‑entropy (+ categorical loss if category head used)
- Optimizer: Adam; early stopping on validation loss
- Inference flow:
  - Clean text → tokenize → pad → LSTM spam score → blend with URL/header risk → rule-based overrides → final decision

---

## 🛡️ Cyber Defense Heuristics
- URL Risk (services/url_intel.py):
  - Suspicious TLDs set (e.g., .zip, .mov, .click, .xyz) ✅ configurable
  - Raw IP hosts and excessive path depth
  - Long query strings and punycode detection
- Header Auth (services/header_auth.py):
  - Unfolds headers to handle line wrapping
  - Parses `Authentication-Results`, `ARC-Authentication-Results`, and fallback scanning
  - Derives SPF/DKIM/DMARC: pass, fail, or unknown
- Decision Overrides (app.py):
  - If DMARC fail or SPF+DKIM fail with risky URL → spam score ≥ 0.90
  - If either fails or URL risk high → spam score ≥ 0.75
  - Threshold set to 0.45 to improve recall

---

## 🧪 Training Your Own Model
Use `train_model.ipynb` as a reference:
- Load `spam.csv`, split into train/val/test
- Fit `Tokenizer` on training text; persist `tokenizer.pkl`
- Build LSTM → train with early stopping
- Save `lstm_model.h5` and optional `category_encoder.pkl`
- Validate with Precision/Recall/F1 and ROC‑AUC; tune threshold for desired tradeoffs

---

## 🚀 Production Tips
- Use `gunicorn` (Linux/macOS) or `waitress` (Windows) for production serving
- Configure TensorFlow threading for performance
- Add caching for header/URL parsing if you integrate external lookups later
- Log predictions (already enabled via SQLite) for periodic threshold tuning

---

## 🧩 Troubleshooting
- Model input shape error (expected 100, got N): ensure padding length is 100 and your saved model uses input shape (None, 100)
- Always "unknown" for SPF/DKIM/DMARC: paste full raw headers including `Authentication-Results` and `Received-SPF`
- Slow first request: model warmup happens at startup; subsequent predictions are faster
- Dependency issues: recreate venv and reinstall `requirements.txt`

---

## 📝 License
This project is provided for educational and research purposes. Add an OSI license (e.g., MIT) if you plan to open source it.

---

## 🙌 Acknowledgements
- Keras/TensorFlow team for DL components
- Bootstrap/Chart.js for UI/visualizations

Happy phishing detection! 🛡️🐟
