<<<<<<< HEAD
# PhishGuard AI — NLP-Based Phishing Email Detector

A complete educational project with a polished Streamlit dashboard, local NLP pipeline, explainable indicators, `.eml` parsing, SQLite history, CSV export, and a model evaluation page.

## Features

- Dark cybersecurity dashboard with Overview, Analyze Email, History & Reports, Model Lab, and About pages
- TF-IDF word n-grams (1–3) + Logistic Regression classifier
- NLP preprocessing preview with optional spaCy lemmatization / stop-word removal
- Optional spaCy Named Entity Recognition if `en_core_web_sm` is installed
- Phishing-phrase indicators for urgency, credential requests, impersonation, financial pressure, and suspicious rewards
- URL extraction and basic structural checks; URLs are **never visited**
- Combined risk indicator, evidence, next-step recommendations, and technical details
- Parse `.eml` and `.txt` uploads
- SQLite local analysis history, filtering, clearing, and CSV export
- Model Lab with accuracy, precision, recall, F1, classification report, and confusion matrix
- Synthetic example dataset for local demonstration

## Important limitations

The bundled dataset is intentionally small and synthetic. This project demonstrates a workflow; it does **not** establish production-grade accuracy. Risk scores are heuristic/model indicators, not calibrated probabilities. It cannot reliably determine whether a message was authored by an LLM. A polished email can be malicious, and a legitimate email can be AI-written. Always verify sensitive requests through a known trusted channel.

## Requirements

- Python 3.10+
- VS Code recommended

## Run on Windows (PowerShell)

1. Extract the ZIP and open the `PhishGuard_NLP` folder in VS Code.
2. Open Terminal → New Terminal.
3. Create a virtual environment and install packages:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If activation is blocked by PowerShell policy, try:

```powershell
.\.venv\Scripts\activate.bat
```

4. Optional: install spaCy's English model for better lemmatization and entity recognition:

```powershell
python -m spacy download en_core_web_sm
```

The app runs without this model; optional entity extraction will return no entities and token preview will use a simple fallback.
5. Run the dashboard:

```powershell
streamlit run app.py
```

If that command is not found, use `python -m streamlit run app.py`.
6. Open the local URL printed in the terminal, normally `http://localhost:8501`.

## macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m spacy download en_core_web_sm  # optional
streamlit run app.py
```

## Project structure

```text
PhishGuard_NLP/
├── app.py
├── requirements.txt
├── README.md
├── phishguard/
│   ├── __init__.py
│   └── engine.py
├── data/
│   ├── email_samples.csv
│   └── README.md
└── tests/
    └── test_engine.py
```

## Use the dashboard

- **Overview:** activity charts, recent analyses, risk distribution, quick sample action
- **Analyze Email:** paste content or upload `.eml` / `.txt`, inspect risk, evidence, entities, and links
- **History & Reports:** search/filter previous analyses and export CSV
- **Model Lab:** run a small held-out evaluation on the synthetic dataset
- **About:** methodology and limitations

## Replace the demo dataset

Replace `data/email_samples.csv` with a labeled CSV containing columns `label,text`. Labels must be `phishing` or `legitimate`. Preserve a sufficiently large and balanced set of examples. If changing the dataset, clear `data/phishguard_history.sqlite3` only if you also want to remove prior local history.

## Viva explanation

1. **Preprocessing:** normalize text, replace URLs/emails with placeholders, optionally lemmatize using spaCy.
2. **Vectorization:** TF-IDF turns words and phrases into weighted numeric features; 1–3 grams capture both individual terms and multiword cues.
3. **Classification:** Logistic Regression estimates a class score from learned text patterns.
4. **Heuristics:** transparent phrase and URL indicators provide additional evidence.
5. **Evaluation:** precision, recall, F1, and confusion matrix measure test-set performance.
6. **Research extension:** evaluate separately on held-out LLM-generated and human-written messages to measure generalization.
=======
# Phishguard-AI
PhishGuard AI is a machine learning-based application designed to analyze emails and identify potential phishing threats using Natural Language Processing (NLP) and security indicators. It provides an interactive dashboard that helps users assess suspicious emails, understand potential risks, and review analysis results.
>>>>>>> 391efea1f916b6c78ecf153fa30edcfe760a02da
