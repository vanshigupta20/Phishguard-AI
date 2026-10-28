"""PhishGuard NLP engine. All analysis runs locally; URLs are never opened."""
import re
import sqlite3
from email import policy
from email.parser import BytesParser
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "email_samples.csv"
DB_PATH = ROOT / "data" / "phishguard_history.sqlite3"

PHISHING_PHRASES = {
    "credential request": ["verify your password", "confirm your password", "enter your credentials", "sign in to restore", "validate your login", "password expires", "reset your password immediately"],
    "urgency or threat": ["account will be suspended", "immediate action required", "within 24 hours", "final warning", "act now", "your account is locked", "avoid losing access", "unusual activity detected"],
    "financial pressure": ["wire transfer", "payment is overdue", "invoice attached", "update your payment", "gift card", "bank details"],
    "impersonation language": ["security team", "help desk", "ceo", "payroll department", "it administrator", "account support"],
    "suspicious reward": ["you have won", "claim your prize", "exclusive reward", "congratulations winner"],
}
URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\]\[\"']+")
SUSPICIOUS_TLDS = {".zip", ".mov", ".top", ".xyz", ".click", ".work", ".country", ".gq", ".tk"}

def _clean_text(text):
    text = str(text or "").lower()
    text = re.sub(r"(?i)\bhttps?://\S+|www\.\S+", " URLTOKEN ", text)
    text = re.sub(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", " EMAILTOKEN ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()

def _preprocess_for_display(text):
    try:
        import spacy
        try:
            nlp = spacy.load("en_core_web_sm")
            doc = nlp(str(text or ""))
            return [t.lemma_.lower() for t in doc if not t.is_space and not t.is_punct and not t.is_stop and t.lemma_.strip()]
        except OSError:
            pass
    except ImportError:
        pass
    return re.findall(r"\b[a-zA-Z][a-zA-Z0-9_-]{1,}\b", str(text or "").lower())

def _training_data():
    df = pd.read_csv(DATA_PATH).dropna(subset=["text","label"])
    df["label"] = df["label"].astype(str).str.lower().map({"legitimate":0,"phishing":1})
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)
    return df

def _make_pipeline():
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            preprocessor=_clean_text, lowercase=False, ngram_range=(1,3),
            min_df=1, max_features=12000, sublinear_tf=True,
            analyzer="word", token_pattern=r"(?u)\b\w[\w'-]+\b"
        )),
        ("clf", LogisticRegression(max_iter=1200, class_weight="balanced", random_state=42))
    ])

def _train_model():
    df = _training_data()
    model = _make_pipeline()
    model.fit(df["text"].astype(str), df["label"])
    return model, len(df)

_MODEL = None
_MODEL_COUNT = 0
def get_model():
    global _MODEL, _MODEL_COUNT
    if _MODEL is None:
        _MODEL, _MODEL_COUNT = _train_model()
    return _MODEL

def get_model_info():
    model = get_model()
    return {"vectorizer":"TF-IDF (1–3 word n-grams)", "classifier":"Logistic Regression", "training_examples":_MODEL_COUNT}

def parse_eml(raw_bytes):
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "text" and part.get_content_subtype() in {"plain","html"}:
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    continue
    else:
        try:
            body_parts.append(msg.get_content())
        except Exception:
            body_parts.append(raw_bytes.decode("utf-8", errors="replace"))
    body = "\n".join(str(p) for p in body_parts)
    body = re.sub(r"<(script|style)\b.*?</\1>", " ", body, flags=re.I|re.S)
    body = re.sub(r"<[^>]+>", " ", body)
    body = re.sub(r"&nbsp;|&amp;|&lt;|&gt;", " ", body, flags=re.I)
    return {"subject":str(msg.get("subject","")), "sender":str(msg.get("from","")), "body":body}

def _find_urls(text):
    return list(dict.fromkeys(u.rstrip(".,);!?") for u in URL_RE.findall(str(text or ""))))

def _url_indicators(urls, sender):
    notes = []
    sender_domain = ""
    match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", sender or "")
    if match:
        sender_domain = match.group(1).lower()
    for url in urls:
        candidate = url if url.lower().startswith(("http://","https://")) else "http://" + url
        try:
            parsed = urlparse(candidate)
            host = (parsed.hostname or "").lower()
            if not host:
                notes.append(f"Could not parse URL host: {url}")
                continue
            if parsed.scheme == "http":
                notes.append(f"Link uses unencrypted HTTP: {url}")
            if host.startswith("xn--") or ".xn--" in host:
                notes.append(f"URL contains an internationalized/punycode domain: {url}")
            if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
                notes.append(f"URL uses an IP address instead of a recognizable domain: {url}")
            suffix = "." + host.rsplit(".",1)[-1] if "." in host else ""
            if suffix in SUSPICIOUS_TLDS:
                notes.append(f"URL uses a less-common top-level domain ({suffix}): {url}")
            if "@" in parsed.netloc:
                notes.append(f"URL includes an @ sign in its authority section: {url}")
            if len(host) > 45 or host.count("-") >= 3:
                notes.append(f"URL host is unusually long or contains many hyphens: {url}")
            if sender_domain and host and sender_domain not in host and host not in sender_domain:
                notes.append(f"Link domain differs from sender domain; verify independently: {url}")
        except Exception:
            notes.append(f"Could not inspect URL: {url}")
    return notes

def _phrase_matches(text):
    lower = str(text or "").lower()
    matched = []
    categories = []
    for category, phrases in PHISHING_PHRASES.items():
        found = [phrase for phrase in phrases if phrase in lower]
        if found:
            categories.append(category)
            matched.extend(found)
    return categories, matched

def _entities(text):
    try:
        import spacy
        nlp = spacy.load("en_core_web_sm")
        doc = nlp(str(text or ""))
        found = []
        for ent in doc.ents:
            if ent.label_ in {"ORG","PERSON","GPE","MONEY","DATE","TIME"}:
                item = f"{ent.text} ({ent.label_})"
                if item not in found:
                    found.append(item)
        return found[:15]
    except Exception:
        return []

def analyze_email(subject, sender, body):
    full_text = f"Subject: {subject}\nFrom: {sender}\n\n{body}".strip()
    model = get_model()
    model_score = float(model.predict_proba([full_text])[0][1])
    categories, matched = _phrase_matches(full_text)
    urls = _find_urls(full_text)
    url_notes = _url_indicators(urls, sender)
    lower = full_text.lower()
    reasons = []
    if categories:
        reasons.append("Phishing-like language detected: " + ", ".join(categories) + ".")
    if url_notes:
        reasons.extend(url_notes[:5])
    if re.search(r"\b(password|passcode|otp|one[- ]time code|credentials|login details)\b", lower):
        reasons.append("Message mentions sensitive authentication information.")
    if re.search(r"\b(urgent|immediately|right now|within \d+ hours|final warning)\b", lower):
        reasons.append("Message uses urgency or time-pressure language.")
    if len(re.findall(r"[A-Z]{4,}", str(body or ""))) >= 3:
        reasons.append("Several all-caps words may be used to attract attention.")
    # Heuristic score is an indicator score, not a calibrated probability.
    heuristic = min(100, len(categories)*18 + min(len(url_notes), 5)*12 + (12 if "password" in lower or "credentials" in lower or "otp" in lower else 0) + (8 if "urgent" in lower or "immediately" in lower else 0))
    # Combined risk intentionally emphasizes the learned text classifier while retaining transparent heuristics.
    risk = int(round(min(100, max(0, model_score*65 + heuristic*0.35))))
    if risk >= 62:
        label, band = "Likely phishing", "High risk"
    elif risk >= 38:
        label, band = "Needs review", "Medium risk"
    else:
        label, band = "Likely legitimate", "Lower risk"
    if not reasons:
        reasons.append("No configured high-risk phrase or URL indicator was detected; this does not prove the email is safe.")
    actions = []
    if label == "Likely phishing" or label == "Needs review":
        actions += ["Do not click links or open attachments until independently verified.", "Contact the organization using a known official website or phone number.", "Report the message through your email provider or security team."]
    else:
        actions += ["Check the sender address and domain carefully.", "Treat unexpected attachments and requests for credentials with caution."]
    tokens = _preprocess_for_display(full_text)
    return {
        "label":label, "risk_band":band, "risk_score":risk,
        "model_score":round(model_score,4), "heuristic_score":heuristic,
        "urls":urls, "url_notes":url_notes, "reasons":reasons,
        "matched_phrases":matched, "entities":_entities(full_text),
        "tokens_preview":tokens[:80], "token_count":len(tokens),
        "actions":actions, "analyzed_at":datetime.now(timezone.utc).isoformat(),
        "subject":str(subject or ""), "sender":str(sender or "")
    }

def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS analyses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analyzed_at TEXT NOT NULL, subject TEXT, sender TEXT, body TEXT,
        label TEXT, risk_score INTEGER, risk_band TEXT, model_score REAL,
        heuristic_score INTEGER, urls TEXT, reasons TEXT
    )""")
    conn.commit()
    return conn

def save_history(subject, sender, body, result):
    import json
    with _connect() as conn:
        conn.execute("""INSERT INTO analyses
        (analyzed_at,subject,sender,body,label,risk_score,risk_band,model_score,heuristic_score,urls,reasons)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)""", (
            result["analyzed_at"], subject, sender, body, result["label"], result["risk_score"],
            result["risk_band"], result["model_score"], result["heuristic_score"],
            json.dumps(result["urls"]), json.dumps(result["reasons"])
        ))

def load_history():
    with _connect() as conn:
        df = pd.read_sql_query("SELECT id, analyzed_at, subject, sender, label, risk_score, risk_band, model_score, heuristic_score FROM analyses ORDER BY id DESC", conn)
    return df

def clear_history():
    with _connect() as conn:
        conn.execute("DELETE FROM analyses")

def load_demo_data():
    return pd.read_csv(DATA_PATH)

def evaluate_model():
    df = _training_data()
    X_train, X_test, y_train, y_test = train_test_split(
        df["text"].astype(str), df["label"], test_size=0.25, random_state=42, stratify=df["label"]
    )
    model = _make_pipeline()
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    metrics = {
        "accuracy":accuracy_score(y_test,pred),
        "precision":precision_score(y_test,pred,zero_division=0),
        "recall":recall_score(y_test,pred,zero_division=0),
        "f1":f1_score(y_test,pred,zero_division=0),
    }
    report = classification_report(y_test,pred,target_names=["Legitimate","Phishing"],zero_division=0)
    cm = confusion_matrix(y_test,pred,labels=[0,1])
    return metrics, report, cm
