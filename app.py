import io
import pandas as pd
import streamlit as st
import plotly.express as px
from phishguard.engine import analyze_email, parse_eml, load_history, save_history, clear_history, load_demo_data, evaluate_model, get_model_info

st.set_page_config(page_title="PhishGuard AI | Email Security", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');
:root { --bg:#0a0f1d; --panel:#101a2d; --panel2:#15223a; --line:#243653; --muted:#9aaac4; --cyan:#57d6d0; --purple:#9b8cff; }
.stApp { background: radial-gradient(ellipse at top left, #152544 0%, #0a0f1d 48%); color:#edf3ff; font-family:'DM Sans',sans-serif; }
[data-testid="stSidebar"] { background:#0e1729; border-right:1px solid #22324d; }
[data-testid="stSidebar"] * { color:#dce6f7; }
h1,h2,h3 { font-family:'Space Grotesk',sans-serif !important; letter-spacing:-.025em; }
.hero { padding: 1.45rem 1.6rem; border:1px solid #2b4164; border-radius:22px; background:linear-gradient(120deg,rgba(29,52,89,.94),rgba(19,27,48,.94)); margin-bottom:1.1rem; box-shadow:0 14px 45px rgba(0,0,0,.16); }
.hero h1 { margin:0; font-size:2.45rem; color:#f7faff; }
.hero p { margin:.45rem 0 0 0; color:#b4c7e4; font-size:1.02rem; }
.eyebrow { color:#57d6d0; text-transform:uppercase; letter-spacing:.15em; font-size:.72rem; font-weight:700; }
.kicker { color:#aabbd5; font-size:.88rem; }
[data-testid="stMetric"] { background:rgba(16,26,45,.86); border:1px solid #263a58; padding:15px 17px; border-radius:16px; }
[data-testid="stMetricLabel"] { color:#aabbd5 !important; }
div[data-testid="stTabs"] button { font-weight:600; }
div[data-testid="stDataFrame"] { border:1px solid #263a58; border-radius:14px; overflow:hidden; }
.stButton>button, .stDownloadButton>button { border-radius:10px; border:1px solid #345074; font-weight:600; }
div[data-testid="stForm"] { border:1px solid #263a58; border-radius:16px; padding:1rem; }
.pill { display:inline-block; border-radius:999px; padding:4px 10px; font-size:.76rem; font-weight:700; border:1px solid #3b526f; background:#17263f; color:#dbe8ff; }
.muted { color:#9aaac4; }
</style>
""", unsafe_allow_html=True)

def metric_row(history):
    if history.empty:
        total, flagged, avg = 0, 0, 0
    else:
        total = len(history)
        flagged = int((history["label"] == "Likely phishing").sum())
        avg = float(history["risk_score"].mean())
    a,b,c,d = st.columns(4)
    a.metric("Emails analyzed", f"{total:,}", help="Analysis history stored locally in SQLite")
    b.metric("Flagged as phishing", f"{flagged:,}")
    c.metric("Average risk score", f"{avg:.0f}/100" if total else "—")
    d.metric("Model", "NLP baseline", help="TF-IDF + Logistic Regression; heuristic indicators are shown separately")

st.sidebar.markdown("## 🛡️ PhishGuard AI")
st.sidebar.caption("NLP-powered email threat analysis")
# Apply navigation requests before creating the radio widget. Streamlit does not
# allow changing a widget's own session-state key after that widget is instantiated.
if "pending_page" in st.session_state:
    st.session_state["page"] = st.session_state.pop("pending_page")
page = st.sidebar.radio("WORKSPACE", ["Overview", "Analyze Email", "History & Reports", "Model Lab", "About"], key="page")
st.sidebar.markdown("---")
st.sidebar.markdown("**Privacy-first demo**")
st.sidebar.caption("Emails are analyzed locally. History is stored in a local SQLite file unless you clear it.")
st.sidebar.markdown("---")
st.sidebar.caption("Research prototype — verify suspicious emails through trusted channels.")

history = load_history()

st.markdown('<div class="hero"><div class="eyebrow">EMAIL THREAT INTELLIGENCE</div><h1>PhishGuard <span style="color:#57d6d0">AI</span></h1><p>Inspect suspicious emails with NLP, interpretable signals, and a clear audit trail.</p></div>', unsafe_allow_html=True)

if page == "Overview":
    metric_row(history)
    left, right = st.columns([1.3,1])
    with left:
        st.subheader("Security activity")
        if not history.empty:
            trend = history.copy()
            trend["analyzed_at"] = pd.to_datetime(trend["analyzed_at"], errors="coerce")
            trend = trend.dropna(subset=["analyzed_at"]).set_index("analyzed_at").resample("D").size().reset_index(name="analyses")
            fig = px.area(trend, x="analyzed_at", y="analyses", title="Email analysis volume", markers=True)
            fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=300, margin=dict(l=10,r=10,t=55,b=10))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Your activity chart will appear after you analyze emails.")
        st.subheader("Recent analyses")
        if history.empty:
            st.caption("No analyses yet. Open **Analyze Email** to inspect a message.")
        else:
            view = history[["analyzed_at","subject","sender","label","risk_score"]].head(8).copy()
            st.dataframe(view, use_container_width=True, hide_index=True)
    with right:
        st.subheader("Risk distribution")
        if not history.empty:
            dist = history["label"].value_counts().rename_axis("result").reset_index(name="count")
            fig = px.pie(dist, names="result", values="count", hole=.68, title="Classification results")
            fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=300, margin=dict(l=10,r=10,t=55,b=10), legend=dict(orientation="h",y=-.1))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No classification results to chart yet.")
        st.markdown("#### Quick actions")
        if st.button("Analyze a sample phishing email", use_container_width=True):
            st.session_state["prefill_email"] = "Subject: Urgent account verification\nFrom: security-alert@example-mail.test\n\nYour account will be suspended today. Verify your password immediately using http://account-verify.example.test/login to avoid losing access."
            st.session_state["prefill_subject"] = "Urgent account verification"
            st.session_state["prefill_sender"] = "security-alert@example-mail.test"
            st.session_state["prefill_nav"] = "Analyze Email"
            st.session_state["pending_page"] = "Analyze Email"
            st.rerun()
        if st.button("Load sample evaluation data", use_container_width=True):
            st.session_state["show_eval"] = True
            st.session_state["pending_page"] = "Model Lab"
            st.rerun()

elif page == "Analyze Email":
    st.subheader("Analyze an email")
    st.write("Paste an email or upload an `.eml` file. Keep sensitive messages local; this prototype does not call an external LLM.")
    demo_df = load_demo_data()
    demo_df["label"] = demo_df["label"].astype(str).str.lower()
    sample_options = ["Choose a sample email…"] + [
        f"{'🚨 Phishing' if row.label == 'phishing' else '✅ Legitimate'} — {str(row.text)[:76]}{'…' if len(str(row.text)) > 76 else ''}"
        for row in demo_df.itertuples(index=False)
    ]
    sample_choice = st.selectbox("Try a sample email", sample_options, index=0,
                                 help="Load a bundled example into the form. These examples are synthetic and for demonstration only.")
    sample_index = sample_options.index(sample_choice) - 1 if sample_choice != sample_options[0] else -1
    sample_subject, sample_sender, sample_body = "", "", ""
    if sample_index >= 0:
        sample_row = demo_df.iloc[sample_index]
        sample_body = str(sample_row["text"])
        sample_subject = "Urgent account notice" if sample_row["label"] == "phishing" else "Project update"
        sample_sender = "security-alert@example-mail.test" if sample_row["label"] == "phishing" else "team@example.test"
        st.caption(f"Selected example type: {'Phishing' if sample_row['label'] == 'phishing' else 'Legitimate'} · Synthetic demo email")

    uploaded = st.file_uploader("Upload email file (.eml or .txt)", type=["eml","txt"])
    uploaded_text = ""
    parsed = {}
    if uploaded:
        raw = uploaded.getvalue()
        if uploaded.name.lower().endswith(".eml"):
            parsed = parse_eml(raw)
            uploaded_text = parsed.get("body","")
        else:
            uploaded_text = raw.decode("utf-8", errors="replace")
    default_subject = sample_subject or parsed.get("subject","")
    default_sender = sample_sender or parsed.get("sender","")
    default_body = sample_body or uploaded_text
    if st.session_state.get("prefill_nav") == "Analyze Email":
        default_subject = st.session_state.pop("prefill_subject", default_subject)
        default_sender = st.session_state.pop("prefill_sender", default_sender)
        default_body = st.session_state.pop("prefill_email", default_body)
        st.session_state.pop("prefill_nav", None)
    with st.form("analyze_form"):
        subject = st.text_input("Subject", value=default_subject)
        sender = st.text_input("Sender address", value=default_sender)
        body = st.text_area("Email body", value=default_body, height=230, placeholder="Paste the email content here…")
        submitted = st.form_submit_button("Analyze email", type="primary", use_container_width=True)
    if submitted:
        result = analyze_email(subject, sender, body)
        save_history(subject, sender, body, result)
        st.session_state["last_result"] = result
        st.session_state["last_email"] = {"subject":subject,"sender":sender,"body":body}
    result = st.session_state.get("last_result")
    if result:
        st.markdown("---")
        risk = result["risk_score"]
        label = result["label"]
        color = "#ff657a" if label == "Likely phishing" else "#f3c969" if label == "Needs review" else "#57d6d0"
        st.markdown(f'<div class="hero"><div class="eyebrow">ANALYSIS RESULT</div><h2 style="color:{color};margin:.3rem 0">{label}</h2><p>Risk score: <b>{risk}/100</b> · {result["risk_band"]}</p></div>', unsafe_allow_html=True)
        c1,c2,c3 = st.columns(3)
        c1.metric("NLP model score", f'{result["model_score"]*100:.1f}%', help="Baseline model probability, trained on the bundled synthetic sample data. Not a calibrated real-world probability.")
        c2.metric("Heuristic indicators", f'{result["heuristic_score"]}/100')
        c3.metric("URLs detected", len(result["urls"]))
        left,right = st.columns([1.05,1])
        with left:
            st.markdown("#### Why it was flagged")
            if result["reasons"]:
                for reason in result["reasons"]:
                    st.markdown(f"- {reason}")
            else:
                st.success("No high-risk indicators were detected by this baseline.")
            st.markdown("#### NLP signals")
            st.write("**Matched phrases:**", ", ".join(result["matched_phrases"]) if result["matched_phrases"] else "None detected")
            st.write("**Named entities:**", ", ".join(result["entities"]) if result["entities"] else "None detected")
        with right:
            st.markdown("#### Detected links")
            if result["urls"]:
                for url in result["urls"]:
                    st.code(url, language=None)
            else:
                st.caption("No URLs detected.")
            st.markdown("#### Suggested next steps")
            for action in result["actions"]:
                st.write("• " + action)
        with st.expander("Technical details"):
            st.json({k:v for k,v in result.items() if k not in ["body","raw_text"]})
        st.warning("This is a decision-support prototype, not a guarantee of safety. A low score does not prove an email is legitimate. Do not click links or enter credentials to test them.")

elif page == "History & Reports":
    st.subheader("Analysis history & reports")
    history = load_history()
    if history.empty:
        st.info("No history yet. Analyze an email to create a record.")
    else:
        col1,col2,col3 = st.columns(3)
        labels = ["All"] + sorted(history["label"].dropna().unique().tolist())
        selected_label = col1.selectbox("Filter by result", labels)
        search = col2.text_input("Search subject or sender")
        min_score = col3.slider("Minimum risk score", 0, 100, 0)
        view = history.copy()
        if selected_label != "All":
            view = view[view["label"] == selected_label]
        if search:
            mask = view["subject"].fillna("").str.contains(search, case=False, regex=False) | view["sender"].fillna("").str.contains(search, case=False, regex=False)
            view = view[mask]
        view = view[view["risk_score"] >= min_score]
        st.dataframe(view[["analyzed_at","subject","sender","label","risk_score","risk_band"]], use_container_width=True, hide_index=True)
        st.download_button("Export filtered history (CSV)", view.to_csv(index=False).encode("utf-8"), "phishguard_history.csv", "text/csv")
        if st.button("Clear all local history", type="secondary"):
            clear_history()
            st.success("Local history cleared.")
            st.rerun()

elif page == "Model Lab":
    st.subheader("Model Lab")
    st.write("Evaluate the baseline on the bundled **synthetic** sample dataset. These results are for demonstration, not evidence of production accuracy.")
    # The Overview quick action requests an evaluation on arrival to this page.
    if st.session_state.pop("show_eval", False):
        st.session_state["eval_result"] = evaluate_model()
    info = get_model_info()
    a,b,c = st.columns(3)
    a.metric("Vectorizer", info["vectorizer"])
    b.metric("Classifier", info["classifier"])
    c.metric("Training examples", info["training_examples"])
    run_evaluation = st.button("Run evaluation", type="primary")
    if st.session_state.pop("show_eval", False):
        run_evaluation = True
    if run_evaluation:
        metrics, report, cm = evaluate_model()
        st.session_state["eval_result"] = (metrics, report, cm)
    if "eval_result" in st.session_state:
        metrics, report, cm = st.session_state["eval_result"]
        x,y,z = st.columns(3)
        x.metric("Accuracy", f'{metrics["accuracy"]*100:.1f}%')
        y.metric("Precision", f'{metrics["precision"]*100:.1f}%')
        z.metric("Recall", f'{metrics["recall"]*100:.1f}%')
        st.caption("Synthetic dataset is small and can produce overly optimistic results. Use a larger independent dataset and split by source/time for a meaningful evaluation.")
        st.code(report, language="text")
        fig = px.imshow(cm, text_auto=True, x=["Legitimate","Phishing"], y=["Legitimate","Phishing"], labels=dict(x="Predicted",y="Actual"), title="Confusion matrix")
        fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True)

elif page == "About":
    st.subheader("About PhishGuard AI")
    st.markdown("""
**Goal:** demonstrate how NLP and classical machine learning can support phishing-email triage.

**NLP techniques included**
- Email text preprocessing and lemmatization (spaCy if installed; safe fallback otherwise)
- TF-IDF with word unigrams, bigrams, and character n-grams
- Logistic Regression classification
- Phrase-level indicators for urgency, credential theft, and impersonation
- Named Entity Recognition (optional spaCy model)
- URL extraction and basic structural checks
- Model evaluation using precision, recall, F1-score, and a confusion matrix

**LLM-generated phishing angle:** this app detects phishing-like content and indicators; it does not reliably determine whether an email was authored by an LLM. To study that question, evaluate separately on held-out human-written and LLM-generated phishing/legitimate emails.

**Privacy:** pasted text is processed locally by this application. Do not deploy it publicly without adding authentication, secure storage, retention controls, and security review.
""")
    st.markdown("#### Project limitations")
    st.write("- Included training data is small and synthetic.")
    st.write("- Heuristics can be bypassed and can flag benign security notices.")
    st.write("- URL checks are structural only; the app does not visit URLs or query threat-intelligence services.")
    st.write("- Always verify sensitive requests through a known official channel.")

st.markdown("---")
st.markdown('<div class="muted" style="font-size:.8rem">PHISHGUARD AI · Educational security prototype · NLP + interpretable indicators</div>', unsafe_allow_html=True)
