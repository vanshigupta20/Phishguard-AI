from phishguard.engine import analyze_email, parse_eml, load_demo_data

def test_demo_dataset_has_both_classes():
    df = load_demo_data()
    assert set(df["label"]) == {"phishing", "legitimate"}

def test_parse_eml():
    raw = b"From: alerts@example.test\r\nSubject: Hello\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThis is a body."
    parsed = parse_eml(raw)
    assert parsed["subject"] == "Hello"
    assert "This is a body" in parsed["body"]

def test_analysis_has_expected_fields():
    result = analyze_email("Urgent account verification", "security@example.test",
                           "Verify your password immediately at http://example.test/login")
    assert result["label"] in {"Likely phishing", "Needs review", "Likely legitimate"}
    assert 0 <= result["risk_score"] <= 100
    assert result["urls"]
