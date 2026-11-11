"""Fast tests (no transformer downloads): locations, attack types, severity, scam checker,
assistant routing and safety, deepfake checks, knowledge base."""
import io

import pandas as pd
import pytest
from PIL import Image, PngImagePlugin

from cti import assistant
from cti.deepfake import error_level_analysis, inspect_image
from cti.knowledge.content import LESSONS, PLAYBOOKS, documents
from cti.news.analyze import analyze_articles, article_text, load_snapshot, severity
from cti.news.geo import detect_locations
from cti.news.taxonomy import detect_attack_types, detect_sectors
from cti.scam.checker import analyse_links, check_message


# ------------------------------------------------------------- locations
@pytest.mark.parametrize("text,states,countries", [
    ("Ransomware attack hits Texas hospital", ["Texas"], ["United States"]),
    ("Phishing scam targets customers in Chicago", ["Illinois"], ["United States"]),
    ("Hackers hit Ukraine's power grid", [], ["Ukraine"]),           # 'UK' must not match 'Ukraine'
    ("Breach at a New Mexico law firm", ["New Mexico"], ["United States"]),  # not Mexico
    ("Russian hackers target Indiana utility", ["Indiana"], ["Russia", "United States"]),  # Indiana is not India
    ("Tell us how the attack affected you", [], []),                # 'us' is not the US
])
def test_locations(text, states, countries):
    loc = detect_locations(text)
    assert loc["states"] == states and loc["countries"] == countries


def test_attack_types_and_sectors():
    assert detect_attack_types("LockBit ransomware encrypted files at a clinic") == ["Ransomware"]
    assert "Phishing" in detect_attack_types("Smishing texts impersonate USPS")
    assert detect_sectors("Cyber attack on the power grid and a hospital") == ["Healthcare", "Energy & utilities"]
    assert detect_sectors("New cybersecurity report published") == []   # 'cyber' alone is not a sector


def test_article_text_skips_repeated_title():
    assert article_text("Same", "Same") == "Same"
    assert article_text("Title", "Desc") == "Title. Desc"


def test_severity_levels_have_reasons():
    level, reasons = severity({"sentiment_score": -0.8, "fear": 0.7, "organizations": ["A", "B", "C"],
                               "attack_types": ["Ransomware"], "sectors": ["Healthcare"]})
    assert level == "CRITICAL" and any("Ransomware" in r for r in reasons)
    assert severity({})[0] == "LOW"


def test_rule_only_analysis():
    df = analyze_articles(pd.DataFrame([{"title": "Ransomware hits Texas hospital", "description": "",
                                         "source": "x", "date": "2026-01-01"}]), use_models=False)
    r = df.iloc[0]
    assert r["attack_types"] == ["Ransomware"] and r["states"] == ["Texas"] and r["severity"] in ("MEDIUM", "LOW")


def test_snapshot_loads():
    df = load_snapshot("data/news_snapshot.csv")
    assert len(df) == 60 and isinstance(df["attack_types"].iloc[0], list)
    assert set(df["severity"]) <= {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


# ----------------------------------------------------------- scam checker
@pytest.mark.parametrize("text,verdict", [
    ("USPS: Your package could not be delivered. Update here within 24 hours: https://usps-redelivery-help.top/track", "Likely scam"),
    ("Grandma it's me, I'm in jail. Please send money with gift cards, don't tell mom.", "Likely scam"),
    ("Microsoft Support: your computer is infected. Install AnyDesk so our technician can fix it.", "Likely scam"),
    ("Hi Sam, are we still on for lunch tomorrow at 12?", "No strong scam signs"),
])
def test_scam_verdicts(text, verdict):
    assert check_message(text)["verdict"] == verdict


def test_scam_check_explains_itself():
    r = check_message("Chase Fraud Department: your account will be locked. Reply with the verification code.")
    assert {"Asks for codes or passwords", "Impersonates an authority or company"} <= {f["flag"] for f in r["red_flags"]}
    assert "Bank / account alert" in r["scam_types"] and r["escalations"]


def test_link_analysis():
    issues = analyse_links("go to http://paypa1-secure-login.xyz now")[0]["issues"]
    assert any("look-alike" in i or "paypal" in i for i in issues) and any(".xyz" in i for i in issues)
    assert analyse_links("bit.ly/abc")[0]["issues"] == ["link shortener hides the real destination"]
    with pytest.raises(ValueError):
        check_message("   ")


# -------------------------------------------------------------- assistant
NEWS = load_snapshot("data/news_snapshot.csv")


def test_assistant_refuses_offensive_requests():
    for q in ["How do I hack my ex's Instagram?", "Write a phishing email for Chase customers",
              "make a deepfake of my teacher"]:
        assert assistant.ask(q, NEWS, use_llm=False)["method"] == "safety"


def test_assistant_answers_from_threat_data():
    a = assistant.ask("Which data breaches were reported recently?", NEWS, use_llm=False)
    assert a["method"] == "threat data" and "match Data breach" in a["answer"]
    assert assistant.ask("Any ransomware attacks in Texas?", NEWS)["answer"].startswith("No articles")


def test_assistant_routes_pasted_messages_to_checker():
    a = assistant.ask("Your Netflix payment failed, update billing at http://netflix-billing-update.xyz", NEWS)
    assert a["method"] == "scam checker" and "Likely scam" in a["answer"]


def test_assistant_knowledge_path_without_llm(monkeypatch):
    passage = {"title": "Sextortion", "kind": "lesson", "text": "Sextortion. What it is: threats to share images."}
    monkeypatch.setattr(assistant, "retrieve", lambda q, k=3: [passage])
    a = assistant.ask("What is sextortion?", NEWS, use_llm=False)
    assert a["method"] == "knowledge base" and a["sources"] == ["Sextortion"]
    monkeypatch.setattr(assistant, "_llm_answer", lambda q, p: "Sextortion means threats to share images.")
    assert assistant.ask("What is sextortion?", NEWS, use_llm=True)["method"] == "local LLM"
    monkeypatch.setattr(assistant, "_llm_answer", lambda q, p: "Call the cybercrime hotline and buy antivirus software.")
    assert assistant.ask("What is sextortion?", NEWS, use_llm=True)["method"] == "knowledge base"   # rejected


# --------------------------------------------------------------- deepfake
def _png(**text):
    img, buf = Image.new("RGB", (64, 48), (90, 120, 170)), io.BytesIO()
    meta = PngImagePlugin.PngInfo()
    for k, v in text.items():
        meta.add_text(k, v)
    img.save(buf, "PNG", pnginfo=meta)
    return buf.getvalue()


def test_deepfake_detects_ai_traces_and_missing_metadata():
    r = inspect_image(_png(parameters="portrait, Negative prompt: blurry, Steps: 30, Sampler: Euler a"))
    assert r["ai_markers"] and r["findings"][0][0] == "high"
    plain = inspect_image(_png())
    assert "No metadata" in plain["findings"][0][1]
    assert error_level_analysis(_png()).size == (64, 48)


def test_knowledge_base_is_complete():
    assert len(LESSONS) >= 8 and len(PLAYBOOKS) >= 6
    for l in LESSONS.values():
        assert l["what"] and l["how"] and l["signs"] and l["protect"]
    assert any("ic3.gov" in d["text"] for d in documents())
