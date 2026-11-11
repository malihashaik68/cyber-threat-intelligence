"""'Is this a scam?' checker for messages, emails and links.

Three signals, all shown to the user:
  1. ML probability from the trained classifier (cti/scam/train.py)
  2. Red flags: explainable rules for tactics the FTC and FBI warn about
  3. Scam type: common US scam patterns (bank, delivery, toll, IRS/SSA, tech support, ...)
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = ROOT / "models" / "scam_model.joblib"

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')]+|\b[a-z0-9-]+\.(?:com|net|org|info|xyz|top|click|link|live|shop|"
                    r"online|site|ru|cn|tk|ml|ga|cf|gq|co|io|me|us|ly|at|cc|gl|to)(?:/[^\s<>\"')]*)?", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rebrand.ly", "rb.gy", "t.ly",
              "shorturl.at", "tiny.cc"}
RISKY_TLDS = {"xyz", "top", "click", "link", "live", "shop", "online", "site", "tk", "ml", "ga", "cf", "gq", "info", "ru", "cn"}
BRANDS = ["paypal", "amazon", "apple", "microsoft", "netflix", "usps", "fedex", "ups", "dhl", "irs", "chase", "wellsfargo",
          "bankofamerica", "citibank", "venmo", "zelle", "cashapp", "coinbase", "ezpass", "dmv", "ssa", "medicare"]

RED_FLAGS = [
    ("Urgency or threat", r"\b(urgent|immediately|within 24 hours|act now|final notice|last chance|suspend(?:ed)?|"
                          r"locked|deactivat\w*|will be closed|legal action|arrest(?:ed)?|warrant|penalt(?:y|ies))\b"),
    ("Asks for codes or passwords", r"\b(one[- ]time (?:pass)?code|otp|verification code|passcode|password|pin\b|"
                                   r"security code|login details|credentials)"),
    ("Asks for personal or financial data", r"\b(social security|ssn|bank account|routing number|card number|cvv|"
                                           r"date of birth|verify your (?:identity|account|information)|update (?:your )?(?:payment|billing)|"
                                           r"payment (?:failed|declined|was unsuccessful)|billing (?:problem|issue|information))"),
    ("Unusual payment method", r"\b(gift cards?|itunes card|google play card|wire transfer|western union|moneygram|"
                               r"bitcoin|crypto(?:currency)?|zelle|cash app|venmo|bitcoin atm)\b"),
    ("Too good to be true", r"\b(you(?:'ve| have)? won|winner|prize|lottery|free (?:gift|iphone|money)|claim your|"
                            r"guaranteed (?:return|profit)|double your|risk[- ]free|\$\d[\d,]* (?:cash|reward))"),
    ("Unexpected delivery or toll problem", r"\b(package|parcel|shipment|delivery) (?:could not|failed|is on hold|"
                                            r"pending)|redelivery|unpaid tolls?|toll (?:balance|violation)|customs fee"),
    ("Impersonates an authority or company", r"\b(irs|social security administration|ssa|fbi|police|medicare|usps|"
                                             r"fedex|ups|amazon|paypal|netflix|apple support|microsoft support|your bank|fraud department)\b"),
    ("Secrecy or isolation", r"\b(don'?t tell|keep (?:this|it) (?:secret|confidential)|do not share this with)\b"),
    ("Remote access request", r"\b(anydesk|teamviewer|remote access|install (?:this|the) app|screen ?share)\b"),
]

SCAM_TYPES = [
    ("Bank / account alert", r"\b(bank|account|card|fraud department|unusual (?:activity|sign[- ]in)|zelle)\b.*\b(locked|suspend|verify|confirm|unusual)"),
    ("Package delivery", r"\b(usps|ups|fedex|dhl|package|parcel|shipment|delivery|redelivery)\b"),
    ("Unpaid toll", r"\b(toll|e-?zpass|sunpass|fastrak)\b"),
    ("Government impersonation (IRS / SSA / police)", r"\b(irs|tax refund|social security|ssa|warrant|arrest|medicare|stimulus)\b"),
    ("Tech support", r"\b(virus|infected|microsoft support|apple support|technician|refund department|subscription renewal|geek squad|norton|mcafee)\b"),
    ("Prize / lottery / giveaway", r"\b(won|winner|prize|lottery|sweepstakes|giveaway|claim your)\b"),
    ("Job / work-from-home", r"\b(job offer|hiring|work from home|remote position|easy money|per day|recruiter|part[- ]time)\b"),
    ("Investment / crypto", r"\b(invest(?:ment)?|crypto|bitcoin|trading|guaranteed (?:return|profit)|double your)\b"),
    ("Romance / friendship", r"\b(love|dear|lonely|soulmate|military deployment|meet you)\b"),
    ("Family emergency / voice clone", r"\b(grandma|grandpa|mom|dad|it'?s me|in jail|bail|accident|hospital).*\b(money|send|wire|gift card)"),
]


@lru_cache(maxsize=1)
def _model():
    import joblib

    return joblib.load(MODEL_PATH)


def model_metrics() -> dict:
    p = MODEL_PATH.with_name("scam_metrics.json")
    return json.loads(p.read_text()) if p.exists() else {}


def analyse_links(text: str) -> list[dict]:
    results = []
    for raw in URL_RE.findall(text or ""):
        url = raw if raw.lower().startswith("http") else "http://" + raw
        host = (urlparse(url).hostname or "").lower()
        if not host or "." not in host:
            continue
        issues = []
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            issues.append("uses a raw IP address instead of a name")
        if host in SHORTENERS:
            issues.append("link shortener hides the real destination")
        tld = host.rsplit(".", 1)[-1]
        if tld in RISKY_TLDS:
            issues.append(f"'.{tld}' domains are often used by scammers")
        base = host.split(".")[-2] if host.count(".") >= 1 else host
        for brand in BRANDS:
            squashed = re.sub(r"[^a-z0-9]", "", host)
            if brand in squashed and base != brand:
                issues.append(f"mentions '{brand}' but the real domain is '{'.'.join(host.split('.')[-2:])}'")
                break
            lookalike = brand.replace("o", "0").replace("l", "1").replace("i", "1")
            if lookalike != brand and lookalike in squashed:
                issues.append(f"look-alike spelling of '{brand}'")
                break
        if host.count("-") >= 2 or host.count(".") >= 4:
            issues.append("unusually long or hyphenated domain")
        if url.lower().startswith("http://") and raw.lower().startswith("http://"):
            issues.append("not encrypted (http, not https)")
        results.append({"link": raw, "domain": host, "issues": issues})
    return results


def check_message(text: str) -> dict:
    text = (text or "").strip()
    if not text:
        raise ValueError("Paste a message, email or link to check.")
    prob = float(_model().predict_proba([text[:3000]])[0][1])
    flags = []
    for name, pattern in RED_FLAGS:
        m = re.search(pattern, text, re.I)
        if m:
            flags.append({"flag": name, "evidence": m.group(0)})
    links = analyse_links(text)
    link_issues = sum(len(l["issues"]) for l in links)
    types = [name for name, pattern in SCAM_TYPES if re.search(pattern, text, re.I | re.S)]

    # combine: the model decides, explainable rules can raise the level
    score = prob + 0.08 * len(flags) + 0.1 * min(link_issues, 3) + (0.1 if types else 0)
    names = {f["flag"] for f in flags}
    # Classic combinations the FTC/FBI describe as near-certain scams, even if the model has
    # not seen this wording (e.g. grandparent / voice-clone scams are rare in the training data).
    escalations = []
    if "Unusual payment method" in names and names & {"Secrecy or isolation", "Urgency or threat",
                                                       "Impersonates an authority or company"}:
        escalations.append("demands gift cards, wire transfer or crypto together with pressure or impersonation")
    if "Asks for codes or passwords" in names and "Impersonates an authority or company" in names:
        escalations.append("someone claiming to be a company or agency asks for a code or password")
    if "Remote access request" in names:
        escalations.append("asks you to install remote-access software")
    if escalations:
        score = max(score, 0.8)
    verdict = "Likely scam" if score >= 0.75 else "Suspicious" if score >= 0.4 else "No strong scam signs"
    advice = {
        "Likely scam": "Do not click links, reply, call numbers in the message or pay. Contact the company using a "
                       "number or website you already trust. Report it (see 'I've been scammed').",
        "Suspicious": "Be careful. Verify through an official channel you look up yourself before doing anything.",
        "No strong scam signs": "No strong signs found, but scammers change tactics. If it asks for money, codes or "
                                "personal data, verify independently first.",
    }[verdict]
    return {"verdict": verdict, "model_probability": round(prob, 3), "score": round(min(score, 1.0), 3),
            "red_flags": flags, "links": links, "scam_types": types, "escalations": escalations,
            "advice": advice}
