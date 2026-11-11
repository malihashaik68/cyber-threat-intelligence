"""NLP analysis of cyber news articles.

For each article (title + description):
  * attack types, sectors and locations (keyword / gazetteer rules, see taxonomy.py, geo.py)
  * sentiment: VADER score + transformer label (distilbert SST-2)
  * emotions: j-hartmann/emotion-english-distilroberta-base (anger, fear, sadness, joy, ...)
  * organisations: transformer NER (dslim/bert-base-NER) on the ORIGINAL text - NER needs capitals
  * severity LOW / MEDIUM / HIGH / CRITICAL with the reasons that triggered it

Heavy transformer models are optional (use_models=False gives a fast rule-only pass).
"""
from __future__ import annotations

import re
from functools import lru_cache

import pandas as pd

from cti.news.geo import detect_locations
from cti.news.taxonomy import detect_attack_types, detect_sectors

HIGH_IMPACT_ATTACKS = {"Ransomware", "Data breach", "Nation-state & espionage", "Supply chain"}
CRITICAL_SECTORS = {"Healthcare", "Energy & utilities", "Government", "Finance & banking"}


@lru_cache(maxsize=1)
def _models():
    from transformers import pipeline
    from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer  # VADER, lexicon included

    return {
        "vader": SentimentIntensityAnalyzer(),
        "sentiment": pipeline("sentiment-analysis", model="distilbert/distilbert-base-uncased-finetuned-sst-2-english"),
        "emotion": pipeline("text-classification", model="j-hartmann/emotion-english-distilroberta-base", top_k=None),
        "ner": pipeline("ner", model="dslim/bert-base-NER", aggregation_strategy="simple"),
    }


def article_text(title: str, description: str | None) -> str:
    """Title plus description; the Guardian API returns no description, so don't repeat the title."""
    description = (description or "").strip()
    return title if not description or description == title else f"{title}. {description}"


def severity(row: dict) -> tuple[str, list[str]]:
    """Original scoring idea (negative tone, fear, anger, organisations involved) plus the
    attack type and sector. Returns the level and the reasons."""
    score, reasons = 0, []
    s = row.get("sentiment_score", 0.0)
    if s < -0.5:
        score += 2; reasons.append("strongly negative tone")
    elif s < -0.2:
        score += 1; reasons.append("negative tone")
    fear = row.get("fear", 0.0)
    if fear > 0.6:
        score += 2; reasons.append("high fear")
    elif fear > 0.3:
        score += 1; reasons.append("some fear")
    if row.get("anger", 0.0) > 0.5:
        score += 1; reasons.append("anger")
    orgs = len(row.get("organizations", []))
    if orgs >= 3:
        score += 2; reasons.append(f"{orgs} organisations named")
    elif orgs >= 1:
        score += 1; reasons.append("organisation named")
    impact = HIGH_IMPACT_ATTACKS & set(row.get("attack_types", []))
    if impact:
        score += 2; reasons.append("high-impact attack: " + ", ".join(sorted(impact)))
    critical = CRITICAL_SECTORS & set(row.get("sectors", []))
    if critical:
        score += 1; reasons.append("critical sector: " + ", ".join(sorted(critical)))
    level = "CRITICAL" if score >= 6 else "HIGH" if score >= 4 else "MEDIUM" if score >= 2 else "LOW"
    return level, reasons


def analyze_articles(articles: pd.DataFrame, use_models: bool = True) -> pd.DataFrame:
    """articles needs columns: title, description, source, date, url (optional)."""
    df = articles.copy()
    if "url" not in df:
        df["url"] = ""
    df["text"] = [article_text(t, d) for t, d in zip(df["title"], df["description"].fillna(""))]
    df["attack_types"] = df["text"].map(detect_attack_types)
    df["sectors"] = df["text"].map(detect_sectors)
    locs = df["text"].map(detect_locations)
    df["states"] = locs.map(lambda l: l["states"])
    df["cities"] = locs.map(lambda l: l["cities"])
    df["countries"] = locs.map(lambda l: l["countries"])

    if use_models:
        m = _models()
        texts = df["text"].str.slice(0, 1000).tolist()
        df["sentiment_score"] = [m["vader"].polarity_scores(t)["compound"] for t in texts]
        sent = m["sentiment"](texts, truncation=True)
        df["tf_sentiment"] = [r["label"] for r in sent]
        df["tf_confidence"] = [round(r["score"], 3) for r in sent]
        emotions = m["emotion"](texts, truncation=True)
        for label in ["anger", "fear", "sadness", "joy", "surprise", "disgust", "neutral"]:
            df[label] = [round(next((e["score"] for e in em if e["label"] == label), 0.0), 3) for em in emotions]
        ner = m["ner"](texts)
        df["organizations"] = [sorted({e["word"] for e in ents if e["entity_group"] == "ORG"
                                       and len(e["word"]) > 2 and "#" not in e["word"]}) for ents in ner]
    else:
        for col in ["sentiment_score", "anger", "fear", "sadness", "joy"]:
            df[col] = 0.0
        df["tf_sentiment"], df["tf_confidence"], df["organizations"] = "", 0.0, [[] for _ in range(len(df))]

    sev = [severity(r) for r in df.to_dict("records")]
    df["severity"] = [s[0] for s in sev]
    df["severity_reasons"] = [s[1] for s in sev]
    return df


LIST_COLUMNS = ["attack_types", "sectors", "states", "cities", "countries", "organizations", "severity_reasons"]


def load_snapshot(path) -> pd.DataFrame:
    import json

    df = pd.read_csv(path)
    for c in LIST_COLUMNS:
        if c in df:
            df[c] = df[c].map(lambda v: json.loads(v) if isinstance(v, str) and v.startswith("[") else [])
    return df


def save_snapshot(df: pd.DataFrame, path) -> None:
    import json

    out = df.copy()
    for c in LIST_COLUMNS:
        if c in out:
            out[c] = out[c].map(json.dumps)
    out.to_csv(path, index=False)
