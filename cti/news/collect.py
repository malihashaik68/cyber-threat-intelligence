"""Fetch live cyber-security news from GNews and The Guardian.

API keys are read from the environment (or Streamlit secrets): GNEWS_API_KEY, GUARDIAN_API_KEY.
Never put keys in code. Free keys: https://gnews.io and https://open-platform.theguardian.com
"""
from __future__ import annotations

import os
import re

import pandas as pd
import requests

QUERY = "cybersecurity OR cyberattack OR ransomware OR phishing OR scam OR data breach OR deepfake"


def _key(name: str) -> str | None:
    value = os.getenv(name)
    if value:
        return value
    try:
        import streamlit as st
        return st.secrets.get(name)
    except Exception:
        return None


def fetch_gnews(max_articles: int = 50) -> list[dict]:
    key = _key("GNEWS_API_KEY")
    if not key:
        return []
    r = requests.get("https://gnews.io/api/v4/search", timeout=30, params={
        "q": QUERY, "lang": "en", "country": "us", "max": max_articles, "apikey": key})
    r.raise_for_status()
    return [{"title": a["title"], "description": a.get("description") or "", "source": a["source"]["name"],
             "date": a["publishedAt"], "url": a.get("url", "")} for a in r.json().get("articles", [])]


def fetch_guardian(max_articles: int = 50) -> list[dict]:
    key = _key("GUARDIAN_API_KEY")
    if not key:
        return []
    r = requests.get("https://content.guardianapis.com/search", timeout=30, params={
        "q": "cyber OR ransomware OR hackers OR scam", "api-key": key, "page-size": max_articles,
        "order-by": "newest", "show-fields": "trailText"})
    r.raise_for_status()
    strip = lambda h: re.sub(r"<[^>]+>", "", h or "").strip()  # trailText contains HTML
    return [{"title": i["webTitle"], "description": strip((i.get("fields") or {}).get("trailText", "")),
             "source": "The Guardian", "date": i["webPublicationDate"], "url": i.get("webUrl", "")}
            for i in r.json()["response"]["results"]]


def fetch_latest() -> pd.DataFrame:
    """Fetch from every source that has a key; de-duplicate by title."""
    rows, errors = [], []
    for fn in (fetch_gnews, fetch_guardian):
        try:
            rows += fn()
        except Exception as exc:  # one source failing should not stop the other
            errors.append(f"{fn.__name__}: {exc}")
    df = pd.DataFrame(rows, columns=["title", "description", "source", "date", "url"])
    df = df.drop_duplicates(subset="title")
    df.attrs["errors"] = errors
    return df


def keys_configured() -> bool:
    return bool(_key("GNEWS_API_KEY") or _key("GUARDIAN_API_KEY"))
