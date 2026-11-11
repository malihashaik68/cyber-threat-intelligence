"""Cyber-safety assistant.

Routing, from most to least reliable:
  1. Offensive requests (how to hack, phish, make a deepfake of someone...) -> polite refusal + defensive help.
  2. A pasted message/link -> the scam checker.
  3. Questions about the threat data by attack pattern, sector or location -> direct answer from the
     analysed news (counts + example headlines). No LLM.
  4. Knowledge questions -> retrieve passages from the knowledge base (all-MiniLM-L6-v2 embeddings);
     a small local LLM (Qwen2.5-Instruct) phrases a short answer, rejected if it adds content that
     isn't in the passages. Sources are always shown.
"""
from __future__ import annotations

import os
import re
from collections import Counter
from functools import lru_cache

import pandas as pd

from cti.knowledge.content import documents
from cti.news.geo import COUNTRIES, US_CITIES, US_STATES
from cti.news.search import closest_matches, describe, filter_news, top_articles
from cti.news.taxonomy import ATTACK_TYPES, SECTORS, detect_attack_types, detect_sectors

LLM_MODEL = os.getenv("CTI_LLM_MODEL", "Qwen/Qwen2.5-0.5B-Instruct")
USE_LLM = os.getenv("CTI_USE_LLM", "1") != "0"
RELEVANCE = 0.30

OFFENSIVE = re.compile(
    r"\b(how (?:do|can|to) i?\s*(?:hack|break into|crack|phish|ddos|dox|steal|spy on|track someone)|"
    r"(?:write|make|create|build|generate) (?:a |an |me )?(?:phishing|malware|ransomware|keylogger|virus|"
    r"scam (?:message|email|text)|deepfake of)|hack (?:into )?(?:my |his |her |their |someone)|"
    r"bypass (?:2fa|mfa|password)|steal (?:passwords|credentials|accounts))", re.I)
DATA_WORDS = re.compile(r"\b(news|trend|trending|reported|recent|latest|how many|which|where|most|top|any|"
                        r"attacks?|cases?|incidents?|breaches|targeted|hit|affected|show)\b", re.I)


def _ans(text, method, sources=None, extra=None):
    return {"answer": text, "method": method, "sources": sources or [], "extra": extra or {}, "llm_note": ""}


# ------------------------------------------------------------ 3. threat data
def _match_filters(q: str) -> dict:
    states = [s for s in US_STATES if re.search(rf"\b{re.escape(s)}\b", q, re.I)]
    states += [US_CITIES[c] for c in US_CITIES if re.search(rf"\b{re.escape(c)}\b", q, re.I)]
    no_states = re.sub("|".join(rf"\b{re.escape(s)}\b" for s in US_STATES), " ", q, flags=re.I)  # New Mexico != Mexico
    countries = sorted({v for k, v in COUNTRIES.items() if len(k) > 3 and re.search(rf"\b{re.escape(k)}\b", no_states, re.I)})
    attacks = detect_attack_types(q)
    attacks = [a for a in attacks if a != "Hacking / cyberattack (general)"] or attacks
    attacks += [a for a in ATTACK_TYPES if a.split(" ")[0].lower() in q.lower() and a not in attacks]
    sectors = detect_sectors(q) + [s for s in SECTORS if s.split(" ")[0].lower() in q.lower()]
    return {"states": sorted(set(states)), "countries": countries, "attack_types": sorted(set(attacks)),
            "sectors": sorted(set(sectors))}


def answer_from_news(q: str, news: pd.DataFrame) -> dict | None:
    f = _match_filters(q)
    if not any(f.values()) or not DATA_WORDS.search(q):
        return None
    df = filter_news(news, f)
    label = describe(f)
    if df.empty:
        lines = [f"None of the current {len(news)} news articles match {label}. This is based on news coverage, "
                 "so it doesn't mean no cases happened."]
        groups = closest_matches(news, f)
        sources = []
        for glabel, g in groups:
            lines.append(f"Closest match: **{glabel}**, {len(g)} article{'s' if len(g) != 1 else ''}:")
            top = top_articles(g, 3)
            lines += [f"- [{r.severity}] {r.title} ({r.source}, {str(r.date)[:10]})" for r in top.itertuples()]
            sources += [f"{r.source}: {r.title}" for r in top.itertuples()]
        if not groups:
            top = top_articles(news, 3)
            lines.append("Top headlines in the current news:")
            lines += [f"- [{r.severity}] {r.title} ({r.source}, {str(r.date)[:10]})" for r in top.itertuples()]
            sources += [f"{r.source}: {r.title}" for r in top.itertuples()]
        if f["attack_types"]:
            lines.append(f"Want to know how {f['attack_types'][0]} attacks work and what to do? Ask me, "
                         "or open the Learn tab.")
        return _ans("\n".join(lines), "threat data", sources, {"filters": f})
    sev = Counter(df["severity"])
    lines = [f"**{len(df)} of {len(news)} articles** match {label}. Severity: "
             + ", ".join(f"{k} {sev[k]}" for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] if sev[k]) + "."]
    top = top_articles(df)
    if not f["attack_types"]:
        common = Counter(a for vals in df["attack_types"] for a in vals).most_common(3)
        if common:
            lines.append("Most common attack types: " + ", ".join(f"{a} ({n})" for a, n in common) + ".")
    lines.append("Highest-severity headlines:")
    lines += [f"- [{r.severity}] {r.title} ({r.source}, {str(r.date)[:10]})" for r in top.itertuples()]
    return _ans("\n".join(lines), "threat data", [f"{r.source}: {r.title}" for r in top.itertuples()],
                {"filters": f})


# ------------------------------------------------------- 4. knowledge + LLM
@lru_cache(maxsize=1)
def _index():
    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    docs = documents()
    return model, docs, model.encode([d["text"] for d in docs], normalize_embeddings=True)


def retrieve(q: str, k: int = 3) -> list[dict]:
    model, docs, vecs = _index()
    qv = model.encode([q], normalize_embeddings=True)[0]
    scored = sorted(((float(v @ qv), d) for v, d in zip(vecs, docs)), key=lambda x: x[0], reverse=True)
    return [{**d, "score": round(s, 3)} for s, d in scored[:k] if s >= RELEVANCE]


@lru_cache(maxsize=1)
def _llm():
    import torch
    from transformers import pipeline

    return pipeline("text-generation", model=LLM_MODEL, dtype=torch.bfloat16)


_STOP = {"which", "there", "their", "about", "would", "could", "should", "these", "those", "other", "being",
         "having", "after", "before", "where", "people", "person", "someone", "important", "always", "never",
         "something", "anything", "things", "really", "usually", "often", "means", "called", "using", "through"}


def _overlap(answer: str, evidence: str) -> float:
    stems = lambda t: {w[:5] for w in re.findall(r"[a-z]{5,}", t.lower()) if w not in _STOP}
    a = stems(answer)
    return 1.0 if not a else len(a & stems(evidence)) / len(a)


def _llm_answer(q: str, passages: list[dict]) -> str:
    ctx = "\n".join(f"- {p['text']}" for p in passages)
    msgs = [{"role": "system", "content": "You are a friendly cyber-safety assistant for the public. Answer using ONLY "
                                          "the facts below, in 2-4 short sentences of plain English. Do not add "
                                          "facts. Never give instructions for attacking anyone."},
            {"role": "user", "content": f"Facts:\n{ctx}\n\nQuestion: {q}"}]
    out = _llm()(msgs, max_new_tokens=140, do_sample=False)[0]["generated_text"][-1]["content"].strip()
    return out.strip("[]").strip()


def ask(q: str, news: pd.DataFrame | None = None, use_llm: bool | None = None) -> dict:
    q = (q or "").strip()
    if not q:
        return _ans("Ask a question, or paste a suspicious message.", "none")
    if OFFENSIVE.search(q):
        return _ans("I can't help with attacking or deceiving anyone. I can explain how these attacks work so you "
                    "can spot and stop them, or help if you've been targeted. Try: 'How do I spot phishing?' or "
                    "'What should I do if my account was hacked?'", "safety")
    if re.search(r"https?://|www\.", q) or len(q) > 220:
        from cti.scam.checker import check_message
        r = check_message(q)
        flags = "; ".join(f["flag"] for f in r["red_flags"]) or "none"
        return _ans(f"**{r['verdict']}** (model score {r['model_probability']:.2f}). Red flags: {flags}. "
                    f"{r['advice']}", "scam checker", extra={"check": r})
    if news is not None and len(news):
        data = answer_from_news(q, news)
        if data:
            return data

    passages = retrieve(q)
    if not passages:
        return _ans("I don't have information on that. Try asking about phishing, scams, identity theft, "
                    "ransomware, deepfakes or what to do after a scam.", "knowledge base")
    sources = sorted({p["title"] for p in passages})
    evidence = " ".join(p["text"] for p in passages)
    if use_llm is None:
        use_llm = USE_LLM
    note = "LLM answers are switched off."
    if use_llm:
        try:
            text = _llm_answer(q, passages)
            if text and _overlap(text, evidence + " " + q) >= 0.6:
                return _ans(text, "local LLM", sources, {"passages": passages})
            note = f"LLM draft rejected (added content not in the sources): “{text}”"
        except Exception as exc:
            note = f"LLM unavailable ({exc.__class__.__name__})."
    best = passages[0]["text"]
    result = _ans(best, "knowledge base", sources, {"passages": passages})
    result["llm_note"] = note
    return result
