"""Cyber Threat Intelligence: a free AI cyber-safety assistant for the public (US focus).

Run:     streamlit run app/streamlit_app.py
Deploy:  share.streamlit.io -> this repo -> main file app/streamlit_app.py
Optional secrets: GNEWS_API_KEY, GUARDIAN_API_KEY (live news), CTI_USE_LLM ("0" to turn off the local LLM)
"""
from __future__ import annotations

import io
import os
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import pandas as pd  # noqa: E402
import plotly.express as px  # noqa: E402
import streamlit as st  # noqa: E402

from cti import assistant  # noqa: E402
from cti.deepfake import CHECKLIST, error_level_analysis, inspect_image  # noqa: E402
from cti.knowledge.content import LESSONS, PLAYBOOKS, RESOURCES  # noqa: E402
from cti.news.analyze import analyze_articles, load_snapshot  # noqa: E402
from cti.news.collect import fetch_latest, keys_configured  # noqa: E402
from cti.news.taxonomy import ATTACK_TYPES  # noqa: E402
from cti.scam.checker import check_message, model_metrics  # noqa: E402

st.set_page_config(page_title="Cyber Threat Intelligence", page_icon="🛡️", layout="wide")
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_COLOR = {"CRITICAL": "#b42318", "HIGH": "#e8590c", "MEDIUM": "#d4a017", "LOW": "#2f9e44"}
STATE_CODES = {"Alabama": "AL", "Alaska": "AK", "Arizona": "AZ", "Arkansas": "AR", "California": "CA", "Colorado": "CO",
               "Connecticut": "CT", "Delaware": "DE", "Florida": "FL", "Georgia": "GA", "Hawaii": "HI", "Idaho": "ID",
               "Illinois": "IL", "Indiana": "IN", "Iowa": "IA", "Kansas": "KS", "Kentucky": "KY", "Louisiana": "LA",
               "Maine": "ME", "Maryland": "MD", "Massachusetts": "MA", "Michigan": "MI", "Minnesota": "MN",
               "Mississippi": "MS", "Missouri": "MO", "Montana": "MT", "Nebraska": "NE", "Nevada": "NV",
               "New Hampshire": "NH", "New Jersey": "NJ", "New Mexico": "NM", "New York": "NY", "North Carolina": "NC",
               "North Dakota": "ND", "Ohio": "OH", "Oklahoma": "OK", "Oregon": "OR", "Pennsylvania": "PA",
               "Rhode Island": "RI", "South Carolina": "SC", "South Dakota": "SD", "Tennessee": "TN", "Texas": "TX",
               "Utah": "UT", "Vermont": "VT", "Virginia": "VA", "Washington": "WA", "West Virginia": "WV",
               "Wisconsin": "WI", "Wyoming": "WY", "District of Columbia": "DC"}


# ------------------------------------------------------------------ data
@st.cache_data(show_spinner=False)
def snapshot() -> pd.DataFrame:
    return load_snapshot(ROOT / "data" / "news_snapshot.csv")


@st.cache_data(ttl=1800, show_spinner="Fetching and analysing the latest cyber news (about a minute)…")
def live_news() -> tuple[pd.DataFrame, list[str]]:
    raw = fetch_latest()
    errors = raw.attrs.get("errors", [])
    return (analyze_articles(raw) if len(raw) else raw), errors


def current_news() -> tuple[pd.DataFrame, str]:
    if st.session_state.get("use_live") and keys_configured():
        df, errors = live_news()
        for e in errors:
            st.sidebar.warning(f"News source error: {e}")
        if len(df):
            return df, f"live news ({len(df)} articles, refreshed every 30 min)"
    return snapshot(), f"saved snapshot ({len(snapshot())} articles); add API keys for live news"


# --------------------------------------------------------------- sidebar
with st.sidebar:
    st.title("🛡️ Cyber Threat Intelligence")
    st.caption("A free AI cyber-safety assistant: check scams, learn how attacks work, follow threats, "
               "and get help. US-focused.")
    if keys_configured():
        st.toggle("Live news", value=True, key="use_live",
                  help="Fetch the latest articles from GNews and The Guardian (cached 30 minutes).")
        if st.button("Refresh now"):
            live_news.clear()
    else:
        st.info("Using a saved news snapshot. Add GNEWS_API_KEY / GUARDIAN_API_KEY in Secrets for live news.")
    st.caption("Not legal or professional security advice. In an emergency or if you're in danger, call 911.")
    st.markdown("[Source code](https://github.com/malihashaik68/cyber-threat-intelligence)")

news, news_label = current_news()
tabs = st.tabs(["🤖 Ask", "🔍 Scam checker", "🗺️ Threat monitor", "📚 Learn", "🎭 Deepfake help",
                "🆘 I've been scammed"])

# ------------------------------------------------------------------- ask
with tabs[0]:
    st.subheader("Ask the cyber-safety assistant")
    st.caption("Ask about scams and attacks, the threat data (by attack type, sector or state), or paste a "
               "suspicious message. Answers show their sources. The local LLM runs on this server; nothing is "
               "sent to an outside AI company.")
    examples = ["How do I spot a phishing text?", "What should I do if I paid a scammer?", "What is sextortion?",
                "Which data breaches were reported recently?", "Any attacks on the government sector?",
                "How can I tell if a video is a deepfake?"]
    cols = st.columns(3)
    for i, ex in enumerate(examples):
        if cols[i % 3].button(ex, key=f"ex{i}"):
            st.session_state.q = ex
    with st.form("ask"):
        q = st.text_input("Your question", value=st.session_state.get("q", ""))
        go = st.form_submit_button("Ask", type="primary")
    if go and q.strip():
        with st.spinner("Thinking…"):
            st.session_state.setdefault("chat", []).insert(0, (q, assistant.ask(q, news)))
    for question, a in st.session_state.get("chat", []):
        with st.container(border=True):
            st.markdown(f"**Q: {question}**")
            st.markdown(a["answer"].replace("\n", "  \n"))
            st.caption(f"Answered by: {a['method']}" + (f" · Sources: {', '.join(a['sources'][:4])}" if a["sources"] else ""))
            if a.get("llm_note"):
                st.caption("ℹ️ " + a["llm_note"])

# ---------------------------------------------------------- scam checker
with tabs[1]:
    st.subheader("Is this a scam?")
    st.caption("Paste a text message, email or link. Your text is checked in memory and not stored.")
    samples = {
        "Delivery text": "USPS: Your package could not be delivered due to an incomplete address. Update here within 24 hours: https://usps-redelivery-help.top/track",
        "Bank alert": "Chase Fraud Department: Unusual sign-in detected. Your account will be locked. Reply with the verification code we just sent you.",
        "Family emergency": "Grandma it's me, I had an accident and I'm in jail. Please send money with gift cards, don't tell mom.",
        "Normal message": "Hi Sam, are we still on for lunch tomorrow at 12? Let me know if you want to switch to Thursday.",
    }
    pick = st.selectbox("Try an example", ["(write your own)"] + list(samples))
    with st.form("check"):
        msg = st.text_area("Message", value=samples.get(pick, ""), height=120)
        check = st.form_submit_button("Check", type="primary")
    if check and msg.strip():
        r = check_message(msg)
        box = {"Likely scam": st.error, "Suspicious": st.warning}.get(r["verdict"], st.success)
        box(f"**{r['verdict']}** · ML model: {r['model_probability']:.0%} scam-like · combined score {r['score']:.0%}")
        st.write(r["advice"])
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Red flags**")
            for f in r["red_flags"] or [{"flag": "None found", "evidence": ""}]:
                st.markdown(f"- {f['flag']}" + (f": “{f['evidence']}”" if f["evidence"] else ""))
            for e in r["escalations"]:
                st.markdown(f"- ⚠️ {e}")
        with c2:
            st.markdown("**Scam type**: " + (", ".join(r["scam_types"]) or "not identified"))
            for link in r["links"]:
                st.markdown(f"**Link** `{link['domain']}`: " + ("; ".join(link["issues"]) or "no obvious issues"))
    m = model_metrics()
    if m:
        st.caption(f"Model: TF-IDF + logistic regression trained on public SMS-spam and phishing datasets. "
                   f"Held-out test ({m['test_size']:,} messages): precision {m['precision']}, recall {m['recall']}, "
                   f"F1 {m['f1']}. No model is perfect: always verify through an official channel.")

# -------------------------------------------------------- threat monitor
with tabs[2]:
    st.subheader("Threat monitor")
    st.caption(f"Source: {news_label}. Locations, attack types and sectors are detected from the article text; "
               "counts reflect news coverage, not official crime statistics.")
    c1, c2, c3 = st.columns(3)
    sev_pick = c1.multiselect("Severity", SEV_ORDER, default=SEV_ORDER)
    type_pick = c2.multiselect("Attack type", list(ATTACK_TYPES))
    state_pick = c3.multiselect("US state", sorted(STATE_CODES))
    df = news[news["severity"].isin(sev_pick)]
    if type_pick:
        df = df[df["attack_types"].map(lambda v: bool(set(v) & set(type_pick)))]
    if state_pick:
        df = df[df["states"].map(lambda v: bool(set(v) & set(state_pick)))]

    sev = Counter(df["severity"])
    k = st.columns(5)
    k[0].metric("Articles", len(df))
    for i, s in enumerate(SEV_ORDER, 1):
        k[i].metric(s.title(), sev.get(s, 0))
    alerts = df[df["severity"].isin(["CRITICAL", "HIGH"])]
    if len(alerts):
        st.markdown("#### 🚨 Alerts: high-risk incidents")
        for r in alerts.sort_values("severity").head(5).itertuples():
            (st.error if r.severity == "CRITICAL" else st.warning)(
                f"**{r.severity}**: {r.title}  \n{r.source}, {str(r.date)[:10]} · Why: {', '.join(r.severity_reasons)}")

    c1, c2 = st.columns(2)
    with c1:
        states = Counter(s for v in df["states"] for s in v)
        if states:
            sdf = pd.DataFrame({"state": list(states), "articles": list(states.values())})
            sdf["code"] = sdf["state"].map(STATE_CODES)
            fig = px.choropleth(sdf, locations="code", locationmode="USA-states", color="articles", scope="usa",
                                hover_name="state", color_continuous_scale="Reds", title="US states in the news")
            st.plotly_chart(fig, width="stretch")
        else:
            st.info("No US states mentioned in these articles yet. Live news (US edition) adds more US coverage.")
    with c2:
        countries = Counter(c for v in df["countries"] for c in v)
        if countries:
            cdf = pd.DataFrame({"country": list(countries), "articles": list(countries.values())})
            fig = px.choropleth(cdf, locations="country", locationmode="country names", color="articles",
                                color_continuous_scale="Reds", title="Countries in the news")
            st.plotly_chart(fig, width="stretch")
    c1, c2 = st.columns(2)
    with c1:
        at = Counter(a for v in df["attack_types"] for a in v)
        if at:
            st.plotly_chart(px.bar(x=list(at.values()), y=list(at.keys()), orientation="h",
                                   labels={"x": "articles", "y": ""}, title="Attack types"), width="stretch")
    with c2:
        rows = [(s, r.severity) for r in df.itertuples() for s in r.sectors]
        if rows:
            sec = pd.DataFrame(rows, columns=["sector", "severity"]).value_counts().reset_index(name="articles")
            st.plotly_chart(px.bar(sec, x="articles", y="sector", color="severity", orientation="h",
                                   color_discrete_map=SEV_COLOR, title="Most exposed sectors (by severity)"),
                            width="stretch")
    st.dataframe(df[["date", "severity", "title", "attack_types", "sectors", "states", "countries", "source"]]
                 .sort_values("date", ascending=False), hide_index=True, width="stretch")

# ----------------------------------------------------------------- learn
with tabs[3]:
    st.subheader("Learn how attacks work, and how to protect yourself")
    for title, l in LESSONS.items():
        with st.expander(title):
            st.markdown(f"**What it is.** {l['what']}\n\n**How it works.** {l['how']}")
            c1, c2 = st.columns(2)
            c1.markdown("**Warning signs**\n" + "\n".join(f"- {s}" for s in l["signs"]))
            c2.markdown("**Protect yourself**\n" + "\n".join(f"- {s}" for s in l["protect"]))

# ---------------------------------------------------------------- deepfake
with tabs[4]:
    st.subheader("Is this image or video fake?")
    st.warning("No tool can prove an image is real or fake. These checks give evidence to weigh together.")
    c1, c2 = st.columns([1, 1])
    with c1:
        st.markdown("#### 1. Checklist")
        score = sum(st.checkbox(f"**{t}**: {q}", key=f"cl{i}") for i, (t, q) in enumerate(CHECKLIST))
        if score >= 3:
            st.error(f"{score} warning signs. Treat it as likely manipulated; verify before sharing or acting.")
        elif score:
            st.warning(f"{score} warning sign(s). Look for other evidence.")
        st.markdown("#### 2. Search where it came from")
        st.markdown("Upload the image to [Google Lens](https://lens.google.com) or [TinEye](https://tineye.com) "
                    "to see if it appeared earlier or in another context.")
        st.markdown("#### 3. Voice-clone calls")
        st.markdown("Hang up and call back on a number you know. Agree a **family safe word** in advance.")
    with c2:
        st.markdown("#### 4. Inspect an image file")
        up = st.file_uploader("Upload a photo (JPG/PNG). It's analysed in memory, not stored.", type=["jpg", "jpeg", "png", "webp"])
        if up:
            data = up.getvalue()
            r = inspect_image(data)
            st.image(data, caption=f"{r['info']['format']} · {r['info']['size']}", width="stretch")
            for level, text in r["findings"]:
                {"high": st.error, "medium": st.warning}.get(level, st.info)(text)
            with st.expander("Error Level Analysis (ELA)"):
                st.caption("Bright, blocky areas changed more when re-saved; edited regions sometimes stand out. "
                           "Screenshots and heavily compressed images give noisy results.")
                buf = io.BytesIO()
                error_level_analysis(data).save(buf, "PNG")
                st.image(buf.getvalue(), width="stretch")
            if r["exif"]:
                with st.expander("All metadata"):
                    st.json(r["exif"])
    st.markdown("#### Someone made a fake of you?")
    st.markdown("\n".join(f"{i}. {s}" for i, s in enumerate(PLAYBOOKS["Someone made a fake image or video of me"], 1)))

# ------------------------------------------------------------------- help
with tabs[5]:
    st.subheader("I've been scammed or hacked: what now?")
    situation = st.radio("What happened?", list(PLAYBOOKS), horizontal=False)
    st.markdown("\n".join(f"{i}. {s}" for i, s in enumerate(PLAYBOOKS[situation], 1)))
    st.markdown("#### Where to report (US)")
    for name, (url, desc) in RESOURCES.items():
        st.markdown(f"- **[{name}]({url})**: {desc}")
