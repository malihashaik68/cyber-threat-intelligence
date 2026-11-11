"""Train the scam-message classifier.

Data (downloaded at training time, not stored in the repo):
  * UCI SMS Spam Collection (5,574 SMS)             huggingface.co/datasets/ucirvine/sms_spam
  * Phishing dataset, texts subset (20,137 emails/SMS, Apache-2.0)
                                                     huggingface.co/datasets/ealvaradob/phishing-dataset
Model: TF-IDF (word 1-2 grams + character 3-5 grams) -> logistic regression.
Evaluation: stratified 80/20 split after removing duplicate texts (no leakage).

Run:  python -m cti.scam.train
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = ROOT / "models" / "scam_model.joblib"
METRICS_PATH = ROOT / "models" / "scam_metrics.json"
SMS_URL = "https://huggingface.co/datasets/ucirvine/sms_spam/resolve/main/plain_text/train-00000-of-00001.parquet"
PHISH_URL = "https://huggingface.co/datasets/ealvaradob/phishing-dataset/resolve/main/texts.json"
MAX_CHARS = 3000


def load_data(cache_dir: Path | None = None) -> pd.DataFrame:
    sms = pd.read_parquet(SMS_URL if not cache_dir else cache_dir / "sms.parquet")
    sms = pd.DataFrame({"text": sms["sms"].str.strip(), "label": sms["label"], "source": "sms"})
    phish = pd.read_json(PHISH_URL if not cache_dir else cache_dir / "texts.json")
    phish = pd.DataFrame({"text": phish["text"].str.strip(), "label": phish["label"], "source": "email/sms"})
    df = pd.concat([sms, phish], ignore_index=True)
    df["text"] = df["text"].str.slice(0, MAX_CHARS)
    df = df[df["text"].str.len() > 5]
    return df.drop_duplicates(subset="text").reset_index(drop=True)


def build_model() -> Pipeline:
    features = FeatureUnion([
        ("words", TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=150_000, sublinear_tf=True)),
        ("chars", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, max_features=150_000,
                                  sublinear_tf=True)),
    ])
    return Pipeline([("features", features),
                     ("clf", LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced"))])


def main(cache_dir: str | None = None) -> dict:
    df = load_data(Path(cache_dir) if cache_dir else None)
    train, test = train_test_split(df, test_size=0.2, stratify=df["label"], random_state=42)
    model = build_model().fit(train["text"], train["label"])
    pred = model.predict(test["text"])
    p, r, f, _ = precision_recall_fscore_support(test["label"], pred, average="binary")
    per_source = {}
    for src, part in test.groupby("source"):
        pp, rr, ff, _ = precision_recall_fscore_support(part["label"], model.predict(part["text"]), average="binary")
        per_source[src] = {"precision": round(pp, 3), "recall": round(rr, 3), "f1": round(ff, 3), "n": len(part)}
    metrics = {"train_size": len(train), "test_size": len(test), "precision": round(p, 3), "recall": round(r, 3),
               "f1": round(f, 3), "accuracy": round(float(np.mean(pred == test["label"])), 3),
               "confusion_matrix": confusion_matrix(test["label"], pred).tolist(), "per_source": per_source}
    print(classification_report(test["label"], pred, target_names=["legitimate", "scam/phishing"], digits=3))
    MODEL_PATH.parent.mkdir(exist_ok=True)
    # final model is trained on all data
    joblib.dump(build_model().fit(df["text"], df["label"]), MODEL_PATH, compress=3)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2))
    return metrics


if __name__ == "__main__":
    import sys
    print(json.dumps(main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
