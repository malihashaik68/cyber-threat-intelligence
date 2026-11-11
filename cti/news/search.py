"""Filter the analysed news, and when a combination of filters has no articles, find the closest
real matches (drop one filter at a time) instead of showing nothing. Nothing is invented."""
from __future__ import annotations

from itertools import combinations

import pandas as pd

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
# column -> how the filter is described when it is dropped
RELAXED = {"severity": "any severity", "attack_types": "any attack type", "sectors": "any sector",
           "states": "any state", "countries": "any country"}


def filter_news(news: pd.DataFrame, filters: dict[str, list[str]]) -> pd.DataFrame:
    """filters: column -> wanted values. 'severity' holds one value per row; the others hold lists."""
    df = news
    for col, want in filters.items():
        if not want:
            continue
        want = set(want)
        if col == "severity":
            mask = df[col].isin(want)
        else:
            mask = df[col].map(lambda vals: bool(want & set(vals)))
        df = df.loc[mask.astype(bool)]  # .astype(bool): an empty mask must select rows, not columns
    return df


def top_articles(df: pd.DataFrame, n: int = 5) -> pd.DataFrame:
    return (df.assign(_rank=df["severity"].map(SEV_RANK))
              .sort_values(["_rank", "date"], ascending=[True, False]).head(n).drop(columns="_rank"))


def describe(filters: dict[str, list[str]]) -> str:
    return " + ".join(", ".join(v) for v in filters.values() if v)


def closest_matches(news: pd.DataFrame, filters: dict[str, list[str]]) -> list[tuple[str, pd.DataFrame]]:
    """For a filter combination with no results, return the nearest non-empty groups: first keep all
    filters but one, then fewer."""
    active = {c: v for c, v in filters.items() if v}
    if len(active) < 2:
        return []
    keys = list(active)
    for drop_n in range(1, len(keys)):  # drop one filter, then two, ...
        groups = []
        for dropped in combinations(keys, drop_n):
            kept = {c: v for c, v in active.items() if c not in dropped}
            if set(kept) == {"severity"}:
                continue
            df = filter_news(news, kept)
            if len(df):
                groups.append((f"{describe(kept)} ({', '.join(RELAXED[c] for c in dropped)})", df))
        if groups:
            return groups
    return []
